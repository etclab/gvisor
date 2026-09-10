// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/attest"
)

// The egress policy: the netfilter rule set this sandbox's own signed policy
// implies, the code that installs it, and the probe that proves it holds.
//
// # Why this lives in tunneld and not in a second binary
//
// The rule set is generated from `policy.json` — the document whose digest
// every peer checks — and a document is only worth generating rules from if the
// generator checked the author's signature over it first. tunneld already holds
// the author key that arrived inside the launch measurement
// (/etc/attested-tunnel/author.pub, ADR-0004) and already knows how to refuse a
// policy that key did not sign. A separate installer would be a second loader
// and a second signature check, and two loaders that disagree about what a
// policy says is exactly the failure this design cannot survive. So the guest's
// init runs this binary in a mode that ends after the rules are in the kernel,
// and then runs it again to serve.
//
// # What the policy contributes and what the peer table contributes
//
// [attest.Egress] says one thing today, and it says it in the fail-closed
// direction: `unattested: false` — no traffic may leave this sandbox to a peer
// nothing judged. That is the whole of the rule set's *shape*: both base chains
// default to drop, and the output chain ends in a reject. The peer table then
// says which addresses are the exception, and the run configuration says on
// which port. A policy claiming `unattested: true` never reaches here, because
// attest/policyfile.go refuses to load one — nothing implements permitting it,
// and a digest that vouched for a promise nobody keeps would be worse than no
// digest at all. It is checked again here anyway, because this is the code that
// would have to honour it.
//
// # Reject rather than drop, on the way out
//
// The output chain ends in rejects rather than relying on its drop policy. A
// dropped packet on the way out is indisputable but silent: the local socket
// learns nothing and the caller sees a timeout, which is what a black hole, a
// lost route and a firewall all look like. A reject makes netfilter build a
// refusal addressed back at the local socket, and the kernel turns that into an
// errno — immediately, and distinguishably from ENETUNREACH, which is what "no
// route" looks like. The point of the egress proof is to show the *rule*
// refused rather than the routing table, so the rule is made to say so out
// loud. The input chain keeps a plain drop policy: there is nobody on the other
// end to tell.
//
// The refusal netfilter builds is delivered to the local socket over the
// loopback interface, which is why the guest's init brings `lo` up before it
// does anything else with the network (docs/snp/cloud/tdx/init.tdx). With lo
// down the refusal is dropped on the way back and every probe times out
// instead, which proves nothing.
const (
	// egressTableName is the nftables table this sandbox owns. Nothing else
	// runs in the guest, so the ruleset is flushed before it is installed and
	// this is the only table there is.
	egressTableName = "attested_tunnel"

	// egressChainInput and the rest are the base chains, one per hook that can
	// carry traffic to or from this sandbox. Forwarding is included and left
	// empty: the guest routes for nobody, and a chain that says so is cheaper
	// to read than an absence.
	egressChainInput   = "input"
	egressChainOutput  = "output"
	egressChainForward = "forward"
)

// egressModes are the values -egress takes. Each of them ends the process; none
// of them starts a tunnel.
const (
	egressModePrint   = "print"
	egressModeInstall = "install"
	egressModeProbe   = "probe"
)

// An egressRule is one rule, in both of the forms that have to agree: the text
// a console reader judges the policy by, and the expressions the kernel
// enforces. They are built together, from one description, so that the rendered
// rule set and the installed rule set cannot drift apart.
type egressRule struct {
	text  string
	exprs []expr.Any
}

// An egressChain is one base chain: its hook, its default verdict, and its
// rules in order.
type egressChain struct {
	name   string
	hook   *nftables.ChainHook
	policy nftables.ChainPolicy
	rules  []egressRule
}

// An egressRuleSet is the whole rule set a policy, a peer table and a run
// configuration imply.
type egressRuleSet struct {
	// SandboxID, ListenPort and Peers are the inputs, kept so that the
	// rendering can name them.
	SandboxID  string
	ListenPort uint16
	Peers      []egressPeer

	chains []egressChain
}

// An egressPeer is one entry of the peer table, resolved.
type egressPeer struct {
	Name string
	IP   net.IP
	Port uint16
}

// buildEgressRuleSet derives the rule set from the loaded policy, the peer
// table and the run configuration.
//
// It takes a loaded [attest.Policy] rather than a path, because a policy that
// was not loaded is a policy whose signature nobody checked, and there is no
// way to obtain one of those from attest/policyfile.go by accident.
func buildEgressRuleSet(policy attest.Policy, peers map[string]string, listen string) (*egressRuleSet, error) {
	if policy.Egress.Unattested {
		return nil, errors.New("the policy permits unattested egress; nothing here generates rules for that, and a policy claiming it does not load")
	}
	listenPort, err := portOf(listen)
	if err != nil {
		return nil, fmt.Errorf("the run configuration's listen address %q: %w", listen, err)
	}
	rs := &egressRuleSet{ListenPort: listenPort}
	for _, name := range sortedKeys(peers) {
		host, port, err := net.SplitHostPort(peers[name])
		if err != nil {
			return nil, fmt.Errorf("peer %q is %q, which is not host:port: %w", name, peers[name], err)
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			// A name would have to be resolved, and a guest that resolves
			// names has a resolver to reach, which is the egress this rule set
			// exists to forbid.
			return nil, fmt.Errorf("peer %q is %q; the rule set needs a literal IPv4 address, because a guest that could resolve a name could reach a resolver", name, peers[name])
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("peer %q has port %q: %w", name, port, err)
		}
		rs.Peers = append(rs.Peers, egressPeer{Name: name, IP: ip.To4(), Port: uint16(n)})
	}

	input := egressChain{name: egressChainInput, hook: nftables.ChainHookInput, policy: nftables.ChainPolicyDrop}
	output := egressChain{name: egressChainOutput, hook: nftables.ChainHookOutput, policy: nftables.ChainPolicyDrop}
	forward := egressChain{name: egressChainForward, hook: nftables.ChainHookForward, policy: nftables.ChainPolicyDrop}

	input.rules = append(input.rules, ifaceRule(expr.MetaKeyIIFNAME, "lo", "iif \"lo\" accept"))
	output.rules = append(output.rules, ifaceRule(expr.MetaKeyOIFNAME, "lo", "oif \"lo\" accept"))

	for _, p := range rs.Peers {
		// Outbound: this sandbox dialing the peer's listener, and this
		// sandbox answering from its own listener. Two rules rather than one,
		// because the ephemeral port of whichever side dialled is not
		// something either side may name in advance.
		output.rules = append(output.rules,
			peerRule(peerRuleSpec{
				addrOffset: 16, addrLabel: "ip daddr",
				portOffset: 2, portLabel: "udp dport",
				ip: p.IP, port: p.Port,
				why: fmt.Sprintf("dial peer %q", p.Name),
			}),
			peerRule(peerRuleSpec{
				addrOffset: 16, addrLabel: "ip daddr",
				portOffset: 0, portLabel: "udp sport",
				ip: p.IP, port: rs.ListenPort,
				why: fmt.Sprintf("answer peer %q from this sandbox's listener", p.Name),
			}),
		)
		// Inbound: the peer answering a dial of ours, and the peer dialing
		// this sandbox's listener.
		input.rules = append(input.rules,
			peerRule(peerRuleSpec{
				addrOffset: 12, addrLabel: "ip saddr",
				portOffset: 0, portLabel: "udp sport",
				ip: p.IP, port: p.Port,
				why: fmt.Sprintf("peer %q answering", p.Name),
			}),
			peerRule(peerRuleSpec{
				addrOffset: 12, addrLabel: "ip saddr",
				portOffset: 2, portLabel: "udp dport",
				ip: p.IP, port: rs.ListenPort,
				why: fmt.Sprintf("peer %q dialing this sandbox's listener", p.Name),
			}),
		)
	}

	// Two refusals rather than one, because the kernel turns them into an
	// answer at the socket by two different routes and only one of them works
	// for TCP. A dropped or ICMP-rejected SYN leaves connect() waiting: the
	// error ip_local_out returns is swallowed by tcp_connect, which ignores
	// everything but ECONNREFUSED and lets the retransmit timer take over, and
	// the ICMP that nf_reject builds arrives too late to matter. A reset does
	// reach it, because a RST on a socket in SYN_SENT is exactly the thing TCP
	// is listening for. UDP needs no such help: a datagram dropped in the
	// output hook fails the sendmsg with EPERM there and then.
	output.rules = append(output.rules, egressRule{
		text: "meta l4proto tcp reject with tcp reset        # so that connect() fails now rather than in a minute",
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
	}, egressRule{
		text: "reject with icmpx admin-prohibited            # everything else the policy did not permit",
		exprs: []expr.Any{
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		},
	})

	rs.chains = []egressChain{input, output, forward}
	return rs, nil
}

// ifaceRule matches one interface by name and accepts. The kernel compares the
// whole IFNAMSIZ-wide field, so the name is zero padded to sixteen bytes.
func ifaceRule(key expr.MetaKey, name, text string) egressRule {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return egressRule{
		text: text,
		exprs: []expr.Any{
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: padded},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// peerRuleSpec describes one accept rule: which address field, which port
// field, and what to put in them.
type peerRuleSpec struct {
	addrOffset uint32
	addrLabel  string
	portOffset uint32
	portLabel  string
	ip         net.IP
	port       uint16
	why        string
}

// peerRule renders and compiles one accept rule.
//
// The nfproto test in front is not decoration. This is an `inet` table, so the
// same chain sees IPv4 and IPv6 packets, and a payload offset counted from the
// network header means different fields in the two. Without it the rule would
// read some other part of an IPv6 header and accept on a coincidence.
func peerRule(s peerRuleSpec) egressRule {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, s.port)
	return egressRule{
		text: fmt.Sprintf("meta nfproto ipv4 %s %s meta l4proto udp %s %d accept   # %s",
			s.addrLabel, s.ip.String(), s.portLabel, s.port, s.why),
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: s.addrOffset, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(nil), s.ip.To4()...)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: s.portOffset, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// portOf reads the port out of a host:port address.
func portOf(addr string) (uint16, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("port 0 asks the kernel to choose, and a rule set cannot name a port nobody has chosen yet")
	}
	return uint16(n), nil
}

// Render writes the rule set in nft's own syntax.
//
// It is nft syntax and not this package's own because the reader of a guest
// console is an operator who knows nft, and because a rendering nobody can
// paste into `nft -f` to compare is a rendering nobody checks. It is generated
// from the same structures [Install] sends to the kernel.
func (rs *egressRuleSet) Render(out io.Writer) {
	fmt.Fprintf(out, "table inet %s {\n", egressTableName)
	for _, ch := range rs.chains {
		fmt.Fprintf(out, "\tchain %s {\n", ch.name)
		fmt.Fprintf(out, "\t\ttype filter hook %s priority 0; policy %s;\n", ch.name, policyWord(ch.policy))
		for _, r := range ch.rules {
			fmt.Fprintf(out, "\t\t%s\n", r.text)
		}
		fmt.Fprintf(out, "\t}\n")
	}
	fmt.Fprintf(out, "}\n")
}

func policyWord(p nftables.ChainPolicy) string {
	if p == nftables.ChainPolicyAccept {
		return "accept"
	}
	return "drop"
}

// Install puts the rule set in the kernel, replacing whatever was there.
//
// The whole ruleset is flushed first. In the measured guest that is not a
// destructive act: init has just mounted /proc and loaded nf_tables, nothing
// else runs, and there is nothing to flush. It is done anyway so that this
// cannot half-install over somebody else's table when it is run on a
// workstation by hand.
func (rs *egressRuleSet) Install() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening a netlink connection to nf_tables: %w", err)
	}
	defer c.CloseLasting()

	c.FlushRuleset()
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: egressTableName})
	for _, ch := range rs.chains {
		policy := ch.policy
		chain := c.AddChain(&nftables.Chain{
			Name:     ch.name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  ch.hook,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &policy,
		})
		for _, r := range ch.rules {
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: r.exprs})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("committing the rule set: %w", err)
	}
	return nil
}

// readInstalledRuleSet asks the kernel what it is holding and renders it.
//
// This is not the same thing as printing what was just sent: the rules come
// back out of nf_tables, decoded from the kernel's own bytes, so a rule that
// was silently dropped or altered on the way in shows up here as an absence or
// a difference. It is the capture the record keeps.
func readInstalledRuleSet(out io.Writer) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening a netlink connection to nf_tables: %w", err)
	}
	defer c.CloseLasting()

	tables, err := c.ListTables()
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	if len(tables) == 0 {
		return errors.New("the kernel holds no nftables table at all")
	}
	chains, err := c.ListChains()
	if err != nil {
		return fmt.Errorf("listing chains: %w", err)
	}
	for _, t := range tables {
		fmt.Fprintf(out, "table %s %s {\n", familyWord(t.Family), t.Name)
		var mine []*nftables.Chain
		for _, ch := range chains {
			if ch.Table.Name == t.Name && ch.Table.Family == t.Family {
				mine = append(mine, ch)
			}
		}
		sort.Slice(mine, func(i, j int) bool { return mine[i].Name < mine[j].Name })
		for _, ch := range mine {
			pol := "(regular chain)"
			if ch.Policy != nil {
				pol = fmt.Sprintf("type %s hook %s priority %d; policy %s;",
					ch.Type, hookWord(ch.Hooknum), priorityOf(ch), policyWord(*ch.Policy))
			}
			fmt.Fprintf(out, "\tchain %s {\n\t\t%s\n", ch.Name, pol)
			rules, err := c.GetRules(t, ch)
			if err != nil {
				return fmt.Errorf("reading the rules of chain %s: %w", ch.Name, err)
			}
			for _, r := range rules {
				fmt.Fprintf(out, "\t\t%s   # handle %d\n", renderExprs(r.Exprs), r.Handle)
			}
			fmt.Fprintf(out, "\t}\n")
		}
		fmt.Fprintf(out, "}\n")
	}
	return nil
}

func priorityOf(ch *nftables.Chain) int32 {
	if ch.Priority == nil {
		return 0
	}
	return int32(*ch.Priority)
}

func familyWord(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return fmt.Sprintf("family%d", f)
}

func hookWord(h *nftables.ChainHook) string {
	if h == nil {
		return "none"
	}
	switch *h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	}
	return fmt.Sprintf("hook%d", *h)
}

// renderExprs turns the expressions the kernel handed back into one line.
//
// It renders the expression vocabulary this file emits and names anything else
// by its Go type rather than guessing at it: a rule set read back is evidence,
// and evidence that quietly prettifies what it did not understand is worth
// less than one that says it did not understand.
func renderExprs(exprs []expr.Any) string {
	out := ""
	add := func(format string, a ...any) {
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf(format, a...)
	}
	// The comparison that follows a load is rendered with it, so a reader sees
	// "ip daddr 10.128.0.41" rather than a register dance.
	var pending string
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Meta:
			switch v.Key {
			case expr.MetaKeyIIFNAME:
				pending = "iif"
			case expr.MetaKeyOIFNAME:
				pending = "oif"
			case expr.MetaKeyNFPROTO:
				pending = "meta nfproto"
			case expr.MetaKeyL4PROTO:
				pending = "meta l4proto"
			default:
				pending = fmt.Sprintf("meta key%d", v.Key)
			}
		case *expr.Payload:
			switch {
			case v.Base == expr.PayloadBaseNetworkHeader && v.Offset == 12 && v.Len == 4:
				pending = "ip saddr"
			case v.Base == expr.PayloadBaseNetworkHeader && v.Offset == 16 && v.Len == 4:
				pending = "ip daddr"
			case v.Base == expr.PayloadBaseTransportHeader && v.Offset == 0 && v.Len == 2:
				pending = "sport"
			case v.Base == expr.PayloadBaseTransportHeader && v.Offset == 2 && v.Len == 2:
				pending = "dport"
			default:
				pending = fmt.Sprintf("payload base%d offset %d len %d", v.Base, v.Offset, v.Len)
			}
		case *expr.Cmp:
			add("%s %s", pending, cmpValue(pending, v.Data))
			pending = ""
		case *expr.Verdict:
			switch v.Kind {
			case expr.VerdictAccept:
				add("accept")
			case expr.VerdictDrop:
				add("drop")
			default:
				add("verdict %d", v.Kind)
			}
		case *expr.Reject:
			switch v.Type {
			case unix.NFT_REJECT_TCP_RST:
				add("reject with tcp reset")
			case unix.NFT_REJECT_ICMPX_UNREACH:
				add("reject with icmpx code %d", v.Code)
			default:
				add("reject type %d code %d", v.Type, v.Code)
			}
		case *expr.Counter:
			add("counter packets %d bytes %d", v.Packets, v.Bytes)
		default:
			add("%T", e)
		}
	}
	if out == "" {
		return "(no expressions)"
	}
	return out
}

// cmpValue renders the right-hand side of a comparison in whatever shape the
// left-hand side made it.
func cmpValue(field string, data []byte) string {
	switch {
	case (field == "iif" || field == "oif") && len(data) == unix.IFNAMSIZ:
		name := data
		for i, b := range data {
			if b == 0 {
				name = data[:i]
				break
			}
		}
		return fmt.Sprintf("%q", string(name))
	case (field == "ip saddr" || field == "ip daddr") && len(data) == 4:
		return net.IP(data).String()
	case (field == "sport" || field == "dport") && len(data) == 2:
		return strconv.Itoa(int(binary.BigEndian.Uint16(data)))
	case field == "meta nfproto" && len(data) == 1:
		if data[0] == unix.NFPROTO_IPV4 {
			return "ipv4"
		}
		if data[0] == unix.NFPROTO_IPV6 {
			return "ipv6"
		}
	case field == "meta l4proto" && len(data) == 1:
		switch data[0] {
		case unix.IPPROTO_UDP:
			return "udp"
		case unix.IPPROTO_TCP:
			return "tcp"
		case unix.IPPROTO_ICMP:
			return "icmp"
		}
	}
	return fmt.Sprintf("0x%x", data)
}

// An egressProbe is one attempt to leave the sandbox where the policy says
// nothing may.
type egressProbe struct {
	Network string // "tcp" or "udp"
	Address string
	Why     string
}

// defaultEgressProbes are the addresses the record has to show refused: the
// provider's metadata server, which is the one address every cloud guest can
// reach and the one an exfiltrating guest would reach for first, and a public
// resolver, which is the shape of "anywhere on the internet".
func defaultEgressProbes() []egressProbe {
	return []egressProbe{
		{Network: "tcp", Address: "169.254.169.254:80", Why: "the provider's metadata server"},
		{Network: "tcp", Address: "8.8.8.8:53", Why: "a public resolver, over TCP"},
		{Network: "udp", Address: "8.8.8.8:53", Why: "a public resolver, over UDP"},
	}
}

// egressProbeTimeout bounds each attempt. A rule that rejects answers in
// microseconds; this is only long enough to tell a reject from a drop.
const egressProbeTimeout = 5 * time.Second

// runEgressProbes tries each address and says what happened. It returns the
// number of attempts that were NOT refused, so that a caller can fail on any
// of them.
//
// The distinction it draws is the point of the exercise. A guest with no
// default route cannot reach anything either, and a transcript showing
// "connection failed" would not say which of the two properties it had
// demonstrated. So the errno is reported, and read: EACCES or EPERM is the
// rule refusing; ENETUNREACH or EHOSTUNREACH is the routing table having
// nothing to say, which would mean the rule was never tested.
func runEgressProbes(probes []egressProbe, logf func(string, ...any)) int {
	leaked := 0
	for _, p := range probes {
		verdict, detail := attemptEgress(p)
		if verdict == "PERMITTED" {
			leaked++
		}
		logf("EGRESS %s %s/%s: %s (%s) — %s", verdict, p.Network, p.Address, detail, p.Why, egressVerdictMeaning(verdict))
	}
	return leaked
}

func egressVerdictMeaning(verdict string) string {
	switch verdict {
	case "REFUSED":
		return "the netfilter rule refused it"
	case "UNROUTED":
		return "no route, so the rule was never reached; this does not demonstrate the policy"
	case "TIMEOUT":
		return "no answer within the probe timeout: a drop rather than a reject, or a black hole"
	case "PERMITTED":
		return "IT LEFT THE SANDBOX; the policy did not hold"
	}
	return "unclassified"
}

// attemptEgress makes one attempt and classifies the failure.
func attemptEgress(p egressProbe) (verdict, detail string) {
	d := net.Dialer{Timeout: egressProbeTimeout}
	conn, err := d.Dial(p.Network, p.Address)
	if err == nil {
		// A connected UDP socket costs nothing to open, so for UDP the dial
		// proves nothing on its own: the datagram has to be sent.
		if p.Network == "udp" {
			_ = conn.SetWriteDeadline(time.Now().Add(egressProbeTimeout))
			_, err = conn.Write([]byte("egress probe"))
		}
		if err == nil {
			// One more read for UDP, in case the send was accepted locally
			// and the refusal came back as an ICMP error.
			if p.Network == "udp" {
				_ = conn.SetReadDeadline(time.Now().Add(egressProbeTimeout))
				buf := make([]byte, 1)
				_, err = conn.Read(buf)
			}
		}
		conn.Close()
		if err == nil {
			return "PERMITTED", "the attempt succeeded"
		}
	}
	return classifyEgressError(err), err.Error()
}

// classifyEgressError reads an errno the way the kernel meant it.
func classifyEgressError(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.EACCES, unix.EPERM, unix.ECONNREFUSED:
			return "REFUSED"
		case unix.ENETUNREACH, unix.EHOSTUNREACH:
			return "UNROUTED"
		}
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "TIMEOUT"
	}
	return "REFUSED-OTHER"
}

// runEgressMode is the whole of -egress: load the three documents, and then do
// one thing.
//
// It loads this sandbox's own policy here rather than taking it from a running
// [tunneld.Tunneld], because these modes run before there is one — the rules
// have to be in the kernel before anything opens a socket. The load is the same
// call tunneld makes and refuses in the same way: no signature, no rules.
func runEgressMode(mode, extra, configDir string, cfg *runConfig, peers map[string]string, author ed25519.PublicKey, logf func(string, ...any), out io.Writer) int {
	policyPath := filepath.Join(configDir, policyName)
	policy, err := attest.LoadPolicyFile(policyPath, author)
	if err != nil {
		logf("refusing to touch the network: %v", err)
		return exitRefusedToStart
	}
	logf("policy %s loaded under the author key; digest %s", policyPath, policy.Digest)
	logf("policy egress: version %d, unattested egress permitted: %v", policy.Egress.Version, policy.Egress.Unattested)

	switch mode {
	case egressModePrint, egressModeInstall:
		rs, err := buildEgressRuleSet(policy, peers, cfg.Listen)
		if err != nil {
			logf("refusing to touch the network: %v", err)
			return exitRefusedToStart
		}
		rs.SandboxID = cfg.SandboxID
		logf("sandbox %q listens on udp/%d; %d peer(s) in the table", rs.SandboxID, rs.ListenPort, len(rs.Peers))
		logf("EGRESS RULES as the signed policy and the peer table imply them:")
		rs.Render(out)
		if mode == egressModePrint {
			return exitOK
		}
		if err := rs.Install(); err != nil {
			logf("refusing to continue: installing the rule set: %v", err)
			return exitRefusedToStart
		}
		logf("EGRESS RULES INSTALLED; as the kernel holds them:")
		if err := readInstalledRuleSet(out); err != nil {
			logf("refusing to continue: reading the rule set back: %v", err)
			return exitRefusedToStart
		}
		return exitOK

	case egressModeProbe:
		probes := defaultEgressProbes()
		more, err := parseEgressProbes(extra)
		if err != nil {
			logf("refusing to probe: %v", err)
			return exitRefusedToStart
		}
		probes = append(probes, more...)
		logf("EGRESS PROBE: %d attempt(s) at addresses this policy permits nothing to reach", len(probes))
		leaked := runEgressProbes(probes, logf)
		if leaked != 0 {
			logf("EGRESS PROBE FAILED: %d of %d attempt(s) left the sandbox", leaked, len(probes))
			return exitEgressLeaked
		}
		logf("EGRESS PROBE PASSED: every attempt was refused before it left")
		return exitOK
	}
	logf("refusing to start: -egress %q is not %q, %q or %q", mode, egressModePrint, egressModeInstall, egressModeProbe)
	return exitRefusedToStart
}

// parseEgressProbes reads the extra targets: "udp:10.128.0.1:53,tcp:10.128.0.1:80".
//
// They are a flag rather than a constant because the one address that is
// interesting and not universal is the guest's own gateway, and the gateway is
// on the config device with the rest of the addressing.
func parseEgressProbes(spec string) ([]egressProbe, error) {
	if spec == "" {
		return nil, nil
	}
	var out []egressProbe
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		network, address, ok := strings.Cut(field, ":")
		if !ok || (network != "tcp" && network != "udp") {
			return nil, fmt.Errorf("egress probe target %q is not tcp:ADDR:PORT or udp:ADDR:PORT", field)
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return nil, fmt.Errorf("egress probe target %q: %w", field, err)
		}
		out = append(out, egressProbe{Network: network, Address: address, Why: "named by -egress-probe"})
	}
	return out, nil
}
