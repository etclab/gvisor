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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/attest/ceiling"
)

// The egress ceiling: the netfilter rule set every guest built from this image
// installs, the code that installs it, and the probe that proves it holds.
//
// # Why the rule set is a constant
//
// It was generated from `policy.json` until ticket 22, and the argument for
// generating it here was that tunneld already held the author key that judged
// that document's signature, so no second loader could disagree about what the
// policy said. The argument was sound and the arrangement was still wrong. A
// rule set derived from a document on the config device is a rule set the host
// supplies the inputs to; it cannot be installed until that device has been
// found and mounted, so the guest ran unconstrained for as long as finding a
// disk takes; and a verifier reading the image could not say what the guest
// would enforce. What replaces it is shorter and stronger: the rule set is a
// constant in the measured image ([ceiling]), so there is no document to check,
// nothing outside the launch measurement contributes a byte of it, and it goes
// in before the link is up.
//
// # What the ceiling grants, and what decides whom this sandbox talks to
//
// Loopback in both directions, and udp/[ceiling.Port] on [ceiling.Interface] to
// and from any address. Nothing else: no DHCP, no DNS, no NTP, no ICMP, no
// IPv6, no forwarding, and not the provider's metadata server, which is carved
// out of the tunnel-port grant by name because 169.254.169.254 is an address
// and "any address" would otherwise include it.
//
// The ceiling names no peer and must not. peers.json is on the config device,
// and a ceiling that read it would be a ceiling the config device could widen,
// which is the whole of what ticket 22 removes. Whom this sandbox will speak to
// is decided at the attestation layer — the per-verifier allow-list in
// reference-values.json — and by tunneld's own peer table, which refuses a name
// it does not hold before a socket is opened. Two mechanisms, disjoint: this
// one bounds what the guest can reach at all, that one decides whom it will
// speak to. The cost is stated plainly: under the ceiling alone a compromised
// guest could send udp/4433 to any address on the VPC. It cannot establish
// anything there without evidence the allow-list admits, and it cannot reach
// the metadata server at all.
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

// An egressRuleSet is the whole rule set. Since ticket 22 there is one of them
// and it takes no inputs, so there is nothing here but the chains.
type egressRuleSet struct {
	chains []egressChain
}

// ceilingLinkLocal is the block the ceiling refuses before it reaches the
// tunnel-port grant: 169.254.0.0/16, which is where every cloud provider's
// metadata server lives. It is universal rather than per-image, which is why it
// is not one of [ceiling]'s two constants.
var ceilingLinkLocal = net.IPNet{IP: net.IPv4(169, 254, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}

// buildCeiling is the ceiling, as the kernel has to be handed it.
//
// Note the signature: no policy, no peer table, no listen address, and no error
// return, because a constant cannot fail to be built. The text beside it —
// [ceiling.Text] — is the same rule set for a reader, and a guard test in this
// package's tests holds the two together.
func buildCeiling() *egressRuleSet {
	input := egressChain{name: egressChainInput, hook: nftables.ChainHookInput, policy: nftables.ChainPolicyDrop}
	output := egressChain{name: egressChainOutput, hook: nftables.ChainHookOutput, policy: nftables.ChainPolicyDrop}
	forward := egressChain{name: egressChainForward, hook: nftables.ChainHookForward, policy: nftables.ChainPolicyDrop}

	// Loopback, so that the kernel can deliver a rule's own refusal back to the
	// socket that tripped it.
	input.rules = append(input.rules, ifaceRule(expr.MetaKeyIIFNAME, "lo", "iifname \"lo\" accept"))
	output.rules = append(output.rules, ifaceRule(expr.MetaKeyOIFNAME, "lo", "oifname \"lo\" accept"))

	// The tunnel port on the VPC link, to and from any address. Two rules per
	// direction for the same reason the policy-driven set had two per peer: the
	// ephemeral port of whichever side dialled is not something either side may
	// name in advance.
	input.rules = append(input.rules,
		portRule(expr.MetaKeyIIFNAME, "iifname", 0, "udp sport", "a peer answering a dial of ours"),
		portRule(expr.MetaKeyIIFNAME, "iifname", 2, "udp dport", "a peer dialing this sandbox's listener"),
	)

	// The reset is hoisted above everything in the output chain. The ceiling
	// permits no TCP at all, every accept below it is UDP-only, and a TCP
	// attempt that fell through to the ICMP refusal at the bottom — or to the
	// link-local carve-out under this line — reaches the socket as
	// EHOSTUNREACH, which the probe classifies, correctly, as UNROUTED: "the
	// rule was never reached; this does not demonstrate the policy". The same
	// packets are refused either way; only the transcript differs, and the
	// transcript is the deliverable (ticket 22, spike E3, finding 4).
	output.rules = append(output.rules, egressRule{
		text: "meta l4proto tcp reject with tcp reset        # so that connect() fails now rather than in a minute, and says a rule did it",
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
	})
	// And the carve-out before the grant, so that the grant's "any address"
	// does not include the provider's metadata server.
	output.rules = append(output.rules, linkLocalRefusal())
	output.rules = append(output.rules,
		portRule(expr.MetaKeyOIFNAME, "oifname", 2, "udp dport", "dialing a peer"),
		portRule(expr.MetaKeyOIFNAME, "oifname", 0, "udp sport", "answering a peer from this sandbox's listener"),
	)
	output.rules = append(output.rules, egressRule{
		text: "reject with icmpx admin-prohibited            # everything the ceiling does not permit",
		exprs: []expr.Any{
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		},
	})

	return &egressRuleSet{chains: []egressChain{input, output, forward}}
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

// portRule accepts the tunnel port on the VPC link, in one direction, from and
// to any address. It is what peerRule was before ticket 22, with the address
// test taken out and an interface test put in — so it names no address, and
// nothing on the config device can reach it.
//
// The nfproto test in front is not decoration. This is an `inet` table, so the
// same chain sees IPv4 and IPv6 packets, and the tunnel is IPv4: without it an
// IPv6 packet would be measured against an offset counted from a header it does
// not have. With it, IPv6 falls through to the chain's drop policy.
func portRule(ifaceKey expr.MetaKey, ifaceLabel string, portOffset uint32, portLabel, why string) egressRule {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, ceiling.Interface)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, ceiling.Port)
	return egressRule{
		text: fmt.Sprintf("meta nfproto ipv4 %s %q meta l4proto udp %s %d accept   # %s",
			ifaceLabel, ceiling.Interface, portLabel, ceiling.Port, why),
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Meta{Key: ifaceKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: padded},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: portOffset, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// linkLocalRefusal refuses [ceilingLinkLocal] outright.
//
// A prefix match is a mask-and-compare in the kernel: load the destination
// address, AND it with the mask, compare the result with the network address.
// It is the only rule this file emits that is not an exact comparison, and
// [renderExprs] has a case for the Bitwise expression only because of it.
func linkLocalRefusal() egressRule {
	network := ceilingLinkLocal.IP.To4()
	mask := []byte(ceilingLinkLocal.Mask)
	return egressRule{
		text: fmt.Sprintf("meta nfproto ipv4 ip daddr %s reject with icmpx admin-prohibited   # the provider's metadata server is an address, and the grant below says \"any\"", ceilingLinkLocal.String()),
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(nil), network...)},
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		},
	}
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
//
// An interface test renders as iifname or oifname, and the distinction is not
// cosmetic: iif compares an interface index resolved when the rule is loaded,
// which fails outright against a namespace where the interface does not exist
// yet, while iifname compares the name when a packet arrives — which is what
// lets the ceiling go in before the link is up. This file has always built the
// name form ([ifaceRule] and [portRule] pass MetaKeyIIFNAME and MetaKeyOIFNAME)
// and until ticket 22 only the rendering said otherwise, so every egress
// capture recorded before it described a rule the guest did not install.
func renderExprs(exprs []expr.Any) string {
	out := ""
	add := func(format string, a ...any) {
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf(format, a...)
	}
	// The comparison that follows a load is rendered with it, so a reader sees
	// "ip daddr 10.128.0.41" rather than a register dance, and the mask a
	// Bitwise left behind is carried to the comparison it belongs to.
	var pending string
	var mask []byte
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Meta:
			switch v.Key {
			case expr.MetaKeyIIFNAME:
				pending = "iifname"
			case expr.MetaKeyOIFNAME:
				pending = "oifname"
			case expr.MetaKeyNFPROTO:
				pending = "meta nfproto"
			case expr.MetaKeyL4PROTO:
				pending = "meta l4proto"
			default:
				pending = fmt.Sprintf("meta key%d", v.Key)
			}
		case *expr.Payload:
			pending = payloadField(v)
		// A prefix match is a mask-and-compare, and without this the mask is
		// lost and the rule reads as an exact match on the network address —
		// which is a different rule from the one the kernel is enforcing.
		case *expr.Bitwise:
			mask = v.Mask
		case *expr.Cmp:
			add("%s %s", pending, cmpValue(pending, v.Data, mask))
			pending = ""
			mask = nil
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

// payloadField names the header field a load put in a register, for the four
// this file reads. Anything else is described by its offset rather than named,
// because a name guessed at is worth less than the numbers it was guessed from.
func payloadField(p *expr.Payload) string {
	switch {
	case p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 12 && p.Len == 4:
		return "ip saddr"
	case p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 16 && p.Len == 4:
		return "ip daddr"
	case p.Base == expr.PayloadBaseTransportHeader && p.Offset == 0 && p.Len == 2:
		return "sport"
	case p.Base == expr.PayloadBaseTransportHeader && p.Offset == 2 && p.Len == 2:
		return "dport"
	}
	return fmt.Sprintf("payload base%d offset %d len %d", p.Base, p.Offset, p.Len)
}

// cmpValue renders the right-hand side of a comparison in whatever shape the
// left-hand side made it, and under whatever mask a preceding [expr.Bitwise]
// left for it: an address comparison behind a mask is a prefix and says so,
// rather than pretending to be exact.
func cmpValue(field string, data, mask []byte) string {
	switch {
	case (field == "iifname" || field == "oifname") && len(data) == unix.IFNAMSIZ:
		name := data
		for i, b := range data {
			if b == 0 {
				name = data[:i]
				break
			}
		}
		return fmt.Sprintf("%q", string(name))
	case (field == "ip saddr" || field == "ip daddr") && len(data) == 4:
		if len(mask) == 4 {
			ones, _ := net.IPMask(mask).Size()
			return fmt.Sprintf("%s/%d", net.IP(data), ones)
		}
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
		// The attempt the ceiling's own grant would otherwise permit: the grant
		// is the tunnel port to any address, and the metadata server is an
		// address. It is refused by the carve-out above the grant, and this is
		// the probe that says so (ticket 22, spike E3).
		{Network: "udp", Address: "169.254.169.254:4433", Why: "the metadata server, on the one port the ceiling grants"},
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

// runEgressMode is the whole of -egress: one thing to the kernel or to the
// network, and then this process ends.
//
// It reads nothing. Until ticket 22 it loaded this sandbox's signed policy
// first and derived the rule set from it, which is why the guest's init could
// not install anything before it had found and mounted the config device. The
// ceiling is compiled in, so these modes need no config device, no author key
// and no policy — which is what lets init run `tunneld -egress install`
// immediately after nf_tables loads, with the window in which a measured guest
// is unconstrained closed to zero.
func runEgressMode(mode, extra string, logf func(string, ...any), out io.Writer) int {
	switch mode {
	case egressModePrint:
		// The ceiling's own text and nothing else on the stream, so that this
		// output and the file in the record can be compared byte for byte —
		// and so that the file in the record is regenerated from the binary
		// that enforces it rather than maintained beside it.
		fmt.Fprint(out, ceiling.Text())
		return exitOK

	case egressModeInstall:
		logf("EGRESS CEILING %s (sha256 over the compiled-in ceiling; %s, udp/%d)",
			ceiling.DigestHex(), ceiling.Interface, ceiling.Port)
		rs := buildCeiling()
		logf("EGRESS CEILING as this image carries it:")
		rs.Render(out)
		if err := rs.Install(); err != nil {
			logf("refusing to continue: installing the ceiling: %v", err)
			return exitRefusedToStart
		}
		logf("EGRESS CEILING INSTALLED; as the kernel holds it:")
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
		logf("EGRESS PROBE: %d attempt(s) at addresses the ceiling permits nothing to reach", len(probes))
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
