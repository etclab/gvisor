// Command ceilinginstall is the ceiling as a shrunken egress.go would hold it:
// a constant rule set, built from two compiled-in values and nothing else,
// installed over the same github.com/google/nftables path
// attest/cmd/tunneld/egress.go uses today, and then read back out of the kernel
// and printed.
//
// It is here to answer half of E3's second question — what survives the shrink
// — by construction rather than by assertion. Every function below other than
// buildCeiling is COPIED VERBATIM from attest/cmd/tunneld/egress.go, with one
// exception noted at renderExprs. They are copied rather than imported because
// they are in package main of another command and Go has no way to reach them.
// Copied, they demonstrate exactly what the surviving half of that file is:
//
//	ifaceRule, Render, policyWord, Install, readInstalledRuleSet, priorityOf,
//	familyWord, hookWord, renderExprs, cmpValue
//
// and what it no longer needs: buildEgressRuleSet, peerRule, peerRuleSpec,
// portOf, egressPeer, and the policy/peer-table/listen-address plumbing that
// fed them.
//
// The one exception. renderExprs here carries a case egress.go's does not:
// *expr.Bitwise. The ceiling refuses 169.254.0.0/16 with a prefix match, and a
// prefix match is a mask-and-compare in the kernel. egress.go's renderExprs
// never emitted one — every rule it generated compared a whole address — so it
// prints "*expr.Bitwise" for this rule and loses the mask. That is six lines
// that have to be ADDED during the shrink, and it is the only addition E3
// found.
//
// Usage: ceilinginstall [-print-only]
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// The constant. Two values, both compiled in, neither readable from the config
// device. Changing either makes a different image with a different
// measurement.
// ---------------------------------------------------------------------------

const (
	// ceilingIface is the VPC link as the kernel names it when no udev runs.
	ceilingIface = "eth0"

	// ceilingPort is the tunnel's UDP port.
	ceilingPort uint16 = 4433

	egressTableName    = "attested_tunnel"
	egressChainInput   = "input"
	egressChainOutput  = "output"
	egressChainForward = "forward"
)

// ceilingLinkLocal is the block the ceiling refuses before it reaches the
// tunnel-port grant: 169.254.0.0/16, which is where every cloud provider's
// metadata server lives.
var ceilingLinkLocal = net.IPNet{IP: net.IPv4(169, 254, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}

// ---------------------------------------------------------------------------
// Copied verbatim from attest/cmd/tunneld/egress.go: the types.
// ---------------------------------------------------------------------------

type egressRule struct {
	text  string
	exprs []expr.Any
}

type egressChain struct {
	name   string
	hook   *nftables.ChainHook
	policy nftables.ChainPolicy
	rules  []egressRule
}

// An egressRuleSet is, after the shrink, the constant and nothing else: no
// SandboxID, no ListenPort, no Peers. What is left is the chains.
type egressRuleSet struct {
	chains []egressChain
}

// ---------------------------------------------------------------------------
// buildCeiling replaces buildEgressRuleSet. Note the signature: no policy, no
// peer table, no listen address, and no error return, because a constant
// cannot fail to be built.
// ---------------------------------------------------------------------------

func buildCeiling() *egressRuleSet {
	input := egressChain{name: egressChainInput, hook: nftables.ChainHookInput, policy: nftables.ChainPolicyDrop}
	output := egressChain{name: egressChainOutput, hook: nftables.ChainHookOutput, policy: nftables.ChainPolicyDrop}
	forward := egressChain{name: egressChainForward, hook: nftables.ChainHookForward, policy: nftables.ChainPolicyDrop}

	// Loopback, so the kernel can deliver a rule's own refusal back to the
	// socket that tripped it.
	input.rules = append(input.rules, ifaceRule(expr.MetaKeyIIFNAME, "lo", "iifname \"lo\" accept"))
	output.rules = append(output.rules, ifaceRule(expr.MetaKeyOIFNAME, "lo", "oifname \"lo\" accept"))

	// The tunnel port on the VPC link, to and from any address. Two rules per
	// direction for the same reason the policy-driven set had two per peer:
	// the ephemeral port of whichever side dialled is not something either
	// side may name in advance.
	input.rules = append(input.rules,
		portRule(expr.MetaKeyIIFNAME, "iifname", 0, "udp sport", "a peer answering a dial of ours"),
		portRule(expr.MetaKeyIIFNAME, "iifname", 2, "udp dport", "a peer dialing this sandbox's listener"),
	)
	// The TCP reset is hoisted above everything: the ceiling permits no TCP at
	// all, every accept below is UDP-only, and a TCP attempt that fell through
	// to the ICMP refusal at the bottom — or to the link-local carve-out below
	// — reaches the socket as EHOSTUNREACH, which the ticket 19 probe
	// classifies as UNROUTED rather than REFUSED. Same packets dropped either
	// way; only the transcript differs, and the transcript is the deliverable.
	output.rules = append(output.rules, egressRule{
		text: "meta l4proto tcp reject with tcp reset        # so that connect() fails now rather than in a minute, and says a rule did it",
		exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
	})
	// The link-local carve-out comes before the grant, so that the grant's
	// "any address" does not include the provider's metadata server.
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

// portRule is what peerRule shrinks to: the same shape with the address test
// taken out and an interface test put in. It names no address, so nothing on
// the config device can reach it.
func portRule(ifaceKey expr.MetaKey, ifaceLabel string, portOffset uint32, portLabel, why string) egressRule {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, ceilingIface)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, ceilingPort)
	return egressRule{
		text: fmt.Sprintf("meta nfproto ipv4 %s %q meta l4proto udp %s %d accept   # %s",
			ifaceLabel, ceilingIface, portLabel, ceilingPort, why),
		exprs: []expr.Any{
			// The nfproto test is not decoration: this is an inet table, so
			// the same chain sees IPv4 and IPv6, and the tunnel is IPv4.
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

// linkLocalRefusal refuses 169.254.0.0/16 outright. A prefix match is a
// mask-and-compare: load the destination address, AND it with the mask, and
// compare the result with the network address.
func linkLocalRefusal() egressRule {
	network := ceilingLinkLocal.IP.To4()
	mask := []byte(ceilingLinkLocal.Mask)
	return egressRule{
		text: fmt.Sprintf("meta nfproto ipv4 ip daddr %s reject with icmpx admin-prohibited   # the provider's metadata server is an address, and the grant above says \"any\"", ceilingLinkLocal.String()),
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

// ---------------------------------------------------------------------------
// Copied verbatim from attest/cmd/tunneld/egress.go below this line, except
// for the *expr.Bitwise case in renderExprs, which is new.
// ---------------------------------------------------------------------------

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
		return fmt.Errorf("the kernel holds no nftables table at all")
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

func renderExprs(exprs []expr.Any) string {
	out := ""
	add := func(format string, a ...any) {
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf(format, a...)
	}
	var pending string
	var mask []byte // NEW: carried from a *expr.Bitwise to the *expr.Cmp after it.
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Meta:
			switch v.Key {
			// NEW: "iifname"/"oifname", not "iif"/"oif". The kernel has always
			// held the name-matching rule — egress.go builds it with
			// MetaKeyIIFNAME — and only the rendering said otherwise. They are
			// different rules: iif compares an interface index resolved at load
			// time, iifname compares the name when a packet arrives.
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
		// NEW. A prefix match is a mask-and-compare, and without this case the
		// mask is lost and the rule reads as an exact match on the network
		// address — which is a different rule. Six lines, and the only thing
		// the shrink has to add.
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

// cmpValue is egress.go's, with one parameter added: the mask a preceding
// *expr.Bitwise set, so that an address comparison can print /16 rather than
// pretending to be exact.
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
			return fmt.Sprintf("%s/%d", net.IP(data).String(), ones)
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

func main() {
	printOnly := flag.Bool("print-only", false, "render the constant and stop, without touching the kernel")
	flag.Parse()

	rs := buildCeiling()
	fmt.Printf("ceiling: the constant, with no input from any config device (iface %q, udp/%d):\n", ceilingIface, ceilingPort)
	rs.Render(os.Stdout)
	if *printOnly {
		return
	}
	if err := rs.Install(); err != nil {
		fmt.Fprintln(os.Stderr, "ceiling: refusing to continue:", err)
		os.Exit(1)
	}
	fmt.Println("ceiling: INSTALLED; as the kernel holds it:")
	if err := readInstalledRuleSet(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ceiling: reading the rule set back:", err)
		os.Exit(1)
	}
}
