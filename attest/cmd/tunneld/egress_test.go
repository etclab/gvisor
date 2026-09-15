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
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/attest"
)

// closedPolicy is what every policy this design will load looks like: an egress
// section at the version the loader reads, and unattested egress refused.
func closedPolicy() attest.Policy {
	return attest.Policy{Egress: attest.Egress{Version: 1, Unattested: false}}
}

// The rendering is the artefact a reader judges the guest by, so it is pinned
// here in full. A change to it is a change to what the record claims the guest
// enforces, and should have to be written down twice.
func TestEgressRuleSetRendersWhatThePolicyImplies(t *testing.T) {
	peers := map[string]string{
		"guest-b": "10.128.0.41:4433",
		"guest-c": "10.128.0.42:5555",
	}
	rs, err := buildEgressRuleSet(closedPolicy(), peers, "10.128.0.40:4433")
	if err != nil {
		t.Fatalf("buildEgressRuleSet: %v", err)
	}
	var out bytes.Buffer
	rs.Render(&out)
	got := out.String()

	want := []string{
		"table inet attested_tunnel {",
		"chain input {",
		"type filter hook input priority 0; policy drop;",
		"iif \"lo\" accept",
		"meta nfproto ipv4 ip saddr 10.128.0.41 meta l4proto udp udp sport 4433 accept",
		"meta nfproto ipv4 ip saddr 10.128.0.41 meta l4proto udp udp dport 4433 accept",
		"meta nfproto ipv4 ip saddr 10.128.0.42 meta l4proto udp udp sport 5555 accept",
		"meta nfproto ipv4 ip saddr 10.128.0.42 meta l4proto udp udp dport 4433 accept",
		"chain output {",
		"type filter hook output priority 0; policy drop;",
		"oif \"lo\" accept",
		"meta nfproto ipv4 ip daddr 10.128.0.41 meta l4proto udp udp dport 4433 accept",
		"meta nfproto ipv4 ip daddr 10.128.0.41 meta l4proto udp udp sport 4433 accept",
		"meta nfproto ipv4 ip daddr 10.128.0.42 meta l4proto udp udp dport 5555 accept",
		"meta nfproto ipv4 ip daddr 10.128.0.42 meta l4proto udp udp sport 4433 accept",
		"meta l4proto tcp reject with tcp reset",
		"reject with icmpx admin-prohibited",
		"chain forward {",
		"type filter hook forward priority 0; policy drop;",
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("the rendered rule set does not contain %q; it is:\n%s", line, got)
		}
	}
	// Nothing outside the tunnel port and the peer table may be named. An
	// address appearing here that nobody put in the peer table would be a hole
	// the rendering could hide behind its own verbosity.
	for _, forbidden := range []string{"169.254.169.254", "0.0.0.0", "accept\n\t}"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the rendered rule set contains %q, which nothing put there:\n%s", forbidden, got)
		}
	}
}

// A guest with no peers still gets a rule set, and it is the one that lets
// nothing out. The smoke boot runs exactly this shape, so "nobody to talk to"
// must not be a special case that quietly opens the guest up.
func TestEgressRuleSetWithNoPeersPermitsOnlyLoopback(t *testing.T) {
	rs, err := buildEgressRuleSet(closedPolicy(), map[string]string{}, "10.128.0.40:4433")
	if err != nil {
		t.Fatalf("buildEgressRuleSet: %v", err)
	}
	var out bytes.Buffer
	rs.Render(&out)
	got := out.String()
	if strings.Count(got, "accept") != 2 {
		t.Errorf("a peerless guest should accept on loopback and nowhere else; got:\n%s", got)
	}
	for _, want := range []string{"meta l4proto tcp reject with tcp reset", "reject with icmpx admin-prohibited"} {
		if !strings.Contains(got, want) {
			t.Errorf("a peerless guest's output chain must still end in %q; got:\n%s", want, got)
		}
	}
}

// The one thing the policy contributes to the shape of the rule set is the
// direction it fails in, so a policy claiming the other direction must not
// produce rules at all. attest/policyfile.go refuses to load such a document;
// this is the second refusal, in the code that would have had to honour it.
func TestEgressRuleSetRefusesAPolicyPermittingUnattestedEgress(t *testing.T) {
	p := closedPolicy()
	p.Egress.Unattested = true
	if _, err := buildEgressRuleSet(p, map[string]string{}, "10.128.0.40:4433"); err == nil {
		t.Fatal("a policy permitting unattested egress produced a rule set; nothing here implements permitting it")
	}
}

// A peer table naming a host rather than an address would need a resolver, and
// a guest that can reach a resolver has the egress this rule set exists to
// forbid. The refusal is at authoring time rather than at run time.
func TestEgressRuleSetRefusesANamedPeer(t *testing.T) {
	for _, peers := range []map[string]string{
		{"guest-b": "peer.example:4433"},
		{"guest-b": "10.128.0.41"},
	} {
		if _, err := buildEgressRuleSet(closedPolicy(), peers, "10.128.0.40:4433"); err == nil {
			t.Errorf("peer table %v produced a rule set; it names no address this rule set can use", peers)
		}
	}
}

// The extra probe targets come off the config device by way of a flag, so a
// malformed one has to be refused rather than silently dropped: a probe that
// was not run is a property that was not shown.
func TestParseEgressProbes(t *testing.T) {
	got, err := parseEgressProbes("udp:10.128.0.1:53, tcp:10.128.0.1:80")
	if err != nil {
		t.Fatalf("parseEgressProbes: %v", err)
	}
	if len(got) != 2 || got[0].Network != "udp" || got[0].Address != "10.128.0.1:53" ||
		got[1].Network != "tcp" || got[1].Address != "10.128.0.1:80" {
		t.Errorf("parseEgressProbes gave %+v", got)
	}
	for _, bad := range []string{"sctp:10.0.0.1:53", "udp:10.0.0.1", "10.0.0.1:53"} {
		if _, err := parseEgressProbes(bad); err == nil {
			t.Errorf("parseEgressProbes(%q) was accepted", bad)
		}
	}
}

// The netlink half, exercised only where it can be: installing a rule set needs
// CAP_NET_ADMIN and a kernel with nf_tables. Where that holds — the guest, and
// a workstation running the test as root — the rules go in and are read back
// out of the kernel rather than out of the structure that sent them, so a rule
// the kernel silently declined shows up as an absence.
//
// It is skipped rather than failed elsewhere, and the skip says which of the
// two reasons it was: a guard that is quietly never run is worse than no guard.
func TestEgressRuleSetInstalls(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installing an nftables rule set needs CAP_NET_ADMIN; run this test as root to exercise the netlink path")
	}
	if _, err := os.Stat("/proc/net/netfilter"); err != nil {
		t.Skipf("this kernel exposes no netfilter (%v); nothing to install into", err)
	}
	rs, err := buildEgressRuleSet(closedPolicy(), map[string]string{"guest-b": "10.128.0.41:4433"}, "10.128.0.40:4433")
	if err != nil {
		t.Fatalf("buildEgressRuleSet: %v", err)
	}
	if err := rs.Install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	var back bytes.Buffer
	if err := readInstalledRuleSet(&back); err != nil {
		t.Fatalf("readInstalledRuleSet: %v", err)
	}
	got := back.String()
	for _, want := range []string{
		"table inet attested_tunnel {",
		"policy drop;",
		"iif \"lo\" accept",
		"ip daddr 10.128.0.41",
		"reject with icmpx",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the kernel's own copy of the rule set does not contain %q; it is:\n%s", want, got)
		}
	}
}

// The three functions that read a rule set back out of the kernel and render
// it — readInstalledRuleSet, renderExprs and cmpValue — are the half of this
// file that ticket 22's shrink keeps, and they are the reason a constant
// compiled into the measured image can still be shown to be the thing the
// kernel is enforcing. They were reached only through TestEgressRuleSetInstalls
// before, which needs root, so on a workstation they were never run at all.
// The tests below drive them directly.

// cmpValue renders the right-hand side of a comparison in the shape the
// left-hand side made it, and every field this file loads into a register has
// to have a case here: a comparison that came back as hexadecimal is a rule
// nobody reading the record can check. The last four rows are the fallback,
// which is deliberate and is pinned here too — evidence that quietly prettifies
// what it did not understand is worth less than evidence that says so.
func TestCmpValueRendersEveryFieldItHandles(t *testing.T) {
	iface := make([]byte, unix.IFNAMSIZ)
	copy(iface, "eth0")
	for _, tc := range []struct {
		name  string
		field string
		data  []byte
		want  string
	}{
		{"inbound interface", "iif", iface, `"eth0"`},
		{"outbound interface", "oif", iface, `"eth0"`},
		{"source address", "ip saddr", []byte{10, 128, 0, 41}, "10.128.0.41"},
		{"destination address", "ip daddr", []byte{169, 254, 169, 254}, "169.254.169.254"},
		{"source port", "sport", []byte{0x11, 0x51}, "4433"},
		{"destination port", "dport", []byte{0x00, 0x35}, "53"},
		{"nfproto ipv4", "meta nfproto", []byte{unix.NFPROTO_IPV4}, "ipv4"},
		{"nfproto ipv6", "meta nfproto", []byte{unix.NFPROTO_IPV6}, "ipv6"},
		{"l4proto udp", "meta l4proto", []byte{unix.IPPROTO_UDP}, "udp"},
		{"l4proto tcp", "meta l4proto", []byte{unix.IPPROTO_TCP}, "tcp"},
		{"l4proto icmp", "meta l4proto", []byte{unix.IPPROTO_ICMP}, "icmp"},

		{"a protocol this file never emits", "meta l4proto", []byte{unix.IPPROTO_SCTP}, "0x84"},
		{"a family this file never emits", "meta nfproto", []byte{unix.NFPROTO_ARP}, "0x03"},
		{"an address of the wrong width", "ip daddr", []byte{10, 0}, "0x0a00"},
		{"a field with no case at all", "payload base1 offset 9 len 1", []byte{6}, "0x06"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmpValue(tc.field, tc.data); got != tc.want {
				t.Errorf("cmpValue(%q, %x) = %q, want %q", tc.field, tc.data, got, tc.want)
			}
		})
	}
}

// renderExprs over the expression shapes this file's generator emits, one rule
// at a time. The rules are written out as expressions rather than built by the
// generator, because what this pins is the reading half: these are the shapes
// that come back out of nf_tables, and they have to come back out as the same
// sentence that went in.
func TestRenderExprsRendersTheShapesThisFileEmits(t *testing.T) {
	port := func(n uint16) []byte { return []byte{byte(n >> 8), byte(n)} }
	for _, tc := range []struct {
		name  string
		exprs []expr.Any
		want  string
	}{
		{
			name: "a peer's address on the tunnel port",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 128, 0, 41}},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port(4433)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want: "meta nfproto ipv4 ip daddr 10.128.0.41 meta l4proto udp dport 4433 accept",
		},
		{
			name: "a peer answering from its own listener",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 128, 0, 41}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port(4433)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want: "meta nfproto ipv4 ip saddr 10.128.0.41 sport 4433 accept",
		},
		{
			name: "the reset that makes connect() fail now",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
			},
			want: "meta l4proto tcp reject with tcp reset",
		},
		{
			name:  "the refusal the output chain ends in",
			exprs: []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}},
			want:  "reject with icmpx code 3",
		},
		{
			name:  "a drop",
			exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
			want:  "drop",
		},
		{
			name:  "a counter, which nothing here installs and the kernel may still hold",
			exprs: []expr.Any{&expr.Counter{Packets: 7, Bytes: 420}},
			want:  "counter packets 7 bytes 420",
		},
		{
			name:  "an expression this file has no case for is named, not guessed at",
			exprs: []expr.Any{&expr.Limit{Rate: 1}},
			want:  "*expr.Limit",
		},
		{
			name:  "a rule with no expressions at all",
			exprs: nil,
			want:  "(no expressions)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderExprs(tc.exprs); got != tc.want {
				t.Errorf("renderExprs rendered\n\t%q\nwant\n\t%q", got, tc.want)
			}
		})
	}
}

// An interface test is `iifname`, not `iif`, and the two are different rules:
// iif compares an interface index resolved when the rule is loaded, iifname
// compares the name when a packet arrives. This file has always built the name
// form — ifaceRule passes expr.MetaKeyIIFNAME — so the kernel has always held
// the name form and only the rendering beside it said otherwise, which makes
// every recorded egress capture describe a rule the guest did not install
// (ticket 22, spike E3, finding 3). The assertion below is the corrected
// rendering.
func TestRenderExprsNamesAnInterfaceTheWayTheKernelMatchesIt(t *testing.T) {
	t.Skip("written before the fix: ticket 22's next commit teaches renderExprs and cmpValue iifname/oifname and removes this skip")

	name := make([]byte, unix.IFNAMSIZ)
	copy(name, "eth0")
	for _, tc := range []struct {
		key  expr.MetaKey
		want string
	}{
		{expr.MetaKeyIIFNAME, `iifname "eth0" accept`},
		{expr.MetaKeyOIFNAME, `oifname "eth0" accept`},
	} {
		got := renderExprs([]expr.Any{
			&expr.Meta{Key: tc.key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
			&expr.Verdict{Kind: expr.VerdictAccept},
		})
		if got != tc.want {
			t.Errorf("renderExprs rendered %q, want %q", got, tc.want)
		}
	}
}

// A prefix match is a mask-and-compare in the kernel: load the address, AND it
// with the mask, compare the result with the network address. Every rule this
// file's generator emitted compared a whole address, so renderExprs has never
// seen an *expr.Bitwise and prints its Go type — which loses the mask and makes
// the rule read as an exact match on 169.254.0.0, a different rule from the one
// the kernel is enforcing. The ceiling refuses the whole link-local block, so
// this is the shape ticket 22 has to be able to read back.
func TestRenderExprsRendersAPrefixMatchAsAPrefix(t *testing.T) {
	t.Skip("written before the fix: ticket 22's next commit teaches renderExprs *expr.Bitwise and removes this skip")

	got := renderExprs([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{169, 254, 0, 0}},
		&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
	})
	want := "meta nfproto ipv4 ip daddr 169.254.0.0/16 reject with icmpx code 3"
	if got != want {
		t.Errorf("renderExprs rendered\n\t%q\nwant\n\t%q", got, want)
	}
}

// readInstalledRuleSet against a real kernel, unprivileged.
//
// Installing rules needs CAP_NET_ADMIN, which is why the install test above
// asks for root and is skipped on a workstation. It does not need the
// workstation's own network: nf_tables is namespaced, and a new user namespace
// carries CAP_NET_ADMIN over the new network namespace inside it. So this test
// re-executes itself in one — the same route spike E3 took with `unshare -rn`,
// no sudo and no privileged helper — installs a table, and reads it back out of
// the kernel's own bytes.
//
// What it pins is the reading half: that a rule set installed through this
// file's Install comes back through readInstalledRuleSet as the same sentences,
// with the kernel's handles beside them.
func TestReadInstalledRuleSetReadsTheKernelsOwnBytes(t *testing.T) {
	if !inOwnNetworkNamespace(t) {
		return
	}
	port := []byte{0x11, 0x51}
	rs := &egressRuleSet{chains: []egressChain{
		{
			name: egressChainInput, hook: nftables.ChainHookInput, policy: nftables.ChainPolicyDrop,
			rules: []egressRule{{
				text: "meta nfproto ipv4 meta l4proto udp udp dport 4433 accept",
				exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			}},
		},
		{
			name: egressChainOutput, hook: nftables.ChainHookOutput, policy: nftables.ChainPolicyDrop,
			rules: []egressRule{{
				text: "meta l4proto tcp reject with tcp reset",
				exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
					&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
				},
			}, {
				text: "reject with icmpx admin-prohibited",
				exprs: []expr.Any{
					&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
				},
			}},
		},
		{name: egressChainForward, hook: nftables.ChainHookForward, policy: nftables.ChainPolicyDrop},
	}}
	if err := rs.Install(); err != nil {
		t.Fatalf("Install inside the namespace: %v", err)
	}
	var back bytes.Buffer
	if err := readInstalledRuleSet(&back); err != nil {
		t.Fatalf("readInstalledRuleSet: %v", err)
	}
	got := back.String()
	for _, want := range []string{
		"table inet attested_tunnel {",
		"chain input {",
		"type filter hook input priority 0; policy drop;",
		"meta nfproto ipv4 meta l4proto udp dport 4433 accept   # handle ",
		"chain output {",
		"type filter hook output priority 0; policy drop;",
		"meta l4proto tcp reject with tcp reset   # handle ",
		"reject with icmpx code 3   # handle ",
		"chain forward {",
		"type filter hook forward priority 0; policy drop;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the kernel's own copy of the rule set does not contain %q; it is:\n%s", want, got)
		}
	}
	// Every rule carries the kernel's own handle for it, which is what makes
	// the capture a reading of what the kernel holds rather than a second
	// printing of what was sent. The numbers themselves are the kernel's to
	// choose and are not pinned.
	if n := len(regexp.MustCompile(`# handle [0-9]+`).FindAllString(got, -1)); n != 3 {
		t.Errorf("the capture names %d handles; the three rules installed have three:\n%s", n, got)
	}
	// The chains are printed in name order, which is what makes two captures
	// of the same rule set comparable line by line.
	if i, j := strings.Index(got, "chain forward"), strings.Index(got, "chain input"); i > j {
		t.Errorf("the chains came back out of name order:\n%s", got)
	}
}

// inOwnNetworkNamespace reports whether this process is already inside the
// namespace the caller wants; when it is not, it re-executes this test binary
// in a new user and network namespace to run exactly the calling test there,
// fails the parent if the child did, and returns false.
//
// A new user namespace maps the invoking user to root inside it and carries
// CAP_NET_ADMIN over the network namespace created with it, so nf_tables,
// netlink and the ruleset inside are all reachable without sudo — and the
// workstation's own network and own ruleset are untouched and out of reach. The
// same route the E3 spike took, with the namespace entered by this binary
// rather than by `unshare`.
func inOwnNetworkNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv(egressNamespaceEnv) != "" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), egressNamespaceEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return false
	}
	// A kernel that will not give an unprivileged user a namespace, or one
	// without nf_tables, is a workstation this test cannot run on — and it
	// says which, because a guard that is quietly never run is worse than no
	// guard.
	if !bytes.Contains(out, []byte("--- FAIL")) {
		t.Skipf("could not run this test in a user and network namespace of its own (%v); the kernel it needs is one with unprivileged user namespaces and nf_tables:\n%s", err, out)
	}
	t.Fatalf("this test failed inside its own network namespace:\n%s", out)
	return false
}

// egressNamespaceEnv marks the re-executed child, so that it runs the body
// rather than re-executing itself again.
const egressNamespaceEnv = "TUNNELD_TEST_NETNS"
