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
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/attest/ceiling"
)

// The ceiling is the artefact a reader judges the guest by, so the two forms of
// it — the text in the record and the rules the kernel is handed — are pinned
// against each other here. Four tests that stood in this place until ticket 22
// are gone with the code they drove: they were about the rendering a signed
// policy and a peer table implied, and no policy and no peer table implies
// anything now.

// What `tunneld -egress print` writes is exactly the ceiling's text, with
// nothing of its own around it. That is what lets the file in the record be
// regenerated from the binary that enforces it rather than maintained beside
// it, and what lets a reader compare a guest's console against the record byte
// for byte.
func TestEgressPrintWritesTheCeilingAndNothingElse(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-egress", "print"}, &out); code != exitOK {
		t.Fatalf("tunneld -egress print exited %d:\n%s", code, out.String())
	}
	if out.String() != ceiling.Text() {
		t.Errorf("`-egress print` wrote %d bytes and the ceiling is %d; the two must be the same text:\n%s",
			out.Len(), len(ceiling.Text()), out.String())
	}
	// And it read nothing to do it: no config device, no author key, no policy.
	// This is the property that lets the guest's init install the ceiling
	// before it has found a disk, so it is checked by naming a config
	// directory that does not exist.
	var again bytes.Buffer
	if code := run([]string{"-egress", "print", "-config", filepath.Join(t.TempDir(), "no-such-device")}, &again); code != exitOK {
		t.Errorf("`-egress print` against an absent config device exited %d:\n%s", code, again.String())
	}
	if again.String() != ceiling.Text() {
		t.Error("`-egress print` wrote something different when the config device was missing; it must read nothing at all")
	}
}

// The ceiling is carried twice — as the text [ceiling.Text] returns and as the
// expressions [buildCeiling] hands the kernel — and the two must not drift. The
// text is what a verifier reads and what the digest names; the expressions are
// what actually refuses a packet. A difference between them would be a record
// that describes a rule set the guest does not enforce, which is exactly the
// defect ticket 22 found in the `iif` rendering it inherited.
func TestTheTextAndTheRulesAreTheSameCeiling(t *testing.T) {
	var rendered bytes.Buffer
	buildCeiling().Render(&rendered)
	got, want := ruleLines(rendered.String()), ruleLines(ceiling.Text())
	if len(got) != len(want) {
		t.Fatalf("the rules render as %d lines and the text has %d:\nrules:\n%s\ntext:\n%s",
			len(got), len(want), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n\trules: %q\n\ttext:  %q", i+1, got[i], want[i])
		}
	}
}

// ruleLines is a rule set with the reasoning taken out: no commentary, no blank
// lines, and no trailing justification after a rule. What is left is what the
// kernel is being told, which is the only part of the two forms that has to be
// identical.
func ruleLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimRight(line[:i], " \t")
		}
		if trimmed := strings.TrimSpace(line); trimmed == "" || trimmed == "flush ruleset" {
			continue
		}
		out = append(out, line)
	}
	return out
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

// The netlink half: the ceiling goes into a kernel and comes back out of it.
//
// It is the whole claim of ticket 22 in one test — that what the image carries
// is what the kernel ends up holding — and it runs unprivileged, in a user and
// network namespace of its own, so it runs on a workstation rather than only in
// a guest. The read-back is decoded from nf_tables' own bytes, so a rule the
// kernel silently declined or altered shows up here as an absence or a
// difference.
func TestEgressRuleSetInstalls(t *testing.T) {
	if !inOwnNetworkNamespace(t) {
		return
	}
	if err := buildCeiling().Install(); err != nil {
		t.Fatalf("installing the ceiling: %v", err)
	}
	var back bytes.Buffer
	if err := readInstalledRuleSet(&back); err != nil {
		t.Fatalf("readInstalledRuleSet: %v", err)
	}
	got := back.String()
	for _, want := range []string{
		"table inet attested_tunnel {",
		"policy drop;",
		// The interface rules, named the way the kernel matches them.
		`iifname "lo" accept`,
		`oifname "lo" accept`,
		`iifname "eth0"`,
		`oifname "eth0"`,
		// The tunnel port, in both directions.
		"udp dport 4433",
		"dport 4433",
		"sport 4433",
		// And the carve-out, as a prefix rather than as an address.
		"ip daddr 169.254.0.0/16 reject with icmpx code 3",
		"meta l4proto tcp reject with tcp reset",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the kernel's own copy of the ceiling does not contain %q; it is:\n%s", want, got)
		}
	}
	// Nothing that could only have come off the config device.
	for _, forbidden := range []string{"10.128.0.", "ip saddr"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the kernel's copy of the ceiling names %q, which nothing inside the launch measurement knows:\n%s", forbidden, got)
		}
	}
	// The ceiling as the kernel holds it is the ceiling the digest names: the
	// rules come back in the order they went in, chain by chain.
	if i, j := strings.Index(got, "reject with tcp reset"), strings.Index(got, "169.254.0.0/16"); i > j {
		t.Errorf("the reset comes after the link-local refusal; a TCP attempt at the metadata server would then be UNROUTED rather than REFUSED:\n%s", got)
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
		mask  []byte
		want  string
	}{
		{"inbound interface", "iifname", iface, nil, `"eth0"`},
		{"outbound interface", "oifname", iface, nil, `"eth0"`},
		{"source address", "ip saddr", []byte{10, 128, 0, 41}, nil, "10.128.0.41"},
		{"destination address", "ip daddr", []byte{169, 254, 169, 254}, nil, "169.254.169.254"},
		{"a destination prefix", "ip daddr", []byte{169, 254, 0, 0}, []byte{255, 255, 0, 0}, "169.254.0.0/16"},
		{"a source prefix", "ip saddr", []byte{10, 0, 0, 0}, []byte{255, 0, 0, 0}, "10.0.0.0/8"},
		{"source port", "sport", []byte{0x11, 0x51}, nil, "4433"},
		{"destination port", "dport", []byte{0x00, 0x35}, nil, "53"},
		{"nfproto ipv4", "meta nfproto", []byte{unix.NFPROTO_IPV4}, nil, "ipv4"},
		{"nfproto ipv6", "meta nfproto", []byte{unix.NFPROTO_IPV6}, nil, "ipv6"},
		{"l4proto udp", "meta l4proto", []byte{unix.IPPROTO_UDP}, nil, "udp"},
		{"l4proto tcp", "meta l4proto", []byte{unix.IPPROTO_TCP}, nil, "tcp"},
		{"l4proto icmp", "meta l4proto", []byte{unix.IPPROTO_ICMP}, nil, "icmp"},

		{"a protocol this file never emits", "meta l4proto", []byte{unix.IPPROTO_SCTP}, nil, "0x84"},
		{"a family this file never emits", "meta nfproto", []byte{unix.NFPROTO_ARP}, nil, "0x03"},
		{"an address of the wrong width", "ip daddr", []byte{10, 0}, nil, "0x0a00"},
		{"a field with no case at all", "payload base1 offset 9 len 1", []byte{6}, nil, "0x06"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmpValue(tc.field, tc.data, tc.mask); got != tc.want {
				t.Errorf("cmpValue(%q, %x, mask %x) = %q, want %q", tc.field, tc.data, tc.mask, got, tc.want)
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
