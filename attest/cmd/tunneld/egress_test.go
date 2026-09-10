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
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
)

// closedPolicy is what every policy this design will load looks like: an egress
// section at the version the loader reads, and unattested egress refused.
func closedPolicy() attest.Policy {
	return attest.Policy{Version: attest.PolicyVersion, Egress: attest.Egress{Version: 1, Unattested: false}}
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
