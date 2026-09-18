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

package sandbox_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest/sandbox"
)

// The subset check: a delegation narrows, and this is the rule that says so.
//
// A node pushed P0 and pushing P1 onward may hand on no more than it was given.
// Until this ticket nothing in this tree checked it — the finding is recorded at
// attest/cmd/agent-probe/twohops_test.go:35 — and the shape of the check is
// ticket 23's: component-wise, over sorted deduplicated atoms, with the refusal
// naming which component widened.

// The documents these tests are written against. p0 is the grant; the rest
// narrow it, repeat it in another order, or widen it by exactly one thing.
const (
	p0 = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[80,443]}],` +
		`"f":[{"path":"/work","modes":["r","w"]}],` +
		`"x":[{"path":"/usr/bin/node"}]}`

	p1Narrow = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],` +
		`"f":[{"path":"/work","modes":["r"]}],` +
		`"x":[]}`

	p1Reordered = `{"format":"policy","version":1,` +
		`"n":[{"host":"www.rfc-editor.org","ports":[443,80]},{"host":"api.anthropic.com","ports":[443,443]}],` +
		`"f":[{"path":"/work","modes":["w","r"]}],` +
		`"x":[{"path":"/usr/bin/node"}]}`

	p2WiderN = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"evil.example","ports":[443]}],` +
		`"f":[{"path":"/work","modes":["r","w"]}],` +
		`"x":[{"path":"/usr/bin/node"}]}`

	p2WiderF = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],` +
		`"f":[{"path":"/work","modes":["r","w"]},{"path":"/etc/shadow","modes":["r"]}],` +
		`"x":[{"path":"/usr/bin/node"}]}`

	p2WiderX = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],` +
		`"f":[{"path":"/work","modes":["r"]}],` +
		`"x":[{"path":"/usr/bin/node"},{"path":"/bin/sh"}]}`
)

// TestAPolicyBecomesTheAtomsItGrants is the parse, including the three things a
// policy may not say and the two ways an exec identity may be named.
func TestAPolicyBecomesTheAtomsItGrants(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		what   string
		policy string
		want   []string
	}{
		{
			"a host with ports, a host without, two modes and a path",
			`{"format":"policy","version":1,"n":[{"host":"a","ports":[80,443]},{"host":"b"}],` +
				`"f":[{"path":"/w","modes":["r","w"]}],"x":[{"path":"/bin/sh"}]}`,
			[]string{"net:a:443", "net:a:80", "net:b", "read:/w", "run:/bin/sh", "write:/w"},
		},
		{
			"an exec identity by digest",
			`{"format":"policy","version":1,"x":[{"sha256":"` + digest + `"}]}`,
			[]string{"run:sha256:" + digest},
		},
		{
			"an exec identity by both, which is two grants and not one",
			`{"format":"policy","version":1,"x":[{"path":"/bin/sh","sha256":"` + digest + `"}]}`,
			[]string{"run:/bin/sh", "run:sha256:" + digest},
		},
		{
			"a policy that grants nothing",
			`{"format":"policy","version":1}`,
			nil,
		},
		{
			"the same grant written twice",
			`{"format":"policy","version":1,"n":[{"host":"a","ports":[80]},{"host":"a","ports":[80]}]}`,
			[]string{"net:a:80"},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			got, err := sandbox.Atoms([]byte(tc.policy))
			if err != nil {
				t.Fatalf("reading the atoms: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("the atoms are %v; want %v", got, tc.want)
			}
			if !slices.IsSorted(got) {
				t.Errorf("the atoms are not sorted: %v", got)
			}
		})
	}
}

// TestAPolicyThisSideCannotCompareIsRefused: every refusal here wraps
// ErrPolicyRefused, so a caller can tell "this is not a policy I can judge"
// from "there was nobody to judge it" without reading the sentence.
func TestAPolicyThisSideCannotCompareIsRefused(t *testing.T) {
	for _, tc := range []struct{ what, policy, says string }{
		{"a CIDR", `{"format":"policy","version":1,"n":[{"cidr":"10.0.0.0/8"}]}`, "CIDR"},
		{"an n entry with no host", `{"format":"policy","version":1,"n":[{"ports":[443]}]}`, "names no host"},
		{"a port that is not one", `{"format":"policy","version":1,"n":[{"host":"a","ports":[0]}]}`, "not a port"},
		{"a port past the end", `{"format":"policy","version":1,"n":[{"host":"a","ports":[65536]}]}`, "not a port"},
		{"an f entry with no path", `{"format":"policy","version":1,"f":[{"modes":["r"]}]}`, "names no path"},
		{"an f entry with no mode", `{"format":"policy","version":1,"f":[{"path":"/w"}]}`, "names no mode"},
		{"a mode this side does not know", `{"format":"policy","version":1,"f":[{"path":"/w","modes":["x"]}]}`, `mode "x"`},
		{"an x entry naming nothing", `{"format":"policy","version":1,"x":[{}]}`, "neither a path nor a digest"},
		{"a digest that is not one", `{"format":"policy","version":1,"x":[{"sha256":"ABCD"}]}`, "64 lowercase hexadecimal"},
		{"a body that is not a policy", `{"format":"policy","version":1,"n":"everything"}`, "components can be read"},
		{"the wrong version", `{"format":"policy","version":2}`, "version 2 is not 1"},
		{"not a policy at all", `{"format":"something-else","version":1}`, "is not \"policy\""},
	} {
		t.Run(tc.what, func(t *testing.T) {
			_, err := sandbox.Atoms([]byte(tc.policy))
			if !errors.Is(err, sandbox.ErrPolicyRefused) {
				t.Fatalf("it returned %v; want a refusal", err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal is %q; want it to say %q", err, tc.says)
			}
		})
	}
}

// TestANarrowingPolicyIsAccepted covers the two things that are not widenings:
// dropping grants, and writing the same grants in another order.
func TestANarrowingPolicyIsAccepted(t *testing.T) {
	for _, tc := range []struct{ what, next string }{
		{"the same policy", p0},
		{"a narrower one", p1Narrow},
		{"the same atoms in another order, with a repeat", p1Reordered},
		{"nothing at all", `{"format":"policy","version":1}`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			if err := sandbox.CheckNarrows([]byte(p0), []byte(tc.next)); err != nil {
				t.Errorf("it was refused: %v", err)
			}
		})
	}
}

// TestAWideningPolicyIsRefusedAndTheRefusalNamesTheComponent is the rule
// itself. Which component widened is in the sentence because "it widens" with
// no subject is a refusal an operator cannot act on.
func TestAWideningPolicyIsRefusedAndTheRefusalNamesTheComponent(t *testing.T) {
	for _, tc := range []struct{ what, next, says string }{
		{"a host P0 does not grant", p2WiderN, "it widens n by [net:evil.example:443]"},
		{"a path P0 does not grant", p2WiderF, "it widens f by [read:/etc/shadow]"},
		{"an exec P0 does not grant", p2WiderX, "it widens x by [run:/bin/sh]"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			err := sandbox.CheckNarrows([]byte(p0), []byte(tc.next))
			if !errors.Is(err, sandbox.ErrPolicyRefused) {
				t.Fatalf("it returned %v; want a refusal", err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal is %q; want it to say %q", err, tc.says)
			}
		})
	}
}

// TestAPolicyThatWidensTwoComponentsNamesBoth: a refusal that named only the
// first would send an operator round the loop once per component.
func TestAPolicyThatWidensTwoComponentsNamesBoth(t *testing.T) {
	next := `{"format":"policy","version":1,"n":[{"host":"evil.example"}],"x":[{"path":"/bin/sh"}]}`
	err := sandbox.CheckNarrows([]byte(p0), []byte(next))
	if err == nil {
		t.Fatal("it was accepted")
	}
	if want := "it widens n by [net:evil.example], x by [run:/bin/sh]"; !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal is %q; want it to say %q", err, want)
	}
}

// TestWideningIsOverTheAtomsAndNotOverADocument is what lets a sandbox whose P0
// is not a policy document at all — the sentry's boot table, which is a list of
// names and ports — make the same check.
func TestWideningIsOverTheAtomsAndNotOverADocument(t *testing.T) {
	table := []string{"net:api.anthropic.com:443", "net:www.rfc-editor.org:443"}
	pushed, err := sandbox.Atoms([]byte(p1Narrow))
	if err != nil {
		t.Fatalf("reading the atoms: %v", err)
	}
	if extra := sandbox.Widening(table, pushed); len(extra) != 1 || len(extra["f"]) != 1 {
		t.Errorf("a push naming a file the table has no atom for widened %v; want one f atom", extra)
	}
	if extra := sandbox.Widening(table, []string{"net:api.anthropic.com:443"}); extra != nil {
		t.Errorf("a push inside the table widened %v; want nothing", extra)
	}
}

// TestAnEmptyGrantIsAGrantAndNotAnAbsence is the trap this checker refuses to
// fall into. A caller that has fixed no set does not call Widening; one that has
// fixed the empty set gets the empty set, and a push of anything widens it.
func TestAnEmptyGrantIsAGrantAndNotAnAbsence(t *testing.T) {
	extra := sandbox.Widening(nil, []string{"net:evil.example:443"})
	if len(extra["n"]) != 1 {
		t.Errorf("widening from nothing reported %v; want the one atom", extra)
	}
	if err := sandbox.CheckNarrows([]byte(`{"format":"policy","version":1}`), []byte(p0)); err == nil {
		t.Error("a push was accepted against a policy that grants nothing")
	}
}

// TestTheAtomGrammarIsTheOneTheDenoSandboxAlreadyJudgedBy: the check moved into
// the contract, so the two must agree on what a grant is. They are checked
// against each other by spelling, since the Deno sandbox's atomiser is its own
// (it has an `e` letter, refuses a digest and refuses a host its flag parser
// would refuse) and only the shared spellings can be compared.
func TestTheAtomGrammarIsTheOneTheDenoSandboxAlreadyJudgedBy(t *testing.T) {
	got, err := sandbox.Atoms([]byte(p0))
	if err != nil {
		t.Fatalf("reading the atoms: %v", err)
	}
	want := []string{
		"net:api.anthropic.com:443",
		"net:www.rfc-editor.org:443",
		"net:www.rfc-editor.org:80",
		"read:/work",
		"run:/usr/bin/node",
		"write:/work",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the atoms of P0 are\n  %v\nwant\n  %v", got, want)
	}
	for _, atom := range got {
		kind, value, found := strings.Cut(atom, ":")
		if !found || value == "" {
			t.Errorf("the atom %q is not kind:value", atom)
		}
		if !slices.Contains([]string{"net", "read", "write", "run"}, kind) {
			t.Errorf("the atom %q names a kind the grammar does not: %q", atom, kind)
		}
	}
	if s := fmt.Sprint(got); strings.Contains(s, "env:") {
		t.Errorf("the contract's atoms carry an e letter the policy format has not: %s", s)
	}
}
