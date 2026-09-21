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

package boot

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
)

const testTableJSON = `{"default_exit":"b","names":{"api.anthropic.com":{"port":443},"web.peer-a":{"port":8080}}}`

func testTable(t *testing.T) *netstack.TunnelTable {
	t.Helper()
	table, err := netstack.ParseTunnelTable([]byte(testTableJSON))
	if err != nil {
		t.Fatalf("ParseTunnelTable: %v", err)
	}
	return table
}

func atomsOrFail(t *testing.T, policy string) *policySets {
	t.Helper()
	sets, err := policyAtoms([]byte(policy))
	if err != nil {
		t.Fatalf("policyAtoms(%s): %v", policy, err)
	}
	return sets
}

func same(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ===== the parser =====

func TestPolicyAtomsReadsTheThreeComponents(t *testing.T) {
	sets := atomsOrFail(t, `{"format":"policy","version":1,
		"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"web.peer-a","ports":[8080,443]}],
		"f":[{"path":"/tmp","modes":["r","w"]}],
		"x":[{"path":"/bin/busybox"},{"sha256":"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}]}`)
	if want := []string{"net:api.anthropic.com:443", "net:web.peer-a:443", "net:web.peer-a:8080"}; !same(sets.n, want) {
		t.Errorf("n = %v, wanted %v", sets.n, want)
	}
	if want := []string{"read:/tmp", "write:/tmp"}; !same(sets.f, want) {
		t.Errorf("f = %v, wanted %v", sets.f, want)
	}
	if want := []string{"run:/bin/busybox", "run:sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}; !same(sets.x, want) {
		t.Errorf("x = %v, wanted %v", sets.x, want)
	}
}

func TestPolicyAtomsSortsAndDeduplicates(t *testing.T) {
	sets := atomsOrFail(t, `{"format":"policy","version":1,
		"n":[{"host":"web.peer-a","ports":[443]},{"host":"api.anthropic.com","ports":[443]},{"host":"WEB.peer-a.","ports":[443]}]}`)
	if want := []string{"net:api.anthropic.com:443", "net:web.peer-a:443"}; !same(sets.n, want) {
		t.Errorf("n = %v, wanted %v", sets.n, want)
	}
}

func TestPolicyAtomsRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   string
	}{
		{"empty", ``, "it is empty"},
		{"not json", `not json`, "not a JSON object"},
		{"another format", `{"format":"refvals","version":1}`, `format "refvals" is not "policy"`},
		{"another version", `{"format":"policy","version":2}`, "version 2 is not 1"},
		{"a hostless n entry", `{"format":"policy","version":1,"n":[{"ports":[443]}]}`, "names no host"},
		{"a cidr", `{"format":"policy","version":1,"n":[{"cidr":"10.0.0.0/8"}]}`, "is a CIDR"},
		{"a port that is not one", `{"format":"policy","version":1,"n":[{"host":"a.example","ports":[0]}]}`, "which is not a port"},
		{"a port above the range", `{"format":"policy","version":1,"n":[{"host":"a.example","ports":[65536]}]}`, "which is not a port"},
		{"a host with a slash", `{"format":"policy","version":1,"n":[{"host":"nonsense///"}]}`, "a character a host name may not have"},
		{"an f entry with no mode", `{"format":"policy","version":1,"f":[{"path":"/tmp"}]}`, "names no mode"},
		{"an f entry with an unknown mode", `{"format":"policy","version":1,"f":[{"path":"/tmp","modes":["x"]}]}`, "does not know"},
		{"an f entry with a comma", `{"format":"policy","version":1,"f":[{"path":"/a,/b","modes":["r"]}]}`, "comma or a NUL"},
		{"an x entry with neither", `{"format":"policy","version":1,"x":[{}]}`, "neither a path nor a digest"},
		{"a short digest", `{"format":"policy","version":1,"x":[{"sha256":"abcd"}]}`, "64 hex characters"},
		{"a digest that is not hex", `{"format":"policy","version":1,"x":[{"sha256":"zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}]}`, "not hexadecimal"},
		{"an x path that looks like a digest atom", `{"format":"policy","version":1,"x":[{"path":"sha256:aabb"}]}`, "begins with"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policyAtoms([]byte(tc.policy))
			if err == nil {
				t.Fatalf("policyAtoms accepted %s", tc.policy)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("policyAtoms said %q, wanted something with %q in it", err, tc.want)
			}
			if !strings.HasPrefix(err.Error(), "policy refused: ") {
				t.Errorf("the refusal %q does not read as one", err)
			}
		})
	}
}

// TestPolicyBareHostMeansEveryPort: Deno's grammar has one, and this sandbox
// reads it as the table's one port, because that is all it could ever grant.
func TestPolicyBareHostIsCanonicalisedToTheTablesPort(t *testing.T) {
	table := testTable(t)
	sets := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a"}]}`)
	if want := []string{"net:web.peer-a"}; !same(sets.n, want) {
		t.Fatalf("n parsed as %v, wanted %v", sets.n, want)
	}
	got := canonicalNetAtoms(sets.n, table)
	if want := []string{"net:web.peer-a:8080"}; !same(got, want) {
		t.Errorf("canonicalNetAtoms = %v, wanted %v", got, want)
	}
}

func TestPolicyBareHostTheTableDoesNotCarryIsLeftAlone(t *testing.T) {
	table := testTable(t)
	got := canonicalNetAtoms([]string{"net:elsewhere.example"}, table)
	if want := []string{"net:elsewhere.example"}; !same(got, want) {
		t.Errorf("canonicalNetAtoms = %v, wanted %v", got, want)
	}
}

func TestBootTableAtoms(t *testing.T) {
	got := bootTableAtoms(testTable(t))
	if want := []string{"net:api.anthropic.com:443", "net:web.peer-a:8080"}; !same(got, want) {
		t.Errorf("bootTableAtoms = %v, wanted %v", got, want)
	}
}

// ===== the subset check =====

func TestPolicySubsetFirstPushIsAgainstTheTable(t *testing.T) {
	table := testTable(t)
	base := &policySets{n: bootTableAtoms(table)}
	for _, tc := range []struct {
		name   string
		policy string
		want   string // "" for accepted
	}{
		{"both names", `{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"web.peer-a","ports":[8080]}]}`, ""},
		{"one name", `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}]}`, ""},
		{"no name at all", `{"format":"policy","version":1}`, ""},
		{"a bare host the table carries", `{"format":"policy","version":1,"n":[{"host":"web.peer-a"}]}`, ""},
		{"a name the table does not carry", `{"format":"policy","version":1,"n":[{"host":"evil.example","ports":[443]}]}`, "it widens n by [net:evil.example:443]"},
		{"a port the table does not permit", `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[80]}]}`, "it widens n by [net:web.peer-a:80]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets := atomsOrFail(t, tc.policy)
			sets.n = canonicalNetAtoms(sets.n, table)
			// f and x are fixed by the first push, so the base takes them.
			first := &policySets{n: base.n, f: sets.f, x: sets.x}
			err := policySubset(sets, first)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("policySubset refused a narrowing: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("policySubset accepted a widening")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("policySubset said %q, wanted something with %q in it", err, tc.want)
			}
		})
	}
}

func TestPolicySubsetSecondPushIsAgainstTheFirst(t *testing.T) {
	table := testTable(t)
	first := atomsOrFail(t, `{"format":"policy","version":1,
		"n":[{"host":"web.peer-a","ports":[8080]}],
		"f":[{"path":"/tmp","modes":["r","w"]}],
		"x":[{"path":"/bin/busybox"},{"path":"/bin/sh"}]}`)
	first.n = canonicalNetAtoms(first.n, table)

	for _, tc := range []struct {
		name   string
		policy string
		want   string
	}{
		{"the same policy again", `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}],"f":[{"path":"/tmp","modes":["r","w"]}],"x":[{"path":"/bin/busybox"},{"path":"/bin/sh"}]}`, ""},
		{"strictly narrower", `{"format":"policy","version":1,"f":[{"path":"/tmp","modes":["r"]}],"x":[{"path":"/bin/sh"}]}`, ""},
		{"a name the first push dropped", `{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[{"path":"/tmp","modes":["r","w"]}],"x":[{"path":"/bin/sh"}]}`, "it widens n by [net:api.anthropic.com:443]"},
		{"a mode the first push did not grant", `{"format":"policy","version":1,"f":[{"path":"/etc","modes":["r"]}],"x":[{"path":"/bin/sh"}]}`, "it widens f by [read:/etc]"},
		{"a binary the first push did not grant", `{"format":"policy","version":1,"f":[{"path":"/tmp","modes":["r"]}],"x":[{"path":"/usr/bin/node"}]}`, "it widens x by [run:/usr/bin/node]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets := atomsOrFail(t, tc.policy)
			sets.n = canonicalNetAtoms(sets.n, table)
			err := policySubset(sets, first)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("policySubset refused a narrowing: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("policySubset accepted a widening")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("policySubset said %q, wanted something with %q in it", err, tc.want)
			}
		})
	}
}

// TestPolicySubsetNamesTheFirstComponentThatWidened: n is checked first, so a
// policy that widens more than one is refused by the name of the first. The
// point of the message is that a reader can act on it, not that it is complete.
func TestPolicySubsetNamesTheComponentThatWidened(t *testing.T) {
	base := &policySets{n: []string{"net:a.example:443"}, f: nil, x: nil}
	sets := &policySets{n: []string{"net:b.example:443"}, f: []string{"read:/etc"}, x: []string{"run:/bin/sh"}}
	err := policySubset(sets, base)
	if err == nil || !strings.Contains(err.Error(), "it widens n by") {
		t.Fatalf("policySubset said %v, wanted the n component named", err)
	}
	sets.n = []string{"net:a.example:443"}
	err = policySubset(sets, base)
	if err == nil || !strings.Contains(err.Error(), "it widens f by") {
		t.Fatalf("policySubset said %v, wanted the f component named", err)
	}
	sets.f = nil
	err = policySubset(sets, base)
	if err == nil || !strings.Contains(err.Error(), "it widens x by") {
		t.Fatalf("policySubset said %v, wanted the x component named", err)
	}
}

// ===== the x atoms as the sink sees them =====

func TestExecAllowSplitsPathsFromDigests(t *testing.T) {
	paths, digests := execAllow([]string{
		"run:/bin/busybox",
		"run:sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		"run:/bin/sh",
	})
	if want := []string{"/bin/busybox", "/bin/sh"}; !same(paths, want) {
		t.Errorf("paths = %v, wanted %v", paths, want)
	}
	if want := []string{"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}; !same(digests, want) {
		t.Errorf("digests = %v, wanted %v", digests, want)
	}
}

func TestNetAtomHostPort(t *testing.T) {
	for _, tc := range []struct {
		atom string
		host string
		port int
		ok   bool
	}{
		{"net:a.example:443", "a.example", 443, true},
		{"net:a.example", "", 0, false},
		{"read:/tmp", "", 0, false},
		{"net:[::1]:443", "[::1]", 443, true},
	} {
		host, port, ok := netAtomHostPort(tc.atom)
		if ok != tc.ok || host != tc.host || port != tc.port {
			t.Errorf("netAtomHostPort(%q) = %q, %d, %v; wanted %q, %d, %v", tc.atom, host, port, ok, tc.host, tc.port, tc.ok)
		}
	}
}

// ===== F, and what it does not cover =====

// TestFIsMountsOnly is the whole of F's enforcement in this sandbox, so it is
// worth a test that says so: a bundle mount with ["ro","noexec"] is the
// read-only, non-executable mount the record claims, and there is no way to ask
// for a locked one from config.json — `locked` is not an option ParseMountOptions
// knows, and vfs.MountOptions.Locked is set in exactly one place in this tree,
// for the namespace-root tmpfs.
func TestFIsMountsOnly(t *testing.T) {
	opts := ParseMountOptions([]string{"ro", "noexec"})
	if !opts.ReadOnly {
		t.Errorf(`["ro","noexec"] did not give a read-only mount`)
	}
	if !opts.Flags.NoExec {
		t.Errorf(`["ro","noexec"] did not give a noexec mount`)
	}
	if opts.Locked {
		t.Errorf(`["ro","noexec"] gave a locked mount, which this tree cannot ask for from a bundle`)
	}
	// And the option that would ask for one is not one: it is ignored with a
	// warning, exactly like any other unknown option.
	if locked := ParseMountOptions([]string{"locked"}); locked.Locked {
		t.Errorf(`the "locked" mount option is reachable from config.json after all`)
	}
}

// ===== X semantics: absent vs empty and widening =====

func TestPolicyExecAtomsAbsentVsEmpty(t *testing.T) {
	// Absent x key -> sets.x is nil (unconstrained exec).
	absent := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}]}`)
	if absent.x != nil {
		t.Errorf("absent x resulted in sets.x = %v; want nil", absent.x)
	}

	// Empty x list -> sets.x is non-nil empty slice (grant of nothing).
	empty := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}],"x":[]}`)
	if empty.x == nil {
		t.Fatal("empty x resulted in sets.x = nil; want non-nil empty slice")
	}
	if len(empty.x) != 0 {
		t.Errorf("empty x resulted in sets.x with length %d; want 0", len(empty.x))
	}
}

func TestPolicySubsetWideningAnEmptyX(t *testing.T) {
	base := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}],"x":[]}`)

	// Widening with a binary grant must be refused.
	widenedWithBin := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}],"x":[{"path":"/bin/sh"}]}`)
	err := policySubset(widenedWithBin, base)
	if err == nil || !strings.Contains(err.Error(), "it widens x by [run:/bin/sh]") {
		t.Fatalf("policySubset allowed widening empty x with binary: %v", err)
	}

	// Widening by omitting x (unconstrained) must be refused.
	widenedAbsent := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}]}`)
	err = policySubset(widenedAbsent, base)
	if err == nil || !strings.Contains(err.Error(), "it widens x by unconstraining exec") {
		t.Fatalf("policySubset allowed widening empty x by omitting x: %v", err)
	}

	// Pushing the same empty x again is accepted.
	same := atomsOrFail(t, `{"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[8080]}],"x":[]}`)
	if err := policySubset(same, base); err != nil {
		t.Fatalf("policySubset refused identical empty x: %v", err)
	}
}
