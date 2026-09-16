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

package deno

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gvisor.dev/gvisor/attest/sandbox"
)

// A document is the whole of what this sandbox reads out of a pushed policy:
// ticket 22's `n`, `f` and `x`, and the `e` spike E4 had to invent for the key
// the agent could not otherwise read. All four are unknown fields of a version
// 1 envelope, which is what the contract says a policy is.
//
// `f`'s modes are a list of strings here and were one string in E4's
// throwaway. A set of modes is a set, and a document that says ["r","w"] says
// what it means in the shape it means it.
type document struct {
	N []netEntry  `json:"n"`
	F []fileEntry `json:"f"`
	X []execEntry `json:"x"`
	E []envEntry  `json:"e"`
}

type netEntry struct {
	Host  string `json:"host"`
	CIDR  string `json:"cidr"`
	Ports []int  `json:"ports"`
}

type fileEntry struct {
	Path  string   `json:"path"`
	Modes []string `json:"modes"`
}

type execEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type envEntry struct {
	Variable string `json:"variable"`
}

// refuse is every refusal this package makes: [sandbox.ErrPolicyRefused] and a
// sentence, so that a caller can tell "the sandbox would not take this" from
// "the sandbox was not there" without reading the sentence.
func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", sandbox.ErrPolicyRefused, fmt.Sprintf(format, a...))
}

// atomsOf is the whole of the parse: a policy in, the capability set it grants
// out, sorted and deduplicated, or the reason it is not a policy this sandbox
// can enforce.
//
// The envelope is read here although tunneld has already read it
// (tunneld.PolicyChecked). The reason is [sandbox.Null]'s: reaching this with
// something else means the contract was driven directly, and refusing anyway
// keeps "this sandbox enforces a version 1 policy" a statement about version 1
// rather than about anything at all.
func atomsOf(policy []byte) ([]string, error) {
	if _, err := sandbox.ReadEnvelope(policy); err != nil {
		return nil, err
	}
	var d document
	if err := json.Unmarshal(policy, &d); err != nil {
		return nil, refuse("it is not a policy this sandbox reads: %v", err)
	}
	var atoms []string
	for _, half := range []func(*document) ([]string, error){netAtoms, fileAtoms, execAtoms, envAtoms} {
		got, err := half(&d)
		if err != nil {
			return nil, err
		}
		atoms = append(atoms, got...)
	}
	slices.Sort(atoms)
	return slices.Compact(atoms), nil
}

// netAtoms reads `n`. An entry names a host and the ports of it, and an empty
// port list is the bare host — which E3 measured grants every port, so it is a
// wider grant than it looks and still the one the document asked for.
func netAtoms(d *document) ([]string, error) {
	var atoms []string
	for _, n := range d.N {
		if n.Host == "" {
			return nil, refusedHostless(n)
		}
		if err := checkHost(n.Host); err != nil {
			return nil, err
		}
		if len(n.Ports) == 0 {
			atoms = append(atoms, "net:"+n.Host)
			continue
		}
		for _, port := range n.Ports {
			if port < 1 || port > 65535 {
				return nil, refuse("the n entry for %q names port %d, which is not a port Deno's flag parser takes", n.Host, port)
			}
			atoms = append(atoms, fmt.Sprintf("net:%s:%d", n.Host, port))
		}
	}
	return atoms, nil
}

// refusedHostless is the CIDR refusal, and the reason is spike E3's
// measurement rather than a preference. Deno parses a mask and matches
// addresses against it correctly; every check `fetch` raises is against the
// name in the URL, before resolution; a name is in no CIDR. The entry grants
// exactly the destinations an agent never names, and --allow-net=:443 — the
// other spelling of "everywhere on this port" — parses and grants nothing at
// all, which is worse, because only the exit code of the next fetch says so.
func refusedHostless(n netEntry) error {
	if n.CIDR != "" {
		return refuse("the n entry for %q is a CIDR and Deno checks the host a URL names before it is resolved, so a CIDR grants exactly the destinations an agent never names", n.CIDR)
	}
	return refuse("an n entry names no host")
}

// checkHost refuses, before the exec, what Deno's FQDN parser would refuse
// after it. `--allow-net=nonsense///` is `error: invalid host 'nonsense///':
// invalid char found in FQDN` and exit 1 within a few milliseconds of a
// process this sandbox has already acknowledged (E4 case iv), and an ack
// cannot be taken back. What the parser takes is letters, digits, `-` and `.`
// — which covers a dotted IPv4 literal — or an IP literal in brackets.
func checkHost(host string) error {
	if literal, bracketed := strings.CutPrefix(host, "["); bracketed {
		literal, closed := strings.CutSuffix(literal, "]")
		if !closed {
			return refuse("the host %q opens a bracket it does not close", host)
		}
		if _, err := netip.ParseAddr(literal); err != nil {
			return refuse("the host %q is bracketed and %q is not an IP literal", host, literal)
		}
		return nil
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return refuse("the host %q has a character Deno's FQDN parser refuses: %q", host, r)
		}
	}
	return nil
}

// fileAtoms reads `f`. Deno's grant is on the path as written, resolved
// against the working directory at process start, and it works for a file that
// does not exist yet (E3).
func fileAtoms(d *document) ([]string, error) {
	var atoms []string
	for _, f := range d.F {
		if err := checkPath("f", f.Path); err != nil {
			return nil, err
		}
		if len(f.Modes) == 0 {
			return nil, refuse("the f entry for %q names no mode", f.Path)
		}
		for _, mode := range f.Modes {
			switch mode {
			case "r":
				atoms = append(atoms, "read:"+f.Path)
			case "w":
				atoms = append(atoms, "write:"+f.Path)
			default:
				return nil, refuse("the f entry for %q names the mode %q, which this sandbox does not know", f.Path, mode)
			}
		}
	}
	return atoms, nil
}

// execAtoms reads `x`. The path maps and the digest does not: --allow-run
// matches the spelling of a path and neither the file it resolves to nor its
// contents, and a grant Deno cannot resolve — `--allow-run=sha256:…` — is an
// `Info` line and a process that runs anyway (E3). Granting the path alone
// would be granting whatever binary turns up at it.
func execAtoms(d *document) ([]string, error) {
	var atoms []string
	for _, x := range d.X {
		if x.SHA256 != "" {
			return nil, refuse("the x entry with digest %q cannot be enforced: Deno matches --allow-run by the spelling of a path, has nowhere to put a digest, and treats a grant it cannot resolve as a notice rather than a refusal", x.SHA256)
		}
		if err := checkPath("x", x.Path); err != nil {
			return nil, err
		}
		atoms = append(atoms, "run:"+x.Path)
	}
	return atoms, nil
}

// envAtoms reads `e`, the letter (N, F, X) has not got. The variable is both a
// Deno grant and the reason the child's environment holds it at all
// (childEnviron).
func envAtoms(d *document) ([]string, error) {
	var atoms []string
	for _, e := range d.E {
		if !isEnvName(e.Variable) {
			return nil, refuse("the e entry %q is not an environment variable name", e.Variable)
		}
		atoms = append(atoms, "env:"+e.Variable)
	}
	return atoms, nil
}

// checkPath refuses an empty path, and a path with a comma or a NUL in it.
// The comma is not pedantry: the flags are comma-separated lists, so a comma
// inside a value is a second grant that nobody wrote and that nothing later
// would attribute to this document.
func checkPath(field, path string) error {
	if path == "" {
		return refuse("a %s entry names no path", field)
	}
	if strings.ContainsAny(path, ",\x00") {
		return refuse("the %s entry %q has a comma or a NUL in it, and the flag it would go into is a comma-separated list", field, path)
	}
	return nil
}

// isEnvName is the shell's rule for a variable name: a letter or an
// underscore, then letters, digits and underscores. It excludes the comma for
// the reason checkPath does, and the `=` that would make one entry two.
func isEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// flagsOf renders the capability set as Deno's permission flags, one flag per
// kind with the values in the atoms' own order. It is the last step and not a
// step anything else compares: two flag strings differ when a host is added
// and also when the hosts are merely reordered, and only one of those is a
// widening, which is why the set is what [Sandbox.Apply] judges.
func flagsOf(atoms []string) []string {
	by := map[string][]string{}
	for _, a := range atoms {
		kind, value, _ := strings.Cut(a, ":")
		by[kind] = append(by[kind], value)
	}
	var flags []string
	for _, kind := range []string{"net", "read", "write", "run", "env"} {
		if values := by[kind]; len(values) > 0 {
			flags = append(flags, "--allow-"+kind+"="+strings.Join(values, ","))
		}
	}
	return flags
}
