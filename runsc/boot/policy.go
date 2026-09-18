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

// Policy.Narrow: a pushed policy honoured by a running sandbox.
//
// The supervisor beside the sandbox receives a policy over the contract and
// forwards it here on the control socket. This reads it, checks that it is no
// wider than the policy already in force, replaces the sentry's table in place
// and returns the digest of the bytes it accepted. The workload runs
// throughout: nothing is restarted, no process is signalled, and streams
// already open are not touched. That is the whole reason this sandbox is
// gVisor and not a runtime with a permission flag set (ticket 23 measured the
// alternative: a Deno process's grants are fixed at exec).
//
// Three components are read, and the grammar is Deno's exactly so that two
// sandboxes given the same document mean the same thing by it:
//
//	n  {host, ports}   -> net:<host>:<port>, or net:<host> for every port
//	f  {path, modes}   -> read:<path>, write:<path>
//	x  {path | sha256} -> run:<path>, run:sha256:<hex>
//
// sorted and deduplicated. `cidr` is refused as unenforceable by name, for the
// reason Deno's side records: every check this sandbox raises is against the
// name a workload asked the resolver for, and a name is in no CIDR.
//
// What each component costs the workload differs, and the record says so:
//
//   - `n` is enforced twice, at the resolver and at the connect hook, and is
//     the only component with an address behind it.
//   - `x` is enforced by the seccheck sink in pkg/sentry/policyx.
//   - `f` is enforced by NOTHING here. It is parsed, it is subset-checked and
//     it is carried in the digest, and the only file restriction this sandbox
//     has is what the bundle's mounts already gave it (ro, noexec). A runtime
//     baseline is the policy track's and is named as missing, not invented.

package boot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/policyx"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sync"
)

// policyFormat and policyVersion are the envelope this sandbox reads, matched
// exactly. They are attest/sandbox's PolicyFormat and PolicyVersion, written
// again because attest is a separate Go module with no BUILD files and nothing
// in runsc can import it (the same reason runsc/cmd/tunnel_client.go exists).
const (
	policyFormat  = "policy"
	policyVersion = 1
)

// PolicyNarrowArgs is the pushed policy, exactly as tunneld handed it over.
// The digest is over these bytes and not over anything derived from them.
type PolicyNarrowArgs struct {
	Policy []byte
}

// PolicyNarrowResult is the digest of the policy now in force.
type PolicyNarrowResult struct {
	Digest string
}

// Policy is the control object a pushed policy arrives on. It has exactly one
// exported method, because urpc registers every exported method of the object
// it is given and rejects one that is not an RPC.
type Policy struct {
	l *Loader
}

// Narrow applies a pushed policy to the running sandbox.
//
// It is refused unless the loader has started. This is the inverse of
// containerManager.SetNetworkArgs, which ignores a call that arrives after the
// sandbox started: a policy is about a running workload, and one that arrived
// during boot would be applied to a table the adapter has not been installed
// over yet. Refusing is not the same as ignoring — the push is answered with a
// refusal that reaches the peer that made it.
func (p *Policy) Narrow(args *PolicyNarrowArgs, result *PolicyNarrowResult) error {
	l := p.l
	l.mu.Lock()
	state := l.state
	l.mu.Unlock()
	if state != started {
		return policyRefuse("the sandbox is %s and a policy is honoured only by a started one", state)
	}
	if l.tunnel == nil {
		return policyRefuse("this sandbox has no tunnel adapter, so it has nothing to narrow")
	}
	digest, err := l.tunnel.narrow(args.Policy)
	if err != nil {
		return err
	}
	result.Digest = digest
	return nil
}

// policyState is the policy in force, and the lock a narrowing is serialised
// under. A narrowing is not concurrent with another narrowing; it is concurrent
// with every connect and every exec the workload makes.
type policyState struct {
	mu sync.Mutex

	// inForce is nil until the first push lands. Afterwards it is the atom
	// sets of the last accepted policy, which is P0 for the next one.
	// +checklocks:mu
	inForce *policySets

	// digest is the lowercase hex sha256 of the exact bytes of that policy,
	// which is what the sandbox says it is enforcing on the contract's
	// liveness stream.
	// +checklocks:mu
	digest string

	// xsink is the exec sink, installed at the first push that carries an x
	// and never removed: seccheck's only way of taking a sink back takes every
	// sink back, and the remote sink the refusal events go to is one of them.
	// +checklocks:mu
	xsink *policyx.Sink
}

// policySets is one policy as this sandbox holds it: three components, each a
// sorted deduplicated set of atoms.
type policySets struct {
	n []string
	f []string
	x []string
}

// policyRefuse is every refusal this file makes. The sentence reaches the peer
// that pushed the policy, through the helper and the contract, verbatim.
func policyRefuse(format string, a ...any) error {
	return fmt.Errorf("policy refused: %s", fmt.Sprintf(format, a...))
}

// narrow is the whole of an apply: read, check, swap, record.
func (tn *Tunnel) narrow(policy []byte) (string, error) {
	start := time.Now()
	pushed, err := policyAtoms(policy)
	if err != nil {
		return "", err
	}
	// A bare host means every port, and the table gives a name one port, so in
	// this sandbox the two spellings name the same destination. Canonicalising
	// to the table's port is what makes the subset check a plain set
	// comparison; a host the table does not carry is left as it is and is
	// refused by that comparison a moment later.
	pushed.n = canonicalNetAtoms(pushed.n, tn.bootTable)

	sum := sha256.Sum256(policy)
	digest := hex.EncodeToString(sum[:])

	tn.policy.mu.Lock()
	defer tn.policy.mu.Unlock()

	base := tn.policy.inForce
	if base == nil {
		// The first push. P0 for n is the boot table, so a push may not name a
		// destination the operator did not write down. P0 for f and x is the
		// push itself: nothing before it said anything about files or binaries,
		// so the first push is what fixes them and every later one may only
		// shrink them.
		base = &policySets{n: bootTableAtoms(tn.bootTable), f: pushed.f, x: pushed.x}
	}
	if err := policySubset(pushed, base); err != nil {
		return "", err
	}

	keep := make(map[string]bool, len(pushed.n))
	for _, atom := range pushed.n {
		host, _, ok := netAtomHostPort(atom)
		if !ok {
			return "", policyRefuse("the n atom %q names no port once the table has been consulted", atom)
		}
		keep[host] = true
	}
	before := len(tn.currentTable().Names)
	swapStart := time.Now()
	table, err := netstack.NarrowTunnel(keep)
	if err != nil {
		return "", policyRefuse("%v", err)
	}
	tn.tableMu.Lock()
	tn.table = table
	tn.tableMu.Unlock()
	swap := time.Since(swapStart)

	paths, digests := execAllow(pushed.x)
	if len(pushed.x) > 0 || tn.policy.xsink != nil {
		if tn.policy.xsink == nil {
			tn.policy.xsink = policyx.NewSink()
			policyx.Install(tn.policy.xsink)
		}
		tn.policy.xsink.Narrow(policyx.NewAllow(paths, digests))
		// One line per narrowing about what the sink has cost so far, so that
		// a run of any length carries the number spike E2 measured rather than
		// only a run long enough to trip the sink's own counter.
		tn.policy.xsink.Report()
	}

	tn.policy.inForce = pushed
	tn.policy.digest = digest
	log.Infof("tunnel narrow: sha256=%s n=%d of %d names kept x=%d f=%d", digest, len(keep), before, len(pushed.x), len(pushed.f))
	// The second line is the cost, and it is a line of its own so that the
	// first one keeps saying exactly what was applied and nothing else. The
	// swap is the part a running workload is exposed to: everything before it
	// is reading a document, and everything after it is bookkeeping.
	log.Infof("tunnel narrow: applied in %v, of which the table swap was %v", time.Since(start), swap)
	return digest, nil
}

// ===== the document =====

// policyDocument is what is read out of the pushed bytes. `e`, the letter Deno
// grew for an environment variable, is not read: this sandbox enforces no E,
// and ignoring a grant is a narrowing and never a widening.
type policyDocument struct {
	N []policyNetEntry  `json:"n"`
	F []policyFileEntry `json:"f"`
	X []policyExecEntry `json:"x"`
}

type policyNetEntry struct {
	Host  string `json:"host"`
	CIDR  string `json:"cidr"`
	Ports []int  `json:"ports"`
}

type policyFileEntry struct {
	Path  string   `json:"path"`
	Modes []string `json:"modes"`
}

type policyExecEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// policyAtoms reads the envelope and the three components.
//
// The envelope is read here although tunneld has already read it, for the same
// reason attest/sandbox/deno does: reaching this with something else means the
// contract was driven directly, and refusing anyway keeps "this sandbox
// enforces a version 1 policy" a statement about version 1.
func policyAtoms(policy []byte) (*policySets, error) {
	if len(policy) == 0 {
		return nil, policyRefuse("it is empty")
	}
	var envelope struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(policy, &envelope); err != nil {
		return nil, policyRefuse("%d bytes that are not a JSON object: %v", len(policy), err)
	}
	if envelope.Format != policyFormat {
		return nil, policyRefuse("format %q is not %q", envelope.Format, policyFormat)
	}
	if envelope.Version != policyVersion {
		return nil, policyRefuse("version %d is not %d", envelope.Version, policyVersion)
	}
	var d policyDocument
	if err := json.Unmarshal(policy, &d); err != nil {
		return nil, policyRefuse("it is not a policy this sandbox reads: %v", err)
	}
	sets := &policySets{}
	var err error
	if sets.n, err = policyNetAtoms(&d); err != nil {
		return nil, err
	}
	if sets.f, err = policyFileAtoms(&d); err != nil {
		return nil, err
	}
	if sets.x, err = policyExecAtoms(&d); err != nil {
		return nil, err
	}
	sets.n = sortedSet(sets.n)
	sets.f = sortedSet(sets.f)
	sets.x = sortedSet(sets.x)
	return sets, nil
}

func sortedSet(atoms []string) []string {
	slices.Sort(atoms)
	return slices.Compact(atoms)
}

// policyNetAtoms reads `n`.
func policyNetAtoms(d *policyDocument) ([]string, error) {
	var atoms []string
	for _, n := range d.N {
		if n.Host == "" {
			if n.CIDR != "" {
				return nil, policyRefuse("the n entry for %q is a CIDR and this sandbox checks the name a workload asked the resolver for, before there is an address at all, so a CIDR grants exactly the destinations an agent never names", n.CIDR)
			}
			return nil, policyRefuse("an n entry names no host")
		}
		if err := policyCheckHost(n.Host); err != nil {
			return nil, err
		}
		host := strings.ToLower(strings.TrimSuffix(n.Host, "."))
		if len(n.Ports) == 0 {
			atoms = append(atoms, "net:"+host)
			continue
		}
		for _, port := range n.Ports {
			if port < 1 || port > 65535 {
				return nil, policyRefuse("the n entry for %q names port %d, which is not a port", n.Host, port)
			}
			atoms = append(atoms, fmt.Sprintf("net:%s:%d", host, port))
		}
	}
	return atoms, nil
}

// policyCheckHost is Deno's FQDN rule, kept so that the two sandboxes refuse
// the same documents: letters, digits, '-' and '.', or a bracketed IP literal.
func policyCheckHost(host string) error {
	if literal, bracketed := strings.CutPrefix(host, "["); bracketed {
		literal, closed := strings.CutSuffix(literal, "]")
		if !closed {
			return policyRefuse("the host %q opens a bracket it does not close", host)
		}
		if _, err := netip.ParseAddr(literal); err != nil {
			return policyRefuse("the host %q is bracketed and %q is not an IP literal", host, literal)
		}
		return nil
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return policyRefuse("the host %q has a character a host name may not have: %q", host, r)
		}
	}
	return nil
}

// policyFileAtoms reads `f`.
func policyFileAtoms(d *policyDocument) ([]string, error) {
	var atoms []string
	for _, f := range d.F {
		if err := policyCheckPath("f", f.Path); err != nil {
			return nil, err
		}
		if len(f.Modes) == 0 {
			return nil, policyRefuse("the f entry for %q names no mode", f.Path)
		}
		for _, mode := range f.Modes {
			switch mode {
			case "r":
				atoms = append(atoms, "read:"+f.Path)
			case "w":
				atoms = append(atoms, "write:"+f.Path)
			default:
				return nil, policyRefuse("the f entry for %q names the mode %q, which this sandbox does not know", f.Path, mode)
			}
		}
	}
	return atoms, nil
}

// policyExecAtoms reads `x`. Unlike Deno, this sandbox can enforce a digest:
// the hash of the binary is already computed at the execve point, so an x entry
// may name a path, a sha256, or both.
func policyExecAtoms(d *policyDocument) ([]string, error) {
	var atoms []string
	for _, x := range d.X {
		if x.Path == "" && x.SHA256 == "" {
			return nil, policyRefuse("an x entry names neither a path nor a digest")
		}
		if x.SHA256 != "" {
			sum := strings.ToLower(x.SHA256)
			if len(sum) != 64 {
				return nil, policyRefuse("the x entry with digest %q is not 64 hex characters of sha256", x.SHA256)
			}
			if _, err := hex.DecodeString(sum); err != nil {
				return nil, policyRefuse("the x entry with digest %q is not hexadecimal", x.SHA256)
			}
			atoms = append(atoms, "run:sha256:"+sum)
		}
		if x.Path != "" {
			if err := policyCheckPath("x", x.Path); err != nil {
				return nil, err
			}
			// A path spelled "sha256:…" would produce the atom a digest entry
			// produces, and two documents that mean different things would
			// then compare equal in the subset check. Refused rather than
			// escaped, because no real path looks like this and a policy that
			// contains one is a policy somebody is testing the parser with.
			if strings.HasPrefix(x.Path, "sha256:") {
				return nil, policyRefuse("the x entry path %q begins with %q, which is how a digest is spelled in this sandbox's atoms", x.Path, "sha256:")
			}
			atoms = append(atoms, "run:"+x.Path)
		}
	}
	return atoms, nil
}

// policyCheckPath refuses an empty path and one with a comma or a NUL in it,
// which is Deno's rule and is kept so that a document one sandbox reads the
// other reads the same way.
func policyCheckPath(field, path string) error {
	if path == "" {
		return policyRefuse("a %s entry names no path", field)
	}
	if strings.ContainsAny(path, ",\x00") {
		return policyRefuse("the %s entry %q has a comma or a NUL in it", field, path)
	}
	return nil
}

// ===== the subset check =====

// policySubset is P1 ⊑ P0, component by component, over sorted deduplicated
// atoms. The refusal names the component that widened and the atoms that did
// it, because "refused" without them is a message nobody can act on.
func policySubset(pushed, base *policySets) error {
	for _, c := range []struct {
		name string
		got  []string
		want []string
	}{
		{"n", pushed.n, base.n},
		{"f", pushed.f, base.f},
		{"x", pushed.x, base.x},
	} {
		if extra := notIn(c.got, c.want); len(extra) > 0 {
			return policyRefuse("it widens %s by %v", c.name, extra)
		}
	}
	return nil
}

// notIn is the atoms of got that want does not have.
func notIn(got, want []string) []string {
	have := make(map[string]struct{}, len(want))
	for _, a := range want {
		have[a] = struct{}{}
	}
	var extra []string
	for _, a := range got {
		if _, ok := have[a]; !ok {
			extra = append(extra, a)
		}
	}
	return extra
}

// ===== atoms and the table =====

// bootTableAtoms is P0 for n: one atom per row of the table --tunnel-table
// named, on the one port that row permits.
func bootTableAtoms(t *netstack.TunnelTable) []string {
	atoms := make([]string, 0, len(t.Names))
	for name, e := range t.Names {
		atoms = append(atoms, fmt.Sprintf("net:%s:%d", name, e.Port))
	}
	return sortedSet(atoms)
}

// canonicalNetAtoms rewrites `net:<host>` as `net:<host>:<the table's port>`
// for a host the table carries. A host the table does not carry is left alone,
// and the subset check refuses it.
func canonicalNetAtoms(atoms []string, t *netstack.TunnelTable) []string {
	out := make([]string, 0, len(atoms))
	for _, a := range atoms {
		rest, ok := strings.CutPrefix(a, "net:")
		if !ok {
			out = append(out, a)
			continue
		}
		if _, _, hasPort := netAtomHostPort(a); hasPort {
			out = append(out, a)
			continue
		}
		if e, ok := t.Names[rest]; ok {
			out = append(out, fmt.Sprintf("net:%s:%d", rest, e.Port))
			continue
		}
		out = append(out, a)
	}
	return sortedSet(out)
}

// netAtomHostPort splits `net:<host>:<port>`. It reports false for the bare
// `net:<host>` form, and for anything that is not a net atom at all.
func netAtomHostPort(atom string) (string, int, bool) {
	rest, ok := strings.CutPrefix(atom, "net:")
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(rest[i+1:])
	if err != nil {
		return "", 0, false
	}
	return rest[:i], port, true
}

// execAllow splits the x atoms into the two things the sink matches on.
func execAllow(atoms []string) (paths, digests []string) {
	for _, a := range atoms {
		if sum, ok := strings.CutPrefix(a, "run:sha256:"); ok {
			digests = append(digests, sum)
			continue
		}
		if p, ok := strings.CutPrefix(a, "run:"); ok {
			paths = append(paths, p)
		}
	}
	return paths, digests
}
