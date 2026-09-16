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

// Package deno is a [sandbox.Sandbox] that enforces a pushed policy by
// starting a Deno process with permission flags.
//
// It is the second implementation of the contract and the first that enforces
// anything: [sandbox.Null] records a policy and says it has it, which is the
// honest implementation of a contract in which a sandbox is not where anything
// is enforced. Deno is here because its permission flags are (N, F, X) nearly
// verbatim — --allow-net, --allow-read, --allow-write, --allow-run — so it is
// the cheapest honest enforcer to hold a pushed policy against. It is a study
// instrument and not a plan: what it cannot express is an input to the gVisor
// tickets, and this package's job is to be exact about which half is which.
//
// # Applying is fork and exec, and that changes what an ack means
//
// [sandbox.Null.Apply] is a state change inside the acknowledging process.
// Apply here is a process: the permission flags are fixed at exec, so a policy
// is a running Deno and a second policy is a second one. Spike E4
// (docs/snp/evidence/ticket23/spikes/E4) measured the three consequences, and
// this package narrows one of them and carries the other two as written:
//
//   - The ack is a claim about the past. Apply can truthfully say the process
//     started and can say nothing about whether it is still running. In E4 an
//     ack left Apply 1.9 ms after exec.Start and the process was dead 41 ms
//     later, on a flag Deno's own parser rejects, and the pusher's tunnel
//     stayed up. Two things here narrow that window: every value that reaches
//     a flag is checked before the exec (see [Config] and the refusals below),
//     and Apply does not return until the process has survived a settle —
//     Config.Settle, 50 ms by default, against the 36–43 ms Deno took to die.
//     It narrows and does not close: a workload that dies a minute later is
//     still a tunnel asserting something this sandbox no longer believes, and
//     the contract has no verb for saying so (docs/sandbox-contract.md, "What
//     is not built"). [Sandbox.Done] and [Sandbox.Exited] are what a caller
//     watching for that gets instead, and watching is all they are.
//
//   - A second policy is a restart, and a restart destroys the workload. E4
//     case (iii b): a narrowing push killed an agent mid-conversation, its
//     message history went with it, and the replacement started the task again
//     from turn one in the same working directory. This package does that
//     rather than refusing, because the contract says a sandbox applies a
//     policy its delegator narrowed to and has no way to answer "I am busy" —
//     Apply returns nil or an error, and an error means refused.
//
//   - A widening push is refused, which is the one rule the ticket asks for.
//     The first Apply fixes the set; a later one whose atoms are not a subset
//     of it is refused with [sandbox.ErrPolicyRefused] naming what widened.
//
// # The grammar, and why each refusal is a refusal
//
// The envelope is version 1 and stays version 1 — tunneld has already checked
// it (tunneld.PolicyChecked) before Apply is called, and this package checks it
// again for the same reason [sandbox.Null] does. `n`, `f` and `x` are read as
// ticket 22 left them, with an `e` beside them; all four are unknown fields of
// the envelope, which is what the contract says a policy is. This ticket does
// not define a `P` format, and nothing here should be read as one.
//
//	n: [{"host": "api.anthropic.com", "ports": [443]}]  →  --allow-net=host:port
//	f: [{"path": "./summary.txt", "modes": ["r","w"]}]  →  --allow-read / --allow-write
//	x: [{"path": "/bin/true"}]                          →  --allow-run=path
//	e: [{"variable": "ANTHROPIC_API_KEY"}]              →  --allow-env=NAME, and the environ
//
// Four things in that document are refused rather than mapped, each because
// mapping it would grant something the document did not say:
//
//   - An `n` entry with a `cidr` and no `host`. Deno parses a mask correctly
//     and matches addresses against it correctly, and every check `fetch`
//     raises is against the name in the URL, before resolution (spike E3). A
//     name is in no CIDR, so the entry grants exactly the destinations an agent
//     never names. An entry that carries both is read by its host: the CIDR is
//     then a fact for an enforcer that sees addresses, and this one does not.
//
//   - A host with a character Deno's FQDN parser refuses. `--allow-net=nonsense///`
//     parses as far as the flag and kills the process at startup with `invalid
//     host`, which in E4 happened 43 ms after the ack — the one moment this
//     package cannot take back. Refusing it at Apply turns a dead workload into
//     a refusal the pusher can act on.
//
//   - An `x` entry with a `sha256`. Deno has nowhere to put a digest:
//     --allow-run matches the spelling of a path and nothing else, and a grant
//     it cannot resolve is an `Info` line and a process that runs anyway (E3).
//     Applying the path alone would grant any binary that turns up at it, which
//     is wider than the entry. Worth knowing even for the entries that do map:
//     the grant is on the path, and arguments are not part of it — one granted
//     /bin/sh is every command on the machine.
//
//   - Anything with a comma in it, in a path or a host. The flags are
//     comma-separated lists, so a comma in a value is a second grant nobody
//     wrote.
//
// Everything else in the document is ignored. That is the contract's rule for
// unknown fields and not this package's preference: `n`, `f`, `x` and `e` are
// themselves unknown fields of a version 1 envelope, so a sandbox that refused
// what it did not recognise would refuse every later extension of the same
// document. E4's throwaway adapter did refuse them, on the argument that an
// enforcer cannot skip the part of a policy it did not read; that argument is
// right and the place to answer it is a version bump or the policy track's `P`,
// not a sandbox quietly disagreeing with the envelope it was handed.
//
// # The environment is built, not filtered
//
// The child's environment is exactly the variables `e` names, copied from this
// process's, plus PATH and HOME, which Deno itself needs. E4's adapter passed
// os.Environ() and let --allow-env decide what the script could read, which
// means the API key was in the child's environ under every policy and the
// permission flag was a read gate on a secret the sandbox had already handed
// over. A grant that names a variable has to be the reason the variable is
// there.
//
// # The atoms
//
// A policy becomes a sorted, deduplicated set of atoms, and the set — not the
// flag string — is what a widening is judged on: --allow-net=a,b and
// --allow-net=b,a are two strings and one policy.
//
//	net:<host>:<port>   net:<host>   read:<path>   write:<path>   run:<path>   env:<NAME>
//
// # The import graph
//
// This package imports the standard library, golang.org/x/sys/unix and
// gvisor.dev/gvisor/attest/sandbox, and nothing else from
// gvisor.dev/gvisor/attest — the same invariant package sandbox holds, checked
// the same way (importgraph_test.go). A sandbox sees no evidence, no key and
// no trust decision, and a sandbox that could reach the verifier would be one
// somebody eventually asked to.
package deno

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// DefaultSettle is how long Apply waits for the process to still be there
// before it acknowledges, when [Config] does not say. Deno's startup flag
// validation killed the process 36–43 ms after exec in spike E4, so 50 ms is
// the smallest number that catches it; the wait ends early when the process
// ends, so the cost of a larger one is paid only by a run that fails.
const DefaultSettle = 50 * time.Millisecond

// Config is the process this sandbox starts. Nothing here comes from a pushed
// policy: a delegator says what a workload may reach, and which workload it is
// belongs to whoever set this sandbox up.
type Config struct {
	// Binary is the path to the deno executable, and Script the .ts entry
	// point it runs. Both are used as given; neither is looked up on PATH.
	Binary string
	Script string

	// Dir is the working directory the process runs in. It matters to more
	// than tidiness: a relative --allow-write is resolved against it at process
	// start, so ./summary.txt means a different file under a different Dir.
	Dir string

	// Args are passed to the script, after it, as Deno passes them.
	Args []string

	// Stdout and Stderr are where the process's output goes. A nil one
	// discards it — except that the first line of stderr is kept either way,
	// because it is what a process that dies during the settle has to say for
	// itself.
	Stdout, Stderr io.Writer

	// Settle is how long Apply waits before acknowledging. Zero means
	// [DefaultSettle]; tests set it to say how patient they are.
	Settle time.Duration
}

// A Sandbox is one Deno process at a time, under the policy last pushed to it.
type Sandbox struct {
	network sandbox.Network
	cfg     Config
	settle  time.Duration
	logf    func(string, ...any)

	// proc is written only under mu, by Apply, and read without it by Done and
	// Exited. Whoever is watching for the workload's end is watching precisely
	// while Apply may be holding mu — a restart can spend two seconds waiting
	// for a process to take its SIGTERM — and a liveness signal that blocked
	// behind the thing it reports on would not be one.
	proc atomic.Pointer[process]

	mu      sync.Mutex
	closed  bool
	granted []string
}

var _ sandbox.Sandbox = (*Sandbox)(nil)

// noProcess is what [Sandbox.Done] hands back before anything has been
// started: a closed channel, because "no process is running" is the state Done
// reports and it is already true.
var noProcess = closedChannel()

func closedChannel() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// noNetwork is what a sandbox built without a tunneld behind it passes through
// to: a [sandbox.Network] whose two verbs are the error [sandbox.Null] answers
// its own with. Saying it once, here, is what lets Open and Accept below be
// the pass-through this package claims they are rather than two copies of the
// same guard — a sandbox without a network is a programming error, and an
// error is how it says so rather than a panic in whichever goroutine first
// asked it for a stream.
type noNetwork struct{}

func (noNetwork) Open(context.Context, string) (sandbox.Stream, error) {
	return nil, sandbox.ErrNoNetwork
}

func (noNetwork) Accept(context.Context) (sandbox.Stream, sandbox.Attested, error) {
	return nil, sandbox.Attested{}, sandbox.ErrNoNetwork
}

// New returns a sandbox that will start cfg's process when a policy is pushed
// at it, and passes streams through to n meanwhile. logf may be nil, which
// enforces policies without saying so.
//
// Nothing is validated here and no process is started. A sandbox exists from
// the moment tunneld has one to push at, and what it is allowed to run is not
// known until something pushes.
func New(n sandbox.Network, cfg Config, logf func(string, ...any)) *Sandbox {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if n == nil {
		n = noNetwork{}
	}
	settle := cfg.Settle
	if settle <= 0 {
		settle = DefaultSettle
	}
	return &Sandbox{network: n, cfg: cfg, settle: settle, logf: logf}
}

// Open asks tunneld for a stream to the named peer. It is the null sandbox's
// pass-through, verbatim: what a policy says about the network is enforced in
// the process this sandbox starts, and a sandbox that filtered streams as well
// would be enforcing the same rule in two places that could disagree.
func (s *Sandbox) Open(ctx context.Context, peer string) (sandbox.Stream, error) {
	return s.network.Open(ctx, peer)
}

// Accept takes the next stream a peer opened, with the identity it was
// admitted under.
func (s *Sandbox) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	return s.network.Accept(ctx)
}

// Apply turns the policy into Deno's permission flags and restarts the process
// under them, and acknowledges only once that process has survived the settle.
//
// A refusal — any error, all of them wrapping [sandbox.ErrPolicyRefused] —
// means this sandbox is not enforcing the document, and tunneld turns it into
// the pusher's PolicyNotApplied. The state a refusal leaves behind is the
// honest one and not always a comfortable one: a policy refused before the exec
// leaves the running process alone, and a policy that fails at the settle has
// already stopped it, because the flags could not be changed without it.
func (s *Sandbox) Apply(ctx context.Context, policy []byte) error {
	atoms, err := atomsOf(policy)
	if err != nil {
		return s.refused(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.refused(refuse("this sandbox is closed"))
	}
	if extra := s.widening(atoms); len(extra) > 0 {
		return s.refused(refuse("it widens %v by %v", s.granted, extra))
	}
	s.proc.Load().stop(ctx)
	p, err := s.start(atoms)
	if err != nil {
		return s.refused(refuse("the process did not start: %v", err))
	}
	s.proc.Store(p)
	if err := p.settle(ctx, s.settle); err != nil {
		p.stop(context.Background())
		return s.refused(err)
	}
	s.granted = atoms
	sum := sha256.Sum256(policy)
	s.logf("SANDBOX deno applied atoms=%d sha256=%s pid=%d", len(atoms), hex.EncodeToString(sum[:]), p.cmd.Process.Pid)
	return nil
}

// widening is the atoms want asks for that the applied set does not already
// have. Before the first Apply there is no set and so nothing widens it: a
// sandbox that has enforced nothing has nothing to be narrowed from.
func (s *Sandbox) widening(want []string) []string {
	if s.granted == nil {
		return nil
	}
	have := make(map[string]bool, len(s.granted))
	for _, a := range s.granted {
		have[a] = true
	}
	var extra []string
	for _, w := range want {
		if !have[w] {
			extra = append(extra, w)
		}
	}
	return extra
}

// refused says why on the console and hands the reason back, so that the two
// sentences are the same sentence.
func (s *Sandbox) refused(err error) error {
	s.logf("SANDBOX deno refused: %v", err)
	return err
}

// Close stops the process and leaves this sandbox refusing anything pushed at
// it afterwards. A tunneld that has closed its sandbox is one that should not
// be starting a workload on the next push.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.proc.Load().stop(context.Background())
	return nil
}

// Done is closed when the process started by the most recent Apply exits. It
// is the liveness a caller gets in place of the verb the contract does not
// have: an acknowledged policy whose process has died shows up here and
// nowhere else.
//
// The channel belongs to one process. A caller that takes it, and is then
// overtaken by a second Apply, is watching the process it asked about rather
// than the one running now, which is the distinction worth keeping.
func (s *Sandbox) Done() <-chan struct{} { return s.proc.Load().ended() }

// Exited reports how that process ended: its exit status, and whether it has
// ended at all. It is false while the process runs and before there is one,
// and a process killed by a signal reports -1, as os/exec does.
func (s *Sandbox) Exited() (int, bool) { return s.proc.Load().exited() }
