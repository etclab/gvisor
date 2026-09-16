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

package deno_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/sandbox/deno"
)

// The Deno in these tests is this test binary, re-executed — the idiom
// attest/sandbox/socket_test.go already uses for the sandbox in another
// process, and here for the same reasons. A real Deno would need a network,
// an API key and a runtime nobody in this tree measures; what these tests are
// about is the command line a policy becomes and when the acknowledgement is
// sent, and for that a fake that writes down its own argv and environ says
// more than a real one would.
//
// A child is told from an ordinary test run by its first argument: this
// package starts Deno as `deno run …`, and `go test` never puts a bare `run`
// there. TestMain answers before the testing package has parsed a flag, which
// is why the child does not choke on one.

const (
	// secretVar stands in for ANTHROPIC_API_KEY: a variable `e` names, that
	// the child must be given because the policy said so and not because this
	// process happened to have it. Its value is a string in this file and
	// never a key.
	secretVar = "GVISOR_DENO_TEST_SECRET"
	secret    = "not-a-key"
)

// a run is one process the fake Deno was started as, as it records itself.
type run struct {
	PID  int      `json:"pid"`
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(fakeDeno(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeDeno writes down how it was started and then either dies at once with a
// line on stderr — which is E4 case (iv), a process that starts, is
// acknowledged and is gone milliseconds later — or waits to be stopped.
func fakeDeno(argv []string) int {
	var record, die string
	for _, a := range argv {
		if value, ok := strings.CutPrefix(a, "--record="); ok {
			record = value
		}
		if value, ok := strings.CutPrefix(a, "--die="); ok {
			die = value
		}
	}
	if record != "" {
		line, _ := json.Marshal(run{PID: os.Getpid(), Argv: argv, Env: os.Environ()})
		if f, err := os.OpenFile(record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.Write(append(line, '\n'))
			f.Close()
		}
	}
	if die != "" {
		fmt.Fprintln(os.Stderr, die)
		return 1
	}
	time.Sleep(time.Minute)
	return 0
}

// The policies. Every one of them is a version 1 envelope with `n`, `f`, `x`
// and `e` as unknown fields of it, which is what the contract says a policy
// is.
const (
	// policyFull exercises all four letters at once, and is written with its
	// entries and its modes out of order on purpose: what Deno is started with
	// is the sorted set and not the order somebody typed.
	policyFull = `{"format":"policy","version":1,
		"n":[{"host":"www.rfc-editor.org","ports":[443,80]},{"host":"api.anthropic.com","ports":[443]}],
		"f":[{"path":"./summary.txt","modes":["w"]},{"path":"./notes.md","modes":["w","r"]}],
		"x":[{"path":"/bin/true"}],
		"e":[{"variable":"` + secretVar + `"}]}`

	// twoHosts is E4's case (i), near enough: what a trivial agent needs.
	twoHosts = `{"format":"policy","version":1,
		"n":[{"host":"api.anthropic.com","ports":[443,80]},{"host":"www.rfc-editor.org","ports":[443]}],
		"f":[{"path":"./summary.txt","modes":["r","w"]}]}`

	// twoHostsReordered is twoHosts with the entries, the ports and the modes
	// in another order. The same policy, and not a widening.
	twoHostsReordered = `{"format":"policy","version":1,
		"n":[{"host":"www.rfc-editor.org","ports":[443]},{"host":"api.anthropic.com","ports":[80,443]}],
		"f":[{"path":"./summary.txt","modes":["w","r"]}]}`

	// wider is twoHosts plus a destination nobody granted: E4's case (iii).
	wider = `{"format":"policy","version":1,
		"n":[{"host":"api.anthropic.com","ports":[443,80]},{"host":"www.rfc-editor.org","ports":[443]},{"host":"example.com","ports":[443]}],
		"f":[{"path":"./summary.txt","modes":["r","w"]}]}`

	// narrower is twoHosts with the tool's destination taken away: E4's case
	// (iii b), the narrowing that costs the agent its conversation.
	narrower = `{"format":"policy","version":1,
		"n":[{"host":"api.anthropic.com","ports":[443]}],
		"f":[{"path":"./summary.txt","modes":["r","w"]}]}`

	aCIDR      = `{"format":"policy","version":1,"n":[{"cidr":"0.0.0.0/0","ports":[443]}]}`
	aDigest    = `{"format":"policy","version":1,"x":[{"path":"/bin/true","sha256":"f0b6a7b0c0d0"}]}`
	aBadHost   = `{"format":"policy","version":1,"n":[{"host":"nonsense///","ports":[443]}]}`
	anyPolicy  = `{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}]}`
	notAPolicy = `{"format":"policy","version":1,"n":"everywhere"}`
)

func TestAPolicyBecomesTheFlagsDenoIsStartedWith(t *testing.T) {
	t.Setenv(secretVar, secret)
	f := newFake(t, 0)
	if err := f.Apply(context.Background(), []byte(policyFull)); err != nil {
		t.Fatalf("applying a policy with all four letters in it: %v", err)
	}
	started := f.runs(t, 1)[0]
	want := append([]string{
		"run", "--no-prompt",
		"--allow-net=api.anthropic.com:443,www.rfc-editor.org:443,www.rfc-editor.org:80",
		"--allow-read=./notes.md",
		"--allow-write=./notes.md,./summary.txt",
		"--allow-run=/bin/true",
		"--allow-env=" + secretVar,
		f.script,
	}, f.args...)
	if !slices.Equal(started.Argv, want) {
		t.Errorf("Deno was started as\n\t%q\nwant\n\t%q", started.Argv, want)
	}

	// The environment is built from the policy and not filtered from this
	// process's: exactly what `e` names, and the two variables Deno itself
	// needs.
	wantEnv := environ(secretVar, "PATH", "HOME")
	gotEnv := slices.Clone(started.Env)
	slices.Sort(gotEnv)
	if !slices.Equal(gotEnv, wantEnv) {
		t.Errorf("the child's environment is\n\t%q\nwant\n\t%q", gotEnv, wantEnv)
	}
}

func TestACIDRIsRefusedBecauseDenoMatchesTheNameAnAgentAsks(t *testing.T) {
	f := newFake(t, 0)
	err := f.Apply(context.Background(), []byte(aCIDR))
	checkRefusal(t, err, "0.0.0.0/0")
	f.checkNothingStarted(t)
}

func TestAnExecEntryWithADigestIsRefusedBecauseDenoHasNowhereToPutIt(t *testing.T) {
	f := newFake(t, 0)
	err := f.Apply(context.Background(), []byte(aDigest))
	checkRefusal(t, err, "f0b6a7b0c0d0")
	f.checkNothingStarted(t)
}

func TestAHostDenoWouldRejectAtStartupIsRefusedBeforeTheExec(t *testing.T) {
	f := newFake(t, 0)
	err := f.Apply(context.Background(), []byte(aBadHost))
	checkRefusal(t, err, "nonsense///")
	f.checkNothingStarted(t)
}

func TestABodyThisSandboxCannotReadIsRefusedAlthoughTheEnvelopeIsFine(t *testing.T) {
	f := newFake(t, 0)
	err := f.Apply(context.Background(), []byte(notAPolicy))
	checkRefusal(t, err, "not a policy this sandbox reads")
	f.checkNothingStarted(t)
}

func TestAWideningSecondPolicyIsRefusedAndTheRunningProcessIsUntouched(t *testing.T) {
	f := newFake(t, 0)
	f.apply(t, twoHosts)
	before := f.runs(t, 1)[0]
	running := f.Done()

	err := f.Apply(context.Background(), []byte(wider))
	checkRefusal(t, err, "example.com:443")
	select {
	case <-running:
		t.Error("the refused policy stopped the process the applied one started")
	default:
	}
	after := f.runs(t, 1)
	if len(after) != 1 || after[0].PID != before.PID {
		t.Errorf("the refused policy left %d runs (pids %v); want the one process %d", len(after), pids(after), before.PID)
	}
}

func TestANarrowingSecondPolicyRestartsTheProcessAndLosesTheWorkload(t *testing.T) {
	f := newFake(t, 0)
	f.apply(t, twoHosts)
	first := f.Done()
	f.apply(t, narrower)

	select {
	case <-first:
	default:
		t.Error("the process the first policy started is still running; a narrowing policy is a restart")
	}
	started := f.runs(t, 2)
	if started[0].PID == started[1].PID {
		t.Errorf("both policies report pid %d; the second should be another process", started[0].PID)
	}
	if got := flagOf(started[1].Argv, "--allow-net="); got != "api.anthropic.com:443" {
		t.Errorf("the second process was started with --allow-net=%s; want the narrowed destination", got)
	}
}

func TestTheSameAtomsInADifferentOrderAreNotAWidening(t *testing.T) {
	f := newFake(t, 0)
	f.apply(t, twoHosts)
	f.apply(t, twoHostsReordered)
	started := f.runs(t, 2)
	if !slices.Equal(started[0].Argv, started[1].Argv) {
		t.Errorf("the reordered policy started\n\t%q\nand the first started\n\t%q", started[1].Argv, started[0].Argv)
	}
}

func TestAProcessThatDiesDuringTheSettleIsARefusalCarryingWhatItSaid(t *testing.T) {
	// The settle is generous because it ends as soon as the process does; what
	// it must not do is end before a slow machine has started one.
	f := newFake(t, 10*time.Second, "--die=error: the module could not be loaded")
	err := f.Apply(context.Background(), []byte(anyPolicy))
	checkRefusal(t, err, "error: the module could not be loaded")
	select {
	case <-f.Done():
	default:
		t.Error("the process is gone and Done is open")
	}
	if code, ended := f.Exited(); !ended || code != 1 {
		t.Errorf("Exited reports (%d, %v); want the status 1 the process exited with", code, ended)
	}
}

func TestOpenAndAcceptPassThroughToTheNetworkUntouched(t *testing.T) {
	net := &fakeNetwork{opened: &fakeStream{name: "opened"}, incoming: &fakeStream{name: "incoming"}, who: sandbox.Attested{Peer: "b", Vendor: "amd-sev-snp"}}
	s := deno.New(net, deno.Config{}, t.Logf)
	ctx := context.Background()

	stream, err := s.Open(ctx, "b")
	if err != nil || stream != sandbox.Stream(net.opened) {
		t.Errorf("Open gave back (%v, %v); want the network's own stream", stream, err)
	}
	if net.asked != "b" {
		t.Errorf("the network was asked for peer %q; want %q", net.asked, "b")
	}
	if _, err := s.Open(ctx, "nobody"); err == nil {
		t.Error("Open invented a stream for a peer the network refused")
	}
	accepted, who, err := s.Accept(ctx)
	if err != nil || accepted != sandbox.Stream(net.incoming) || who != net.who {
		t.Errorf("Accept gave back (%v, %+v, %v); want the network's stream and identity", accepted, who, err)
	}

	// A sandbox with no tunneld behind it says so rather than dereferencing
	// one, exactly as the null sandbox does.
	none := deno.New(nil, deno.Config{}, nil)
	if _, err := none.Open(ctx, "b"); !errors.Is(err, sandbox.ErrNoNetwork) {
		t.Errorf("Open with no network returned %v; want ErrNoNetwork", err)
	}
	if _, _, err := none.Accept(ctx); !errors.Is(err, sandbox.ErrNoNetwork) {
		t.Errorf("Accept with no network returned %v; want ErrNoNetwork", err)
	}
}

// ===== the fake Deno, from the test's side =====

// a fake is a sandbox whose Deno is this test binary, with the file every
// child writes itself down in.
type fake struct {
	*deno.Sandbox
	dir    string
	script string
	record string
	args   []string
}

func newFake(t *testing.T, settle time.Duration, extra ...string) *fake {
	t.Helper()
	dir := t.TempDir()
	f := &fake{
		dir:    dir,
		script: filepath.Join(dir, "agent.ts"),
		record: filepath.Join(dir, "runs.jsonl"),
	}
	f.args = append([]string{"--record=" + f.record}, extra...)
	f.Sandbox = deno.New(nil, deno.Config{
		Binary: os.Args[0],
		Script: f.script,
		Dir:    dir,
		Args:   f.args,
		Settle: settle,
	}, t.Logf)
	t.Cleanup(func() { f.Close() })
	return f
}

func (f *fake) apply(t *testing.T, policy string) {
	t.Helper()
	if err := f.Apply(context.Background(), []byte(policy)); err != nil {
		t.Fatalf("applying %s: %v", policy, err)
	}
}

// runs waits for n processes to have written themselves down and returns them
// in the order they started. Apply has already waited for the settle, so this
// waits only for a child's first write and fails rather than hanging.
func (f *fake) runs(t *testing.T, n int) []run {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		started := f.recorded(t)
		if len(started) >= n || time.Now().After(deadline) {
			if len(started) != n {
				t.Fatalf("%d processes wrote themselves down; want %d", len(started), n)
			}
			return started
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fake) recorded(t *testing.T) []run {
	t.Helper()
	text, err := os.ReadFile(f.record)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading what the processes wrote down: %v", err)
	}
	var started []run
	for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n") {
		var r run
		if json.Unmarshal([]byte(line), &r) == nil {
			started = append(started, r)
		}
	}
	return started
}

func (f *fake) checkNothingStarted(t *testing.T) {
	t.Helper()
	if started := f.recorded(t); len(started) != 0 {
		t.Errorf("a refused policy started %d processes: %v", len(started), pids(started))
	}
}

func checkRefusal(t *testing.T, err error, say string) {
	t.Helper()
	if !errors.Is(err, sandbox.ErrPolicyRefused) {
		t.Fatalf("the policy was answered with %v; want a refusal wrapping ErrPolicyRefused", err)
	}
	if !strings.Contains(err.Error(), say) {
		t.Errorf("the refusal is %q; it does not say %q", err, say)
	}
}

func pids(started []run) []int {
	var out []int
	for _, r := range started {
		out = append(out, r.PID)
	}
	return out
}

func flagOf(argv []string, flag string) string {
	for _, a := range argv {
		if value, ok := strings.CutPrefix(a, flag); ok {
			return value
		}
	}
	return ""
}

// environ is what this process's named variables look like in a child's, in
// the order a sorted comparison wants them.
func environ(names ...string) []string {
	var out []string
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	slices.Sort(out)
	return out
}

// ===== the network, from the test's side =====

// a fakeNetwork is tunneld with everything but the two verbs taken out: what
// the pass-through tests need to know is that the stream that came back is the
// one it handed over.
type fakeNetwork struct {
	opened   *fakeStream
	incoming *fakeStream
	who      sandbox.Attested
	asked    string
}

func (f *fakeNetwork) Open(_ context.Context, peer string) (sandbox.Stream, error) {
	f.asked = peer
	if peer != "b" {
		return nil, fmt.Errorf("tunneld: unknown peer: %q is not in the peer table", peer)
	}
	return f.opened, nil
}

func (f *fakeNetwork) Accept(context.Context) (sandbox.Stream, sandbox.Attested, error) {
	return f.incoming, f.who, nil
}

// a fakeStream carries nothing. These tests compare the stream that came back
// with the one the network gave out, and never read or write one.
type fakeStream struct{ name string }

func (*fakeStream) Read([]byte) (int, error)         { return 0, io.EOF }
func (*fakeStream) Write(p []byte) (int, error)      { return len(p), nil }
func (*fakeStream) Close() error                     { return nil }
func (*fakeStream) CloseWrite() error                { return nil }
func (*fakeStream) SetDeadline(time.Time) error      { return nil }
func (*fakeStream) SetReadDeadline(time.Time) error  { return nil }
func (*fakeStream) SetWriteDeadline(time.Time) error { return nil }
