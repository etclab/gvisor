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

// The two hops the ticket asks for, live, on the promoted pieces: three
// tunnelds over loopback with the fake platform, a policy pushed on each hop,
// this binary's own loop on the middle one and attest/sandbox/deno on the far
// one.
//
//	root ──push P0──▶ a ──push P1──▶ b
//	     "GO\n"            delegate         Deno holds P1's flags and is the
//	     ◀── a's answer ── ◀── transcript ── only thing between b's agent and
//	                                         the network
//
// root's sandbox opens one stream to a and says GO. a's sandbox is the null
// one, which records P0 and enforces nothing; the agent on a has one tool,
// delegate, so the only thing it can reach is the peer named in its task. Its
// delegate opens a stream to b — which is the push of P1 — writes RUN and
// reads the far transcript back as the tool result. b's sandbox is
// attest/sandbox/deno, whose Apply is a Deno process under P1's permission
// flags.
//
// # Two things about this arrangement, said here because they are findings
//
// **Nothing enforces P1 ⊑ P0.** a's tunneld pushes whatever document it was
// configured with; no code on either side compares it with what root pushed at
// a. The containment below is by construction — two constants written to be
// contained — and making it a rule belongs to the policy track.
//
// **The workload starts at push time, not at request time.** Spike E4 had a
// harness that owned the Deno process's stdin and could carry RUN into it; the
// promoted package owns the process's stdio and exposes none of it, and the
// script starts on end of input, which is what a process the sandbox started
// gets. So the task on b begins when a's push is applied, before any stream
// exists, and the stream a opens carries only "give me the result". The
// alternatives were a socket or a file for the RUN line, and both would have
// needed a grant in P for the delegation channel itself — which is a finding
// either way and is recorded in the README rather than bought with a grant
// this run did not need.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/internal/fixture"
	"gvisor.dev/gvisor/attest/internal/snpfake"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/sandbox/deno"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The two variables that decide whether this test runs at all. It spends money
// on the model and needs a Deno on the machine, so it is off unless both say
// otherwise and `go test ./...` stays green and free.
const (
	liveEnv = "AGENT_PROBE_LIVE"
	denoEnv = "AGENT_PROBE_DENO"
)

// The policies, in the spellings attest/sandbox/deno reads: `n` entries carry
// a host because Deno checks the name a URL gives before it is resolved, `f`
// modes are a list because a set of modes is a set, and there is an `e`
// because (N, F, X) has no letter for the variable the agent's key is in.
const (
	// p0 is what root pushes to a: E1's resource list, narrowed to the two
	// destinations and the one file the task needs.
	p0 = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[],"e":[{"variable":"ANTHROPIC_API_KEY"}]}`

	// p1Same is case (i)'s P1. ⊑ is not ⊏: equal sets are applied, and using
	// the same document on both hops leaves case (ii) as the only case in
	// which P1 is strictly narrower than P0, which is the variable being
	// measured.
	p1Same = p0

	// p1Narrow is case (ii)'s P1: P0 without the tool's destination.
	p1Narrow = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[],"e":[{"variable":"ANTHROPIC_API_KEY"}]}`

	// p2Wider is case (iii)'s: case (i)'s set plus a host. A widening.
	p2Wider = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]},` +
		`{"host":"example.com","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[],"e":[{"variable":"ANTHROPIC_API_KEY"}]}`
)

// The three images and the TCB they run at. Every set here admits all three,
// because what this test is about begins after admission.
var (
	rootImage = bytes.Repeat([]byte{0x41}, 48)
	aImage    = bytes.Repeat([]byte{0x42}, 48)
	bImage    = bytes.Repeat([]byte{0x43}, 48)

	hopTCB    = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	hopPolicy = attest.GuestPolicy{AllowSMT: true}
)

func TestTwoHops(t *testing.T) {
	// The skip is first and reads two variables, so that a tree without them
	// pays nothing: no platform, no tunneld, no process.
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a Deno: set %s=1 and %s to the deno binary", liveEnv, denoEnv)
	}
	binary := os.Getenv(denoEnv)
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("%s=%q is not a Deno this test can start: %v", denoEnv, binary, err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatalf("%s=1 and no ANTHROPIC_API_KEY in the environment: the agents on a and b both need it", liveEnv)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	w := newWorld(t, ctx, out, binary)

	// (i) and (iii) are one arrangement: (iii) is a second pusher arriving at
	// the b of case (i) while its workload is still running, which is the only
	// way a widening can be provoked at all — a push is once per tunnel, so a
	// tunneld has no second push to make on a tunnel it already pushed on.
	first := w.run(t, "i", p0, p1Same, w.widen)
	if !strings.Contains(first.answer, "DONE") {
		t.Errorf("(i) root's answer does not contain the far agent's last word:\n%s", first.answer)
	}
	if first.a.ToolError {
		t.Errorf("(i) a's delegate came back as a tool error, and P1 grants everything the task needs")
	}
	if code, ended := first.b.box.Exited(); !ended || code != 0 {
		t.Errorf("(i) b's agent ended with status %d (ended=%v); want 0", code, ended)
	}

	// (ii) is a fresh three, because a policy is per sandbox and a push is per
	// tunnel: the same b cannot be asked to hold a second one.
	second := w.run(t, "ii", p0, p1Narrow, nil)
	// The denial is asserted where the ticket puts it — "visible to A as a tool
	// error, not a trust decision" — which is b's transcript and a's loop. It
	// is deliberately not asserted on what root read: a's model answered with
	// the far side's last word rather than with the transcript its task told it
	// to repeat, in both cases, and an assertion that root can see the denial
	// would be an assertion about a model's discretion. The line below records
	// what root did read instead.
	if !strings.Contains(second.far, "NotCapable") {
		t.Errorf("(ii) b was not denied the destination P1 leaves out; it said:\n%s", second.far)
	}
	if !second.a.ToolError {
		t.Errorf("(ii) a's delegate did not come back as a tool error, and the far side was denied a destination")
	}
	if second.openErr != nil {
		t.Errorf("(ii) a's Open to b returned %v; a denied resource on b is not a refusal of the hop", second.openErr)
	}
	for _, forbidden := range []string{"PolicyNotApplied", "refused", "verification refused"} {
		if strings.Contains(second.answer, forbidden) {
			t.Errorf("(ii) root's answer carries %q, which is a trust decision and not a tool error:\n%s", forbidden, second.answer)
		}
	}
	if refused := second.b.matching("REFUSAL"); len(refused) != 0 {
		t.Errorf("(ii) b's tunneld refused something: %v", refused)
	}
	out.logf("\nFINDING root read %q in case (i) and %q in case (ii). a's model was told to repeat the far transcript verbatim and answered with its last word instead, so the tool error — is_error=%v in case (ii) — is visible at a and stops there.",
		first.answer, second.answer, second.a.ToolError)
}

// ===== the world the three tunnelds are built in =====

// A hopWorld is what one case's tunnelds are made from: the reference value
// set they admit each other by, where the transcript goes, and the Deno this
// run starts.
type hopWorld struct {
	ctx    context.Context
	out    *record
	author fixture.Author
	set    string
	binary string
}

func newWorld(t *testing.T, ctx context.Context, out *record, binary string) *hopWorld {
	t.Helper()
	author := fixture.NewAuthor(t)
	var admits attest.ReferenceValueSet
	for _, image := range [][]byte{rootImage, aImage, bImage} {
		admits.Values = append(admits.Values, attest.ReferenceValue{
			LaunchMeasurement: image, MinimumTCB: hopTCB, GuestPolicy: hopPolicy,
		})
	}
	document, err := attest.MarshalReferenceValueSet(admits)
	if err != nil {
		t.Fatalf("marshalling the set all three are admitted by: %v", err)
	}
	path := filepath.Join(t.TempDir(), "reference-values.json")
	fixture.WriteSigned(t, path, document, author.Sign(t, string(document)))
	return &hopWorld{ctx: ctx, out: out, author: author, set: path, binary: binary}
}

// logf is one side's voice in the transcript.
func (w *hopWorld) logf(who string) func(string, ...any) {
	return func(format string, a ...any) { w.out.logf(who+"  "+format, a...) }
}

// start runs one tunneld on an ephemeral port, pushing push to every peer it
// dials. It is the loopback harness attest/tunneld's own tests start, written
// here because a helper in one package's _test.go files is not reachable from
// another's and this test has to live beside the loop it drives.
func (w *hopWorld) start(t *testing.T, name string, image []byte, peers tunneld.PeerTable, push string, refused func(*attest.Refusal)) *tunneld.Tunneld {
	t.Helper()
	p := fixture.SNPPlatform(t, snpfake.Config{LaunchMeasurement: image, TCB: hopTCB, Policy: hopPolicy})
	td, err := tunneld.New(w.ctx, tunneld.Config{
		SandboxID:             name,
		Acquirer:              p,
		Verifier:              fixture.VerifierTrusting(t, p),
		ReferenceValueSetPath: w.set,
		PolicyDigest:          sha256.Sum256([]byte("two hops: " + name)),
		AuthorPublicKey:       w.author.Public,
		Peers:                 peers,
		ListenAddr:            "127.0.0.1:0",
		PushPolicy:            []byte(push),
		RefusalLog: func(r *attest.Refusal) {
			w.out.logf("%s  REFUSAL %s", name, r.LogString())
			if refused != nil {
				refused(r)
			}
		},
	})
	if err != nil {
		t.Fatalf("tunneld.New(%s): %v", name, err)
	}
	t.Cleanup(func() { td.Close() })
	return td
}

// ===== b, the far side: a Deno process is what a policy means here =====

// A bSide is the far end of the second hop: its tunneld, the sandbox that
// turns a pushed policy into a Deno process, the file that process writes
// everything it says to, and the lines b's own console carried.
type bSide struct {
	name     string
	dir      string // the Deno process's working directory, which ./summary.txt is under
	log      string // where its stdout and stderr go, read once it has ended
	td       *tunneld.Tunneld
	box      *deno.Sandbox
	timed    *timedSandbox
	accepted chan struct{}

	// lineLog is b's console, and matching over it is which policies the
	// sandbox applied, which it refused and what its tunneld refused — all
	// assertions a case makes after the fact.
	lineLog
}

// startB brings up the far side and the goroutine that answers a's stream.
func (w *hopWorld) startB(t *testing.T, name string) *bSide {
	t.Helper()
	b := &bSide{name: name, dir: t.TempDir(), log: filepath.Join(t.TempDir(), "workload.log"), accepted: make(chan struct{}, 1)}
	// keep is b's console as evidence. The workload's own output does not come
	// through here: it goes to a file, because the sandbox hands its process's
	// stdout to whatever io.Writer it was configured with and an *os.File is the
	// one writer two goroutines and a child process can share without a lock.
	keep := func(format string, a ...any) { b.add(fmt.Sprintf(format, a...)) }
	b.td = w.start(t, "b-"+name, bImage, nil, "", func(r *attest.Refusal) { keep("REFUSAL %s", r.LogString()) })
	script, err := filepath.Abs("deno/agent.ts")
	if err != nil {
		t.Fatalf("the Deno agent's path: %v", err)
	}
	sink, err := os.Create(b.log)
	if err != nil {
		t.Fatalf("the file b's workload says everything to: %v", err)
	}
	t.Cleanup(func() { sink.Close() })
	say := w.logf("b-" + name)
	b.box = deno.New(b.td, deno.Config{
		Binary: w.binary,
		Script: script,
		Dir:    b.dir,
		Stdout: sink,
		Stderr: sink,
	}, func(format string, a ...any) {
		keep(format, a...)
		say(format, a...)
	})
	t.Cleanup(func() { b.box.Close() })
	b.timed = &timedSandbox{Sandbox: b.box, who: "b-" + name, out: w.out}
	b.td.Attach(b.timed)
	go w.serveB(b)
	return b
}

// serveB answers the stream a opens: one RUN line, and then everything the
// workload said once it has ended.
//
// The workload is not started here. It was started by Apply, which is what
// made a's Open return, so by the time this reads RUN the task is already
// under way — the stream asks for the result and does not ask for the work.
func (w *hopWorld) serveB(b *bSide) {
	say := w.logf("b-" + b.name)
	for {
		s, who, err := b.box.Accept(w.ctx)
		if err != nil {
			return
		}
		say("accepted a stream from peer=%q measurement=%s policy_digest=%s", who.Peer, who.Measurement, who.PolicyDigest)
		select {
		case b.accepted <- struct{}{}:
		default:
		}
		go func() {
			defer s.Close()
			line, err := bufio.NewReader(s).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "RUN" {
				fmt.Fprintf(s, "exit=-1\nTOOL_ERROR b: %q is not a request (%v)\n", strings.TrimSpace(line), err)
				s.CloseWrite()
				return
			}
			began := time.Now()
			select {
			case <-b.box.Done():
			case <-w.ctx.Done():
			}
			code, _ := b.box.Exited()
			say("the workload ended with status %d, %s after the RUN line arrived", code, time.Since(began).Round(time.Millisecond))
			said, err := os.ReadFile(b.log)
			if err != nil {
				said = []byte("TOOL_ERROR b: what the workload said could not be read: " + err.Error())
			}
			fmt.Fprintf(s, "exit=%d\n%s", code, said)
			s.CloseWrite()
		}()
	}
}

// ===== the push as the pushed side sees it =====

// timedSandbox is the wrapper the ticket's timings need: how long Apply took
// at the side the policy was pushed to, which is the push-and-ack number that
// the pusher's cold Open contains but does not separate.
type timedSandbox struct {
	sandbox.Sandbox
	who string
	out *record

	mu   sync.Mutex
	took []time.Duration
	errs []error
}

func (s *timedSandbox) Apply(ctx context.Context, policy []byte) error {
	return timeApply(ctx, s.Sandbox, policy, s.out, s.who, func(took time.Duration, err error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.took, s.errs = append(s.took, took), append(s.errs, err)
	})
}

// timeApply runs one Apply, says on who's behalf how long it took, and hands
// the number to note. Both wrappers this package puts around a sandbox are a
// clock on an Apply and differ only in where the number goes: here into a
// slice a case reads after the run, and in governed_test.go into the push it
// belongs to.
func timeApply(ctx context.Context, inner sandbox.Sandbox, policy []byte, out *record, who string, note func(time.Duration, error)) error {
	began := time.Now()
	err := inner.Apply(ctx, policy)
	took := time.Since(began)
	note(took, err)
	out.logf("%s  Apply returned after %s: %v", who, took.Round(time.Microsecond), err)
	return err
}

// first is how long the first Apply took, which is the one the hop waited for.
func (s *timedSandbox) first() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.took) == 0 {
		return 0
	}
	return s.took[0]
}

// ===== one case =====

// A hopOpen is what the delegate tool's one Open cost and whether it happened:
// the cold tunnel of the second hop, which contains the push of P1 and b's
// acknowledgement of it.
type hopOpen struct {
	took time.Duration
	err  error
}

// A hopResult is one case's evidence and its clock.
type hopResult struct {
	answer  string
	far     string
	a       Result
	b       *bSide
	openErr error
}

// run is one case end to end: three tunnelds, two pushes, one GO, one answer.
// while, when a case has one, runs as soon as b has accepted a's stream — which
// is the window in which b's workload is alive and a second pusher can be made
// to arrive.
func (w *hopWorld) run(t *testing.T, name, root, middle string, while func(*testing.T, *bSide)) hopResult {
	t.Helper()
	out := w.out
	out.logf("\n===== case (%s) =====", name)
	out.logf("P0 root -> a = %s", root)
	out.logf("P1 a    -> b = %s", middle)
	out.logf("nothing checks that P1 is contained in P0: a's tunneld pushes the document it was configured with, and the containment here is by construction")

	b := w.startB(t, name)
	aTd := w.start(t, "a-"+name, aImage, tunneld.PeerTable{"b": b.td.Addr().String()}, middle, nil)
	aBox := sandbox.NewNull(aTd, w.logf("a-"+name))
	aTimed := &timedSandbox{Sandbox: aBox, who: "a-" + name, out: out}
	aTd.Attach(aTimed)

	rootTd := w.start(t, "root-"+name, rootImage, tunneld.PeerTable{"a": aTd.Addr().String()}, root, nil)
	rootBox := sandbox.NewNull(rootTd, w.logf("root-"+name))

	// a's agent: one tool, and the peer it may reach is the one its task names.
	// Its own requests to the model go out of this process directly — the model
	// endpoint over the contract is what spike E2 measured, and what is being
	// measured here is the hop.
	hop := make(chan hopOpen, 4)
	answered := make(chan Result, 1)
	go w.serveA(b.name, aBox, Tools{Delegate: func(ctx context.Context, peer string) (sandbox.Stream, error) {
		began := time.Now()
		s, err := aBox.Open(ctx, peer)
		took := time.Since(began)
		out.logf("a-%s  Open(%q) returned after %s: err=%v", name, peer, took.Round(time.Millisecond), err)
		hop <- hopOpen{took, err}
		return s, err
	}}, answered)

	began := time.Now()
	s, err := rootBox.Open(w.ctx, "a")
	coldRootA := time.Since(began)
	if err != nil {
		t.Fatalf("(%s) root could not reach a: %v", name, err)
	}
	defer s.Close()
	out.logf("root-%s  Open(\"a\") returned after %s, which is the dial, both sides judging the other's evidence, the push of P0 and a's acknowledgement", name, coldRootA.Round(time.Millisecond))
	if _, err := io.WriteString(s, "GO\n"); err != nil {
		t.Fatalf("(%s) root could not say GO: %v", name, err)
	}
	s.CloseWrite()

	read := make(chan string, 1)
	go func() {
		body, err := io.ReadAll(s)
		if err != nil {
			out.logf("root-%s  reading a's answer: %v", name, err)
		}
		read <- string(body)
	}()

	// The meddler, if the case has one, and the promise that it is finished
	// before anything is asserted about it.
	finished, meddled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(meddled)
		select {
		case <-b.accepted:
			if while != nil {
				while(t, b)
			}
		case <-finished:
		case <-w.ctx.Done():
		}
	}()

	answer := <-read
	total := time.Since(began)
	close(finished)
	<-meddled

	res := <-answered
	var opened hopOpen
	select {
	case opened = <-hop:
	default:
	}

	said, err := os.ReadFile(b.log)
	if err != nil {
		t.Errorf("(%s) what b's workload said could not be read: %v", name, err)
	}
	far := string(said)
	out.logf("\nroot-%s  received %d bytes:\n%s", name, len(answer), answer)
	summary := filepath.Join(b.dir, "summary.txt")
	if info, err := os.Stat(summary); err == nil {
		out.logf("b-%s  %s is %d bytes, which is the f grant used", name, summary, info.Size())
	} else {
		out.logf("b-%s  %s was not written: %v", name, summary, err)
	}
	out.logf("\nb-%s  said, in full:\n%s", name, far)
	w.timings(name, coldRootA, aTimed.first(), opened.took, b.timed.first(), far, total)
	out.logf("TOKENS case=%s side=a input=%d output=%d cost=$%.6f calls=%v",
		name, res.InputTokens, res.OutputTokens, res.Cost, res.Calls)
	out.logf("TOKENS case=%s side=b %s %s", name, field(far, "totals: "), field(far, "cost: "))
	return hopResult{answer: answer, far: far, a: res, b: b, openErr: opened.err}
}

// timings is the ticket's "timings per hop": the cold tunnel at each dialer,
// the push and its acknowledgement as the pushed side saw it, when the far
// agent made its first tool call, and how long the whole of it took.
func (w *hopWorld) timings(name string, coldRootA, applyA, coldAB, applyB time.Duration, far string, total time.Duration) {
	w.out.logf("TIMING case=%s hop=root->a cold_open=%s push_ack=%s", name,
		coldRootA.Round(time.Millisecond), applyA.Round(time.Microsecond))
	w.out.logf("TIMING case=%s hop=a->b cold_open=%s push_ack=%s first_tool_call=%s agent_end_to_end=%s", name,
		coldAB.Round(time.Millisecond), applyB.Round(time.Microsecond),
		firstToolCall(far), field(far, "wall time: "))
	w.out.logf("TIMING case=%s total_root_to_answer=%s", name, total.Round(time.Millisecond))
}

// serveA is the middle: one stream in, the loop, and the model's last word
// back. What root gets is the agent's answer and nothing else — no exit
// status, no policy, no measurement — because the answer is the whole of what
// one agent owes another.
func (w *hopWorld) serveA(name string, box *sandbox.Null, tools Tools, answered chan<- Result) {
	say := w.logf("a-" + name)
	s, who, err := box.Accept(w.ctx)
	if err != nil {
		say("accepting root's stream: %v", err)
		answered <- Result{}
		return
	}
	defer s.Close()
	say("accepted a stream from peer=%q measurement=%s policy_digest=%s", who.Peer, who.Measurement, who.PolicyDigest)
	line, err := bufio.NewReader(s).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "GO" {
		fmt.Fprintf(s, "a: %q is not a request (%v)\n", strings.TrimSpace(line), err)
		s.CloseWrite()
		answered <- Result{}
		return
	}
	res, err := Run(w.ctx, &http.Client{}, Delegate("b"), tools, w.out)
	if err != nil {
		say("the agent failed: %v", err)
		fmt.Fprintf(s, "a: the agent failed: %v\n", err)
	} else {
		io.WriteString(s, res.Final)
	}
	s.CloseWrite()
	answered <- res
}

// ===== case (iii) =====

// widen is the third case: a second tunneld, pushing a policy that adds a host
// to the set b is already holding, arriving while b's workload is running.
//
// It cannot be a's second push. A push is once per tunnel — the book is keyed
// by the connection and Config.PushPolicy is one document fixed at New — so a
// widening is only reachable from a different pusher on a different tunnel,
// which is what spike E4 found and what this repeats on the promoted package.
func (w *hopWorld) widen(t *testing.T, b *bSide) {
	out := w.out
	out.logf("\n===== (iii) a second pusher widens, while b's agent is running =====")
	out.logf("P2 a2 -> b = %s", p2Wider)

	a2 := w.start(t, "a2-"+b.name, aImage, tunneld.PeerTable{"b": b.td.Addr().String()}, p2Wider, nil)
	box := sandbox.NewNull(a2, w.logf("a2-"+b.name))
	began := time.Now()
	s, err := box.Open(w.ctx, "b")
	took := time.Since(began)
	if err == nil {
		s.Close()
		t.Errorf("(iii) a2's Open succeeded; a widening push must take the tunnel with it")
		return
	}
	out.logf("a2-%s  Open returned after %s: %v", b.name, took.Round(time.Millisecond), err)
	out.logf("a2-%s  reason = %v (errors.Is ErrRefused: %v)", b.name, attest.ReasonOf(err), errors.Is(err, attest.ErrRefused))
	if attest.ReasonOf(err) != attest.ReasonPolicyNotApplied {
		t.Errorf("(iii) the reason is %v; want ReasonPolicyNotApplied", attest.ReasonOf(err))
	}

	// The workload the first push started is untouched: the sandbox refused
	// before it stopped anything, so the process is the same one and it is
	// still running.
	select {
	case <-b.box.Done():
		t.Errorf("(iii) b's Deno process has ended; the refusal was supposed to leave it alone")
	default:
		out.logf("b-%s  the process the first push started is still running: Done is not closed", b.name)
	}
	if applied := b.matching("SANDBOX deno applied"); len(applied) != 1 {
		t.Errorf("(iii) b started %d processes; want the one the first push started: %v", len(applied), applied)
	} else {
		out.logf("b-%s  the one process this sandbox ever started: %s", b.name, applied[0])
	}
	refusals := b.matching("SANDBOX deno refused")
	if len(refusals) != 1 || !strings.Contains(refusals[0], "widens") {
		t.Errorf("(iii) b's sandbox log does not say the policy widened: %v", refusals)
	} else {
		out.logf("b-%s  %s", b.name, refusals[0])
	}
}

// ===== reading the far transcript =====

// field is the rest of the first line of text that begins with prefix, which
// is how the numbers the Deno agent printed for itself — its totals, its cost,
// its wall time — are read back without a second format to keep in step.
func field(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(prefix)); ok {
			return strings.TrimSpace(rest)
		}
	}
	return "unknown"
}

// firstToolCall is when the far agent made its first tool call, as the far
// agent stamped it: milliseconds from the start of the Deno runtime, which is
// the exec plus whatever the runtime spends before the script's first line.
func firstToolCall(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// A stop_reason line says tool_use too, and it is not a call: the
		// stamp is what tells the two apart, because only a call has one.
		if !strings.HasPrefix(line, "t=") || !strings.Contains(line, " tool_use ") {
			continue
		}
		if stamp, _, ok := strings.Cut(strings.TrimPrefix(line, "t="), " "); ok {
			return stamp
		}
	}
	return "unknown"
}
