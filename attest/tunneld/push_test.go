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

// The policy push over the loopback harness (ticket 22, docs/policy-push.md).
//
// These are the same two tunnelds every test in this package runs, with the
// fake platform injected through Config. What is asserted is external
// behaviour: the document that came back on the wire, what the sandbox beside
// the receiving tunneld was handed, what its operator log says, and whether the
// tunnel survived.
//
// The receiving half is driven here by an ordinary exchange carrying the policy
// bytes, because that is exactly what a push is — one framed exchange, told
// from an application one by the format of the document it carries. The
// delegator's half, which makes that exchange before it hands out a stream, is
// below.

package tunneld_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
	"gvisor.dev/gvisor/attest/tunneld"
)

// ack is the acknowledgement as a peer reads it off the wire. It is declared
// here rather than taken from package tunneld because what these tests assert
// on is the bytes that crossed, not the type that wrote them.
type ack struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Reason  string `json:"reason"`
}

// recordingSandbox is the sandbox beside a tunneld in these tests: it records
// every policy pushed at it, in the order they arrived, and refuses when it is
// told to.
//
// It answers no stream. What a push test needs from a sandbox is Apply, and one
// that opened and accepted streams too would be [sandbox.Null] under another
// name — which the contract's own tests already drive (sandbox_test.go).
type recordingSandbox struct {
	// refusal, when set, is what Apply returns after recording the push. A
	// sandbox that refuses still records: "the delegator re-dialed and pushed
	// again" is a claim about attempts, not about acknowledgements.
	refusal error

	// takes is how long Apply spends before it answers, for the tests that are
	// about what may happen while it is answering; holds, when set, is a
	// sandbox that never answers at all until the test closes it.
	takes time.Duration
	holds chan struct{}

	// applied is every policy this sandbox was handed, in order, and events —
	// when a test wires one — is the log where "applied" is written beside
	// whatever else that side did.
	applied eventLog
	events  *eventLog
}

var _ sandbox.Sandbox = (*recordingSandbox)(nil)

func (s *recordingSandbox) Open(context.Context, string) (sandbox.Stream, error) {
	return nil, errors.New("this sandbox opens nothing")
}

func (s *recordingSandbox) Accept(context.Context) (sandbox.Stream, sandbox.Attested, error) {
	return nil, sandbox.Attested{}, errors.New("this sandbox accepts nothing")
}

func (s *recordingSandbox) Apply(_ context.Context, policy []byte) error {
	if s.takes > 0 {
		time.Sleep(s.takes)
	}
	if s.holds != nil {
		<-s.holds
	}
	s.applied.record(string(policy))
	s.events.record("applied")
	return s.refusal
}

// eventLog is what one side did, in order: the policies a sandbox was handed,
// or the things a peer's tunneld did around them. A nil log records nothing, so
// a test that is not about ordering wires none.
//
// It is read as one string rather than as a slice or a count, because every
// question these tests ask of an order — did this happen before that, was this
// pushed once or twice or not at all — is answered by the whole of it, and a
// failure then prints what happened instead of how many things did.
type eventLog struct {
	mu sync.Mutex
	in []string
}

func (l *eventLog) record(what string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.in = append(l.in, what)
	l.mu.Unlock()
}

func (l *eventLog) order() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.in, ", ")
}

// pushNode is one tunneld in a push test: the node the rest of this package
// starts, with its operator log captured and the sandbox beside it in reach.
type pushNode struct {
	*node
	refusals *refusalRecorder
}

// startPushNode starts a tunneld with a recording sandbox beside it and its
// operator log captured, which is what makes it a tunneld a policy can be
// pushed to and a refusal read off. A nil sandbox is a tunneld with none
// attached, which is one of the ways a push does not land — and is why the
// check is here rather than at a call site, since a typed nil is a sandbox as
// far as an interface is concerned.
func startPushNode(t *testing.T, name string, image []byte, admits attest.ReferenceValueSet, box *recordingSandbox, adjust ...func(*tunneld.Config)) *pushNode {
	t.Helper()
	refusals := newRefusalRecorder()
	hands := append([]func(*tunneld.Config){func(cfg *tunneld.Config) { cfg.RefusalLog = refusals.record }}, adjust...)
	n := start(t, name, image, admits, nil, hands...)
	if box != nil {
		n.Attach(box)
	}
	return &pushNode{node: n, refusals: refusals}
}

// toward is the peer table of a tunneld that knows one peer: that name, at that
// node's address.
func toward(name string, n *pushNode) func(*tunneld.Config) {
	return func(cfg *tunneld.Config) { cfg.Peers = tunneld.PeerTable{name: n.Addr().String()} }
}

// pushing is the configuration a delegator is started with: the policy it
// pushes to every peer it dials.
func pushing(policy string) func(*tunneld.Config) {
	return func(cfg *tunneld.Config) { cfg.PushPolicy = []byte(policy) }
}

// pushed sends the policy bytes as the plain exchange a push is, and returns
// the acknowledgement that came back.
func pushed(t *testing.T, ch *tunneld.Channel, policy string) ack {
	t.Helper()
	response, err := ch.Exchange(ctx(t), []byte(policy))
	if err != nil {
		t.Fatalf("pushing %s: %v", policy, err)
	}
	var a ack
	if err := json.Unmarshal(response, &a); err != nil {
		t.Fatalf("the acknowledgement is not a JSON object: %q: %v", response, err)
	}
	if a.Format != "policy-ack" || a.Version != 1 {
		t.Errorf("the acknowledgement is %q; want format policy-ack version 1", response)
	}
	return a
}

// endsWithin reports the error a stream ended with, or nil if it is still open.
// It is how a test sees a tunnel closed underneath it: the stream on it stops.
func endsWithin(t *testing.T, s *tunnel.Stream, d time.Duration) error {
	t.Helper()
	ended := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(s)
		ended <- err
	}()
	select {
	case err := <-ended:
		if err == nil {
			return io.EOF
		}
		return err
	case <-time.After(d):
		return nil
	}
}

// TestAPushedPolicyReachesTheSandboxAndIsAcknowledged is the receiving half:
// a request that says it is a policy goes to the sandbox and not to the
// application handler, and the answer says the sandbox has it.
func TestAPushedPolicyReachesTheSandboxAndIsAcknowledged(t *testing.T) {
	box := &recordingSandbox{}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), box)
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()

	if answer := pushed(t, ch, policyV1); !answer.OK {
		t.Fatalf("the push was refused: %q", answer.Reason)
	}
	if got := box.applied.order(); got != policyV1 {
		t.Errorf("the sandbox was handed %q; want exactly the pushed bytes", got)
	}
	if b.served.Load() != 0 {
		t.Errorf("b's application handler answered %d exchanges; a push is not one", b.served.Load())
	}
	if logged := b.refusals.none(); len(logged) != 0 {
		t.Errorf("b refused something: %s", logged[0].LogString())
	}

	// And the exchange the push did not replace: an ordinary request on the
	// same tunnel still reaches the handler.
	echoed, err := ch.Exchange(ctx(t), []byte("still framed"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if want := "sandbox-b:still framed"; string(echoed) != want {
		t.Errorf("exchange returned %q; want %q", echoed, want)
	}
	if b.served.Load() != 1 {
		t.Errorf("b's handler answered %d exchanges; want 1", b.served.Load())
	}
}

// A pushRefusalCase is one way a pushed policy fails to land: the sandbox
// beside the receiving tunneld, the policy sent, what the refusal must say,
// and what (if anything) the sandbox was handed.
type pushRefusalCase struct {
	name    string
	box     *recordingSandbox
	policy  string
	says    string
	applied string
}

// TestAPushTheSandboxRefusesClosesTheTunnel is every way a push fails to land,
// and the one thing all three do: the refusal goes back, the reason is logged,
// and the tunnel goes with it. A peer whose policy did not land is a peer whose
// next stream would run under a contract neither side holds.
func TestAPushTheSandboxRefusesClosesTheTunnel(t *testing.T) {
	for _, c := range []pushRefusalCase{
		{
			name:    "the sandbox will not take it",
			box:     &recordingSandbox{refusal: errors.New("this sandbox will not run that")},
			policy:  policyV1,
			says:    "the sandbox beside this tunneld did not apply it",
			applied: policyV1,
		},
		{
			// Refused at the boundary, so that an acknowledgement means a
			// sandbox with that policy on every implementation of the contract.
			name:   "the version is not one this tunneld reads",
			box:    &recordingSandbox{},
			policy: policyV2,
			says:   "this tunneld does not read a policy of that format and version",
		},
		{
			// An acknowledgement means a sandbox has the policy, and there is
			// no sandbox.
			name:   "no sandbox is attached",
			policy: policyV1,
			says:   "no sandbox is attached to this tunneld",
		},
	} {
		t.Run(c.name, func(t *testing.T) { runPushRefusalCase(t, c) })
	}
}

// runPushRefusalCase drives one pushRefusalCase: it starts the pair, pushes
// the case's policy over a tunnel that already carries a stream, and checks
// that the refusal, the sandbox, the operator log, and the tunnel itself all
// agree the policy did not land.
func runPushRefusalCase(t *testing.T, c pushRefusalCase) {
	t.Helper()
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), c.box)
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})
	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	// A stream on the tunnel before the push, so that the test can see
	// the tunnel end rather than infer it from a channel that would
	// quietly re-dial.
	stream, err := ch.OpenStream(ctx(t))
	if err != nil {
		t.Fatalf("opening a stream: %v", err)
	}
	defer stream.Close()

	answer := pushed(t, ch, c.policy)
	if answer.OK {
		t.Fatalf("the push was acknowledged")
	}
	if answer.Reason != c.says {
		t.Errorf("the refusal says %q; want %q", answer.Reason, c.says)
	}
	if c.box != nil && c.box.applied.order() != c.applied {
		t.Errorf("the sandbox was handed %q; want %q", c.box.applied.order(), c.applied)
	}
	r := b.refusals.next(t)
	if got := r.Reason(); got != attest.ReasonPolicyNotApplied {
		t.Errorf("b refused with %v; want %v (log: %s)", got, attest.ReasonPolicyNotApplied, r.LogString())
	}
	if line := r.LogString(); !strings.Contains(line, attest.ReasonPolicyNotApplied.String()) {
		t.Errorf("the operator log does not name the reason: %q", line)
	}
	if err := endsWithin(t, stream, 5*time.Second); err == nil {
		t.Errorf("the tunnel survived a refused push")
	}
}

// The delegator's half. Everything below starts A with a policy to push and
// asks it for a peer: what is asserted is what B was handed, in what order, and
// what A was told when B would not take it.

// TestNoStreamIsHandedOutBeforeThePushIsAcknowledged is the push at its
// ordinary size: A opens to B, B's null sandbox takes the policy, and only then
// does A hold a stream.
//
// The null sandbox is the one under test here rather than this file's recording
// one, because the line it writes is half the claim: the digest on B's console
// is the digest of the bytes A sent, or the push carried something else.
func TestNoStreamIsHandedOutBeforeThePushIsAcknowledged(t *testing.T) {
	console := &eventLog{}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), nil)
	b.Attach(sandbox.NewNull(b.Tunneld, func(format string, args ...any) {
		console.record(fmt.Sprintf(format, args...))
	}))
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))

	stream, err := a.Open(ctx(t), "b")
	if err != nil {
		t.Fatalf("opening a stream to b: %v", err)
	}
	defer stream.Close()

	sum := sha256.Sum256([]byte(policyV1))
	want := fmt.Sprintf("SANDBOX applied format=policy version=1 bytes=%d sha256=%s", len(policyV1), hex.EncodeToString(sum[:]))
	if got := console.order(); got != want {
		t.Errorf("b's console says\n %s\nwant\n %s", got, want)
	}
	if logged := b.refusals.none(); len(logged) != 0 {
		t.Errorf("b refused something: %s", logged[0].LogString())
	}
}

// TestAPeerThatWillNotApplyThePolicyIsRefused is every way a push can fail to
// land, from the delegator's side: no stream, the tenth reason, the tunnel
// closed, and a next attempt that dials and pushes afresh rather than
// inheriting the verdict.
func TestAPeerThatWillNotApplyThePolicyIsRefused(t *testing.T) {
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })

	for _, c := range []struct {
		name    string
		box     *recordingSandbox
		policy  string
		timeout time.Duration
		applied string
	}{
		{
			name: "the sandbox refuses it",
			box:  &recordingSandbox{refusal: errors.New("this sandbox will not run that")},
			// Pushed twice: the tunnel the first refusal closed is not the
			// tunnel the second attempt dials.
			policy:  policyV1,
			applied: policyV1 + ", " + policyV1,
		},
		{
			// Refused by B's tunneld before its sandbox is woken, which is why
			// the sandbox is handed nothing at all.
			name:   "the version is not one the peer reads",
			box:    &recordingSandbox{},
			policy: policyV2,
		},
		{
			// A sandbox that never answers is a push that is never
			// acknowledged, and an acknowledgement that has not arrived is not
			// one that might still.
			name:    "nobody acknowledges it",
			box:     &recordingSandbox{holds: never},
			policy:  policyV1,
			timeout: 250 * time.Millisecond,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), c.box)
			a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil,
				toward("b", b), pushing(c.policy), func(cfg *tunneld.Config) { cfg.PushTimeout = c.timeout })

			stream, err := a.Open(ctx(t), "b")
			if err == nil {
				stream.Close()
				t.Fatalf("a stream was handed out over a policy that was not applied")
			}
			if got := attest.ReasonOf(err); got != attest.ReasonPolicyNotApplied {
				t.Errorf("a's caller was told %v (%v); want %v", got, err, attest.ReasonPolicyNotApplied)
			}
			if r := a.refusals.next(t); r.Reason() != attest.ReasonPolicyNotApplied {
				t.Errorf("a logged %s; want the push refused", r.LogString())
			}

			// The tunnel went, so the next ask is a new handshake and a new
			// push rather than the same verdict handed out again.
			if _, err := a.Open(ctx(t), "b"); attest.ReasonOf(err) != attest.ReasonPolicyNotApplied {
				t.Errorf("the second open returned %v; want the push refused again", err)
			}
			// What the sandbox was handed over both attempts: the policy
			// twice where it refused it, and nothing at all where its tunneld
			// refused the document before waking it.
			if c.applied != "" && c.box.applied.order() != c.applied {
				t.Errorf("b's sandbox was handed %q; want %q — the second attempt must push again", c.box.applied.order(), c.applied)
			}
			if c.policy == policyV2 && c.box.applied.order() != "" {
				t.Errorf("b's sandbox was handed %q; a version its tunneld does not read must not reach it", c.box.applied.order())
			}
		})
	}
}

// TestNothingReachesAPeerBeforeItsSandboxAppliedThePolicy is the ordering, read
// off the side that would see it broken: B records what it was asked to do, and
// the policy is the first line whatever A does next.
func TestNothingReachesAPeerBeforeItsSandboxAppliedThePolicy(t *testing.T) {
	events := &eventLog{}
	box := &recordingSandbox{takes: 100 * time.Millisecond, events: events}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), box, func(cfg *tunneld.Config) {
		cfg.Handler = func(context.Context, []byte) ([]byte, error) {
			events.record("exchange")
			return []byte("sandbox-b:"), nil
		}
	})
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))

	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		stream, _, err := b.Accept(ctx(t))
		if err != nil {
			return
		}
		events.record("stream")
		stream.Close()
	}()

	channel, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer channel.Close()
	if _, err := channel.Exchange(ctx(t), []byte("hello")); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	stream, err := channel.OpenStream(ctx(t))
	if err != nil {
		t.Fatalf("opening a stream: %v", err)
	}
	defer stream.Close()
	<-accepted

	if got, want := events.order(), "applied, exchange, stream"; got != want {
		t.Errorf("b saw %q; want %q — nothing may reach it before the policy did", got, want)
	}
	// And one push for one tunnel, however many times it is asked for: the
	// exchange and the stream above already ran over the tunnel the first ask
	// established.
	if got := box.applied.order(); got != policyV1 {
		t.Errorf("b's sandbox was handed %q; want the policy once — one tunnel is one push", got)
	}
}

// TestAFreshTunnelIsPushedToAgain: the push is per tunnel and not per peer, so
// a tunnel that reached its maximum age and was re-attested carries the policy
// again. A re-attested peer is a peer judged afresh, and a policy applied by
// the tunnel before it is not a fact about this one.
func TestAFreshTunnelIsPushedToAgain(t *testing.T) {
	box := &recordingSandbox{}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), box)
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil,
		toward("b", b), pushing(policyV1), func(cfg *tunneld.Config) {
			cfg.Limits = tunneld.Limits{IdleTimeout: 30 * time.Second, MaxAge: 200 * time.Millisecond}
		})

	for i := 0; i < 2; i++ {
		stream, err := a.Open(ctx(t), "b")
		if err != nil {
			t.Fatalf("opening a stream to b: %v", err)
		}
		stream.Close()
		time.Sleep(250 * time.Millisecond)
	}
	if want := policyV1 + ", " + policyV1; box.applied.order() != want {
		t.Errorf("b's sandbox was handed %q over two tunnels; want %q", box.applied.order(), want)
	}
}

// TestConcurrentOpensShareOnePush: several callers arriving on a fresh tunnel
// make one push between them and all wait for it. A second push would be a
// second policy in flight beside the first, and a caller that did not wait
// would be the stream this design says cannot exist.
func TestConcurrentOpensShareOnePush(t *testing.T) {
	box := &recordingSandbox{takes: 100 * time.Millisecond}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), box)
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := a.Open(ctx(t), "b")
			if err == nil {
				stream.Close()
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if got := box.applied.order(); got != policyV1 {
		t.Errorf("b's sandbox was handed %q; want the policy once — one tunnel is one push", got)
	}
}

// TestAPushBeforeAdmissionIsImpossible is the construction, asserted.
//
// There is no moment at which a push could precede admission: a push is an
// exchange on a tunnel, a tunnel exists only where Dial established one, and
// Dial returns after the QUIC handshake in which ratls judged the peer (spike
// E2, "A push before admission", with the file and line of every step). So a
// peer that refuses this side is a peer this side never pushes to, and what its
// caller is told is that the tunnel was not established — not that a policy was
// not applied, which would be a claim about a peer nobody reached.
//
// The other half of the construction is the manufactured channel, which
// TestAChannelNoTunneldMadeRefusesRatherThanPanicking (sandbox_test.go) covers:
// &Channel{} reaches no peer and refuses rather than dereferencing the tunneld
// it has not got.
func TestAPushBeforeAdmissionIsImpossible(t *testing.T) {
	// b's set does not admit a's image, so b aborts the handshake.
	box := &recordingSandbox{}
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageNone), box)
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))

	stream, err := a.Open(ctx(t), "b")
	if err == nil {
		stream.Close()
		t.Fatalf("a stream was handed out to a peer that refused this side")
	}
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Errorf("a's caller was told %v; want ErrNotEstablished", err)
	}
	if got := attest.ReasonOf(err); got != attest.ReasonNone {
		t.Errorf("a's caller was told %v; a peer that was never admitted cannot have failed to apply a policy", got)
	}
	if got := box.applied.order(); got != "" {
		t.Errorf("b's sandbox was handed %q over a tunnel that was never established", got)
	}
	if b.served.Load() != 0 {
		t.Errorf("b answered %d exchanges over a refused tunnel", b.served.Load())
	}
}

// TestAPushReachesASandboxInAnotherProcess: the push crosses the local contract
// too, and the sandbox that answers it is the one attached over the unix socket
// rather than anything in this tunneld's process.
//
// It is the composition the command makes when it is given -sandbox-socket
// (attest/cmd/tunneld/nullsandbox.go): tunneld attaches the [sandbox.Host], the
// host sends APPLY down the socket, and the acknowledgement that goes back onto
// the tunnel is the attached sandbox's. The client is dialed in this process
// because what is under test is the boundary rather than the fork —
// attest/sandbox/socket_test.go re-executes the test binary for that.
func TestAPushReachesASandboxInAnotherProcess(t *testing.T) {
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), nil)
	host, err := sandbox.Listen(filepath.Join(t.TempDir(), "sandbox.sock"), b.Tunneld, nil)
	if err != nil {
		t.Fatalf("listening for a sandbox: %v", err)
	}
	defer host.Close()
	b.Attach(host)

	applied := &eventLog{}
	client, err := sandbox.Dial(host.Path(), sandbox.RoleEnforcing, func(_ context.Context, policy []byte) error {
		applied.record(string(policy))
		return nil
	})
	if err != nil {
		t.Fatalf("attaching a sandbox: %v", err)
	}
	defer client.Close()
	for host.Attached() == 0 {
		time.Sleep(time.Millisecond)
	}

	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))
	stream, err := a.Open(ctx(t), "b")
	if err != nil {
		t.Fatalf("opening a stream to b: %v", err)
	}
	defer stream.Close()

	if got := applied.order(); got != policyV1 {
		t.Errorf("the sandbox in the other process was handed %q; want the pushed bytes", got)
	}
}
