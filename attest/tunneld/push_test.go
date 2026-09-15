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
	"encoding/json"
	"errors"
	"io"
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
	// about what may happen while it is answering.
	takes time.Duration

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
	s.applied.record(string(policy))
	s.events.record("applied")
	return s.refusal
}

// eventLog is what one side did, in order: the policies a sandbox was handed,
// or the things a peer's tunneld did around them. A nil log records nothing, so
// a test that is not about ordering wires none.
//
// It is read as a count and as one string rather than as a slice, because those
// are the two questions an assertion asks of an order and the second prints
// legibly when it fails.
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

func (l *eventLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.in)
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
	box      *recordingSandbox
}

// startPushNode starts a tunneld with a recording sandbox attached to it, which
// is what makes it a tunneld a policy can be pushed to at all. A nil sandbox is
// a tunneld with none attached, which is one of the ways a push does not land.
func startPushNode(t *testing.T, name string, image []byte, admits attest.ReferenceValueSet, box *recordingSandbox) *pushNode {
	t.Helper()
	refusals := newRefusalRecorder()
	n := start(t, name, image, admits, nil, func(cfg *tunneld.Config) { cfg.RefusalLog = refusals.record })
	if box != nil {
		n.Attach(box)
	}
	return &pushNode{node: n, refusals: refusals, box: box}
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
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), &recordingSandbox{})
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()

	if answer := pushed(t, ch, policyV1); !answer.OK {
		t.Fatalf("the push was refused: %q", answer.Reason)
	}
	if got := b.box.applied.order(); got != policyV1 {
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

// TestAPushTheSandboxRefusesClosesTheTunnel is every way a push fails to land,
// and the one thing all three do: the refusal goes back, the reason is logged,
// and the tunnel goes with it. A peer whose policy did not land is a peer whose
// next stream would run under a contract neither side holds.
func TestAPushTheSandboxRefusesClosesTheTunnel(t *testing.T) {
	for _, c := range []struct {
		name    string
		box     *recordingSandbox
		policy  string
		says    string
		applied int
	}{
		{
			name:    "the sandbox will not take it",
			box:     &recordingSandbox{refusal: errors.New("this sandbox will not run that")},
			policy:  policyV1,
			says:    "the sandbox beside this tunneld did not apply it",
			applied: 1,
		},
		{
			// Refused at the boundary, so that an acknowledgement means a
			// sandbox with that policy on every implementation of the contract.
			name:    "the version is not one this tunneld reads",
			box:     &recordingSandbox{},
			policy:  policyV2,
			says:    "this tunneld does not read a policy of that format and version",
			applied: 0,
		},
		{
			// An acknowledgement means a sandbox has the policy, and there is
			// no sandbox.
			name:   "no sandbox is attached",
			policy: policyV1,
			says:   "no sandbox is attached to this tunneld",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
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
			if c.box != nil && c.box.applied.count() != c.applied {
				t.Errorf("the sandbox was handed %d policies; want %d", c.box.applied.count(), c.applied)
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
		})
	}
}
