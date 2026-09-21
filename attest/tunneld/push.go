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

package tunneld

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
)

// The policy push (ticket 22, docs/policy-push.md).
//
// After a tunnel is established — which is to say after both sides have judged
// the other's evidence — the delegator sends the policy it is delegating under,
// and the peer's tunneld hands it to the sandbox beside it and answers. This
// file is both halves of that: what a received push does here, and what a push
// this tunneld makes waits for.
//
// # It is an ordinary exchange
//
// A push is one framed [tunnel.Conn.Exchange] whose request is the policy bytes
// and whose response is the acknowledgement. Nothing was added to the wire for
// it and nothing needed to be (spike E2): one stream is one exchange already,
// the framing refuses trailing bytes already, and a push is told from an
// application exchange by the `format` field of the document it carries. An
// exchange that is not a policy is byte-identical to what it was before this
// file existed, and reaches the handler it always reached.
//
// # Why the policy carries no signature
//
// Because it is trusted for having arrived here, and for nothing else. The
// tunnel it came over exists only because this side judged the peer's evidence
// against its own reference value set and the peer judged this side's; a
// signature on the document would be the peer's operator saying a second time
// what the peer's measurement already said, in a document that cannot be about
// this exchange. What is deliberately *not* claimed is that a pushed policy is
// measured: it is in nobody's launch measurement and a verifier reading the
// peer's image cannot see it. What that image does carry is the egress ceiling
// compiled into it (attest/ceiling), which is the bound a push cannot widen.
//
// # What tunneld reads of it
//
// Two fields, `format` and `version`, and never `n`, `f` or `x`
// ([sandbox.ReadEnvelope]). A tunneld that parsed a policy would be a second
// implementation of whatever a policy means, in the one process that has no
// business holding an opinion about it.

// The acknowledgement. It is its own format because it is its own document: an
// application response that happened to be JSON, or a peer that echoed the
// policy back, must not read as an acknowledgement.
//
// The version is this side's, always, and not the pushed policy's. It says
// which reader wrote the answer, so a refusal of an unknown version is still an
// answer the pusher can read.
const (
	ackFormat  = "policy-ack"
	ackVersion = sandbox.PolicyVersion
)

// The sentences a refusal carries back. They are fixed, and they say what a
// pushing peer needs in order to act: whether the document is one this tunneld
// reads at all, whether there is a sandbox here to read it, and whether that
// sandbox took it.
//
// What stays here is the detail — which field, which version, which sandbox and
// which socket — because that is a fact about this guest, and the peer supplied
// the document rather than the machine. It reaches the operator through the
// refusal log, which is where every other reason in the taxonomy surfaces too.
const (
	ackUnreadable = "this tunneld does not read a policy of that format and version"
	ackNoSandbox  = "no sandbox is attached to this tunneld"
	ackRefused    = "the sandbox beside this tunneld did not apply it"
)

// pushRefusalGrace is how long a refused push's tunnel stays up after the
// refusal has been written.
//
// [tunnel.Conn.Serve] sends a handler's answer after the handler returns, so a
// connection closed inside the handler would take the answer with it and the
// peer would learn only that its tunnel died. Nothing rests on the grace being
// long enough: a pusher that gets no answer refuses its own push for the same
// reason and closes its side too. It is short because the tunnel is already
// carrying something neither side agrees on.
const pushRefusalGrace = 100 * time.Millisecond

// A policyAck is the whole of what a push brings back: whether the sandbox at
// the far end has the policy, and if not, this side's sentence about why.
type policyAck struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
}

// Attach names the sandbox this tunneld hands a pushed policy to, and is how a
// push reaches a sandbox at all. A tunneld with nothing attached refuses every
// push rather than acknowledging one nobody applied — an acknowledgement means
// a sandbox has the policy, and there is no sandbox.
//
// Whatever it is given is wrapped in [PolicyChecked], so that the envelope is
// read at this boundary whichever sandbox is beside this tunneld: the null one
// in this process, or a [sandbox.Host] with another process behind it.
//
// It is a method rather than a field on [Config] because a sandbox is built
// around the tunneld it speaks through — [sandbox.NewNull] and [sandbox.Listen]
// both take the [sandbox.Network] this tunneld is — so neither can exist before
// New has returned. A push that arrives in the window between the two is
// refused, which is the honest answer rather than an unlucky one.
func (t *Tunneld) Attach(box sandbox.Sandbox) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.livenessMu.Lock()
	if t.livenessCancel != nil {
		t.livenessCancel()
		t.livenessCancel = nil
	}
	t.livenessMu.Unlock()
	if box == nil {
		t.box = nil
		return
	}
	t.box = PolicyChecked(box)
}

// attached is the sandbox beside this tunneld, or nil while there is none.
func (t *Tunneld) attached() sandbox.Sandbox {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.box
}

// handleFor is the handler one accepted tunnel is served with: a policy push
// goes to the sandbox beside this tunneld and everything else goes to the
// application handler, exactly as before.
//
// It closes over the connection because a refused push ends that tunnel, and a
// handler is otherwise told nothing about which one it is answering on.
func (t *Tunneld) handleFor(conn *tunnel.Conn) Handler {
	return func(ctx context.Context, request []byte) ([]byte, error) {
		if addressedToTheSandbox(request) {
			return t.applyPushed(ctx, conn, request)
		}
		return t.handle(ctx, request)
	}
}

// addressedToTheSandbox reports whether a request is a policy push rather than
// an exchange for the application handler.
//
// It is the format field and nothing else. The version is deliberately not part
// of the question: a push whose version this side does not speak is still a
// push, and answering it with a refusal is the difference between a peer that
// learns its policy did not land and a peer whose policy was quietly echoed
// back to it by an application handler.
func addressedToTheSandbox(request []byte) bool {
	var e sandbox.Envelope
	if err := json.Unmarshal(request, &e); err != nil {
		return false
	}
	return e.Format == sandbox.PolicyFormat
}

// applyPushed is the receiving half: the policy goes to the sandbox beside this
// tunneld, and the answer says whether the sandbox has it.
//
// One sentence decides both fields of the answer, because they are one fact: an
// acknowledgement is the absence of a reason to refuse.
func (t *Tunneld) applyPushed(ctx context.Context, conn *tunnel.Conn, policy []byte) ([]byte, error) {
	sentence := t.applyOrRefuse(ctx, conn, policy)
	return json.Marshal(policyAck{Format: ackFormat, Version: ackVersion, OK: sentence == "", Reason: sentence})
}

// applyOrRefuse hands the policy to the sandbox and returns the sentence that
// goes back to the peer, or "" if the sandbox has it.
//
// The envelope is read here and again inside the sandbox [Attach] wrapped, and
// both readings earn their keep: this one chooses which sentence the peer is
// sent, and the one behind [PolicyChecked] is the guarantee that no sandbox is
// ever woken for a document tunneld could not read, which holds however this
// function is later rewritten.
func (t *Tunneld) applyOrRefuse(ctx context.Context, conn *tunnel.Conn, policy []byte) string {
	if _, err := sandbox.ReadEnvelope(policy); err != nil {
		return t.refusePush(conn, ackUnreadable, err)
	}
	box := t.attached()
	if box == nil {
		return t.refusePush(conn, ackNoSandbox, errors.New("no sandbox is beside this tunneld"))
	}
	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, t.cfg.PushTimeout)
		defer cancel()
	}
	if err := box.Apply(waitCtx, policy); err != nil {
		// Which of the two sentences the peer is told is the difference between
		// "there is nobody here to take it" and "the sandbox here would not
		// have it", and the sandbox says which by the sentinel it wraps.
		sentence := ackRefused
		if errors.Is(err, sandbox.ErrNoEnforcingSandbox) {
			sentence = ackNoSandbox
		}
		return t.refusePush(conn, sentence, err)
	}
	t.watchPolicy(conn, box, policy)
	return ""
}

// watchPolicy starts watching whether the sandbox goes on enforcing what this
// peer just pushed, when the sandbox is one that says (contract v3).
//
// A sandbox in this tunneld's own process is not watched, and there is nothing
// to watch: [sandbox.Null] is this process, and a caller asking whether it is
// still running has been answered by the fact that it asked. Only
// [sandbox.Host] implements the interface, because only a process boundary
// raises the question.
//
// The digest is over the bytes this side received, which is the number the
// pusher computed over the bytes it sent and the number the sandbox pulses
// back. Three numbers, one comparison, and no field on the wire for any of it.
func (t *Tunneld) watchPolicy(conn *tunnel.Conn, box sandbox.Sandbox, policy []byte) {
	live, ok := box.(sandbox.Live)
	if !ok {
		return
	}
	sum := sha256.Sum256(policy)
	digest := hex.EncodeToString(sum[:])

	t.livenessMu.Lock()
	if t.livenessCancel != nil {
		t.livenessCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.livenessCancel = cancel
	t.livenessMu.Unlock()

	go t.watchLiveness(ctx, conn, digest, box, live)
}

// watchLiveness watches the policy in force on the sandbox. It is owned per
// sandbox attachment and outlives the tunnel the policy arrived on.
//
// When liveness is lost:
// - If the pushing tunnel is still open, it is closed and ReasonPolicyNotLive is logged.
// - If no tunnel is open, ReasonPolicyNotLive is logged with a sentence stating
//   that no tunnel was closed because none was open.
// In both cases, the enforcing attachment is dropped and the host's policy state
// becomes not-live.
func (t *Tunneld) watchLiveness(ctx context.Context, conn *tunnel.Conn, digest string, box sandbox.Sandbox, live sandbox.Live) {
	lost := live.Watch(ctx, digest)
	select {
	case err, ok := <-lost:
		if !ok {
			return
		}
		if conn != nil && conn.Live() {
			t.refuse(attest.Refuse(attest.ReasonPolicyNotLive,
				"a peer at %s pushed a policy this sandbox no longer enforces: %v", conn.RemoteAddr(), err))
			conn.Close()
		} else {
			t.refuse(attest.Refuse(attest.ReasonPolicyNotLive,
				"the policy pushed to this sandbox is no longer live: %v; no tunnel was closed because none was open", err))
		}
		if d, ok := box.(interface{ DropEnforcing() }); ok {
			d.DropEnforcing()
		}
		return
	case <-ctx.Done():
		return
	case <-t.done:
		return
	}
}

// refusePush logs the refusal, ends the tunnel the push arrived on, and gives
// back the sentence the peer is told.
//
// The tunnel goes because a peer whose policy did not land is a peer whose next
// stream would run under a contract neither side holds. Carrying that stream
// would make the push advisory, which is the shape this design refuses
// everywhere else; the refusal is logged with its own reason so that an
// operator reads why the tunnel went rather than inferring it from its absence.
func (t *Tunneld) refusePush(conn *tunnel.Conn, sentence string, why error) string {
	t.refuse(attest.Refuse(attest.ReasonPolicyNotApplied,
		"a peer at %s pushed a policy this sandbox did not apply: %v", conn.RemoteAddr(), why))
	time.AfterFunc(pushRefusalGrace, func() { conn.Close() })
	return sentence
}

// refuse writes one refusal to the log this tunneld was started with. It is the
// same sink the handshake's refusals go to, because an operator reading a
// console has one place to look and a reason is a reason.
func (t *Tunneld) refuse(r *attest.Refusal) { t.refusals(r) }

// DefaultPushTimeout bounds how long a push waits for its acknowledgement when
// [Config.PushTimeout] says nothing.
//
// A push is one round trip on a tunnel that is already established — spike E2
// measured 0.83 ms at the median for a 2 KiB policy on loopback — so the bound
// is not a performance number and is not tuned like one. It is there so that a
// peer which never answers is a refusal this side reaches on its own, rather
// than a caller left waiting on whatever context it happened to pass in.
const DefaultPushTimeout = 10 * time.Second

// A pushBook is the pushes this tunneld has made, one per tunnel it dialed.
//
// It is keyed by the connection and not by the peer, because "once" means once
// per tunnel: a tunnel that was lost, or that reached its maximum age and was
// re-attested, is a new handshake and the policy has to be pushed to it again.
// Nothing here outlives a tunnel — dead connections are dropped as new ones are
// entered, the way the accepted list is (tunneld.go, live).
type pushBook struct {
	mu sync.Mutex
	m  map[*tunnel.Conn]*onePush
}

// onePush is one tunnel's push and its outcome, shared by everyone who asked
// for that peer while it was in flight. Several callers racing on a fresh
// tunnel make one push between them and all wait on it, which is what keeps
// "before any stream is handed out" true under concurrency rather than only in
// the test that asks for one stream.
type onePush struct {
	done chan struct{}
	err  error
}

func newPushBook() *pushBook { return &pushBook{m: map[*tunnel.Conn]*onePush{}} }

// begin returns this tunnel's push, and whether this caller is the one that has
// to make it.
func (b *pushBook) begin(conn *tunnel.Conn) (*onePush, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.m[conn]; ok {
		return p, false
	}
	for c := range b.m {
		if !c.Live() {
			delete(b.m, c)
		}
	}
	p := &onePush{done: make(chan struct{})}
	b.m[conn] = p
	return p, true
}

// settle publishes the outcome to everyone waiting on it.
func (p *onePush) settle(err error) {
	p.err = err
	close(p.done)
}

// pushPolicy is what stands between an established tunnel and the first thing
// anybody sends over it: this tunneld's policy, pushed once, acknowledged
// before the tunnel is handed back.
//
// A tunneld with no policy to push does nothing here, which is what keeps every
// recorded scenario's behaviour exactly what it was.
func (t *Tunneld) pushPolicy(ctx context.Context, conn *tunnel.Conn, name, addr string) error {
	if len(t.cfg.PushPolicy) == 0 {
		return nil
	}
	p, mine := t.pushes.begin(conn)
	if mine {
		p.settle(t.makePush(ctx, conn, name, addr))
	}
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// makePush is the exchange itself, and everything a failed one costs.
//
// Refused, answered in a version this side does not read, answered with
// something that is not an acknowledgement at all, or not answered inside the
// deadline: all four are one outcome, because all four leave this side unable
// to say the peer is running under the policy it was sent. The tunnel is closed
// so that nothing is carried over it in the meantime, the refusal is logged
// with its reason, and the caller is told it was refused.
func (t *Tunneld) makePush(ctx context.Context, conn *tunnel.Conn, name, addr string) error {
	err := t.exchangePush(ctx, conn)
	if err == nil {
		return nil
	}
	r := attest.Refuse(attest.ReasonPolicyNotApplied,
		"%q at %s did not apply the policy pushed to it: %v", name, addr, err)
	t.refuse(r)
	conn.Close()
	return r
}

// exchangePush sends the policy and waits for the answer, or for the deadline.
//
// The wait is here rather than in the exchange because [tunnel.Conn.Exchange]
// takes a context for opening its stream and then reads the response without
// one: a peer that accepts a push and never answers it would otherwise hold
// this caller until the tunnel died of idleness, which is a minute of a sandbox
// waiting for a stream. The goroutine left behind ends when the read does, and
// the read ends because the caller closes the connection on every failure.
func (t *Tunneld) exchangePush(ctx context.Context, conn *tunnel.Conn) error {
	deadline, cancel := context.WithTimeout(ctx, t.cfg.PushTimeout)
	defer cancel()
	answered := make(chan error, 1)
	go func() { answered <- readAck(conn.Exchange(deadline, t.cfg.PushPolicy)) }()
	select {
	case err := <-answered:
		return err
	case <-deadline.Done():
		return fmt.Errorf("it was not acknowledged within %s: %w", t.cfg.PushTimeout, deadline.Err())
	}
}

// readAck is what an answer has to be for a push to have landed: this side's
// format, this side's version, and ok. It takes the exchange's error beside its
// response because a push that never got an answer and a push that got the
// wrong one are the same outcome to the caller.
func readAck(response []byte, err error) error {
	if err != nil {
		return err
	}
	var a policyAck
	if err := json.Unmarshal(response, &a); err != nil {
		return fmt.Errorf("the answer is %d bytes that are not a JSON object: %v", len(response), err)
	}
	switch {
	case a.Format != ackFormat || a.Version != ackVersion:
		return fmt.Errorf("the answer is format %q version %d, not %q version %d", a.Format, a.Version, ackFormat, ackVersion)
	case !a.OK:
		return fmt.Errorf("the peer refused it: %s", a.Reason)
	}
	return nil
}
