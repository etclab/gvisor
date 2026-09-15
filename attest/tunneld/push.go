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
	"encoding/json"
	"errors"
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
	if err := box.Apply(ctx, policy); err != nil {
		return t.refusePush(conn, ackRefused, err)
	}
	return ""
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
