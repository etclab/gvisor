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

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// A Host is tunneld's side of the contract for a sandbox in another process:
// the unix socket it listens on, the streams it hands over descriptors for,
// and the policy it pushes.
//
// It is a [Sandbox] itself, and that is not a trick. Open and Accept are the
// [Network] it was built on, so a caller in tunneld's own process sees the same
// two verbs whether or not anybody has attached; Apply sends the policy down
// the socket and returns the sandbox's acknowledgement or its refusal. What
// changes across the boundary is where the bytes go, not what the contract
// says.
//
// The socket is created with mode 0600 and is the local face of the boundary:
// anything that can open it can ask for a stream to any peer this tunneld can
// reach. It cannot ask for a stream to a peer this tunneld would not itself
// dial, and it cannot see evidence or keys, so the worst a local process that
// gets to it can do is use a channel it did not earn — which is exactly what
// the sandbox beside tunneld is for. Keeping other processes off it is the
// deployment's job and, in the measured image, there are none.
type Host struct {
	// Network is what Open and Accept are answered out of, promoted so that a
	// Host is a Sandbox.
	Network

	ln   *net.UnixListener
	path string
	logf func(string, ...any)

	// done closes when this host does, so that a watch on an attachment's
	// liveness ends because the host went rather than reporting every
	// attachment it just dropped as a sandbox that died.
	done chan struct{}

	applySem chan struct{}

	// applyWait is how long a push may take when its caller gave no deadline.
	// It is [DefaultApplyWait] and is a field so that a test can shorten it; it
	// is written before the host is used and read after, never both at once.
	applyWait time.Duration

	mu      sync.Mutex
	closed  bool
	conns   []*attached
	inForce []byte
	// enforcingWaiter is where the one push that is waiting for an enforcing
	// sandbox to attach is handed it, or nil while none is waiting. There is at
	// most one because there is at most one push in flight (holdPush), so this
	// is one channel and not a queue.
	enforcingWaiter chan *attached
	wg              sync.WaitGroup
}

// ErrHostClosed is returned once the host has been closed.
var ErrHostClosed = errors.New("sandbox: host closed")

// ErrNoEnforcingSandbox is what a push meets when there is no enforcing sandbox
// any more: none was attached, none arrived inside the wait, or the one that was
// there was given up during the push because it went or would not answer.
//
// It wraps [ErrPolicyRefused], because that is what it is to the caller, and it
// is its own sentinel because two things turn on it that the text of an error
// should not have to carry. Tunneld answers a pushing peer a different sentence
// for it — "no sandbox is attached to this tunneld" rather than "the sandbox
// beside this tunneld did not apply it" — and it says whether the policy that
// was in force is still being enforced by anything, which is what decides
// whether the watch over that policy goes back on after a push that did not
// land.
var ErrNoEnforcingSandbox = fmt.Errorf("%w: no enforcing sandbox is attached", ErrPolicyRefused)

// DefaultApplyWait bounds the whole of a push whose caller gave no deadline —
// the wait for an enforcing sandbox to attach and then the wait for its answer,
// end to end — and the replay of the policy in force at an enforcing sandbox
// that has just attached.
//
// It is one bound over both halves because either of them can be the one that
// does not end: a sandbox that never attaches and a sandbox that attaches and
// never answers hold the same push slot, and a bound over only the first of them
// is the bound that reads as though there were one.
//
// It is the ten seconds tunneld's DefaultPushTimeout is, and it is written again
// here rather than imported because package sandbox imports nothing of tunneld —
// that is the contract's shape and not an oversight. Nothing rests on the two
// being equal; what rests on this existing is that no wait here is unbounded.
const DefaultApplyWait = 10 * time.Second

var (
	_ Sandbox = (*Host)(nil)
	_ Live    = (*Host)(nil)
)

// Listen binds path and serves the contract on it out of n. The directory is
// created if it is missing, and a socket left behind by a previous run is
// replaced; anything else already at that path is an error rather than
// something to delete.
func Listen(path string, n Network, logf func(string, ...any)) (*Host, error) {
	if n == nil {
		return nil, ErrNoNetwork
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: making the directory for %s: %w", path, err)
	}
	switch info, err := os.Lstat(path); {
	case err == nil && info.Mode()&fs.ModeSocket != 0:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("sandbox: replacing the socket at %s: %w", path, err)
		}
	case err == nil:
		return nil, fmt.Errorf("sandbox: %s is not a socket (%s)", path, info.Mode())
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("sandbox: %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("sandbox: listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("sandbox: %s: %w", path, err)
	}
	h := &Host{Network: n, ln: ln, path: path, logf: logf, done: make(chan struct{}), applySem: make(chan struct{}, 1), applyWait: DefaultApplyWait}
	h.wg.Add(1)
	go h.accept()
	return h, nil
}

// Path is the socket a sandbox connects to.
func (h *Host) Path() string { return h.path }

// Attached is how many sandboxes are connected with a declared role.
func (h *Host) Attached() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	var n int
	for _, c := range h.conns {
		if c.role != "" && !c.isGone() {
			n++
		}
	}
	return n
}

// Apply pushes the policy to the enforcing sandbox and returns its
// acknowledgement or refusal.
//
// If no enforcing sandbox has attached yet, Apply waits for one inside the
// caller's deadline: a push that lands before the enforcing sandbox attaches is
// acknowledged only once that sandbox has it, which is the whole of what an
// acknowledgement on this socket means. A caller that gave neither a deadline
// nor a way to cancel is refused at once instead, because nothing it supplied
// could ever end that wait; a caller that gave a deadline keeps it, however
// long; and a push with no deadline behind it is bounded end to end by
// [DefaultApplyWait], the wait for an attachment and the wait for its answer
// together.
//
// One push is in flight at a time. That is what keeps two pushes — or a push and
// the replay a freshly attached sandbox is offered — from crossing on the socket
// and leaving the sandbox enforcing the older of the two.
func (h *Host) Apply(ctx context.Context, policy []byte) error {
	// Whether this caller can be waited for at all is read before the bound
	// below, because the bound gives every push a deadline and would answer the
	// question the same way for all of them.
	_, hasDeadline := ctx.Deadline()
	canWait := hasDeadline || ctx.Done() != nil

	ctx, cancel := h.bound(ctx)
	defer cancel()

	if err := h.holdPush(ctx); err != nil {
		return err
	}
	defer h.releasePush()

	a, waiter, err := h.enforcingOrWaiter(canWait)
	if err != nil {
		return err
	}
	if a == nil {
		if a, err = h.awaitEnforcing(ctx, waiter); err != nil {
			return err
		}
	}
	if err := a.apply(ctx, policy); err != nil {
		if ctx.Err() != nil {
			// The sandbox did not answer inside the bound, so whether it has
			// this policy is not something this side can say — and it may
			// install it a moment from now and start pulsing that policy's
			// digest, which is a claim nobody here made. What cannot be said
			// cannot be claimed: the attachment is given up and nothing is left
			// in force, which is what a heartbeat that stops gets and for the
			// same reason.
			a.claimLost.Store(true)
			h.DropEnforcing()
			return fmt.Errorf("%w to %s: it did not answer the push and has been dropped: %w", ErrNoEnforcingSandbox, h.path, err)
		}
		return err
	}
	// The policy in force is written here and nowhere else, which is what makes
	// it by construction a policy a sandbox answered for.
	h.mu.Lock()
	h.inForce = policy
	h.mu.Unlock()
	h.said(policy)
	return nil
}

// bound is the context the whole of a push runs under: the caller's, with
// [DefaultApplyWait] over the top where the caller gave no deadline of its own.
// A caller's own deadline is kept, however long it is — the ceiling is for the
// caller that named none.
func (h *Host) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, h.applyWait)
}

// holdPush takes the one push slot this host has, and releasePush gives it
// back.
func (h *Host) holdPush(ctx context.Context) error {
	select {
	case h.applySem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-h.done:
		return ErrHostClosed
	}
}

func (h *Host) releasePush() { <-h.applySem }

// enforcingOrWaiter is the enforcing attachment if one is here, or the channel
// the next one to attach will be handed down. Exactly one of the two is non-nil
// when the error is nil.
func (h *Host) enforcingOrWaiter(canWait bool) (*attached, chan *attached, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, nil, ErrHostClosed
	}
	if a := h.enforcing(); a != nil {
		return a, nil, nil
	}
	if !canWait {
		return nil, nil, fmt.Errorf("%w to %s", ErrNoEnforcingSandbox, h.path)
	}
	h.enforcingWaiter = make(chan *attached, 1)
	return nil, h.enforcingWaiter, nil
}

// enforcing is the attachment a policy is pushed to, or nil while there is
// none. It is called under h.mu, and there is at most one of them: a second
// enforcing client on this socket is refused as it attaches.
func (h *Host) enforcing() *attached {
	for _, c := range h.conns {
		if c.role == RoleEnforcing && !c.isGone() {
			return c
		}
	}
	return nil
}

// awaitEnforcing waits for the enforcing sandbox to attach and to be handed this
// push. The context is the push's own, bounded once in [Host.Apply], so the wait
// here and the wait for the sandbox's answer share one deadline rather than each
// having its own.
func (h *Host) awaitEnforcing(ctx context.Context, waiter chan *attached) (*attached, error) {
	select {
	case a, ok := <-waiter:
		if !ok || a == nil {
			return nil, ErrHostClosed
		}
		return a, nil
	case <-ctx.Done():
		h.dropWaiter(waiter)
		return nil, fmt.Errorf("%w to %s", ErrNoEnforcingSandbox, h.path)
	case <-h.done:
		h.dropWaiter(waiter)
		return nil, ErrHostClosed
	}
}

// dropWaiter gives up this push's waiter, once the push has stopped waiting on
// it. It clears only its own: the push slot is still held here, so nothing can
// have put another waiter in its place, and comparing says so rather than
// leaving it to be relied on.
func (h *Host) dropWaiter(w chan *attached) {
	h.mu.Lock()
	if h.enforcingWaiter == w {
		h.enforcingWaiter = nil
	}
	h.mu.Unlock()
}

// said writes the one console line a push is read off, in the shape [Null]
// writes it and with the same four fields.
//
// The SANDBOX applied line is written only when the enforcing sandbox has
// acknowledged.
func (h *Host) said(policy []byte) {
	if h.logf == nil {
		return
	}
	e, err := ReadEnvelope(policy)
	if err != nil {
		// Unreachable through tunneld, which reads the envelope first. A
		// sandbox that took something else has its own console.
		return
	}
	sum := sha256.Sum256(policy)
	h.log("SANDBOX applied format=%s version=%d bytes=%d sha256=%s", e.Format, e.Version, len(policy), hex.EncodeToString(sum[:]))
}

// watchInterval is how often a watch looks at what the attachments last said.
// It is a quarter of a pulse so that a digest that does not match is a refusal
// inside a quarter of a second rather than at the next heartbeat: a mismatch is
// known the moment it arrives, and the only thing between the two is this
// loop's granularity.
const watchInterval = DefaultPulse / 4

// Watch reports the loss of liveness for the policy with the given digest
// (live.go). It watches the enforcing sandbox attached here that has
// acknowledged a policy.
func (h *Host) Watch(ctx context.Context, digest string) <-chan error {
	lost := make(chan error, 1)
	h.mu.Lock()
	closed := h.closed
	var watched []*attached
	for _, a := range h.conns {
		if a.role == RoleEnforcing && a.acknowledgedPolicy() {
			watched = append(watched, a)
		}
	}
	h.mu.Unlock()
	switch {
	case closed:
		close(lost)
	case len(watched) == 0:
		// There is nothing here that ever claimed this policy — the sandbox
		// that had it has gone, or the only attachment is one that was never
		// pushed to. Either way the claim cannot be watched, and saying that a
		// socket closed would name a sandbox that may still be sitting on this
		// one.
		h.reportLost(lost, "no attachment has acknowledged this policy")
	default:
		go h.watch(ctx, digest, watched, lost)
	}
	return lost
}

// watch is one caller's watch: it looks at what each attachment last said, and
// ends at the first one that is no longer saying it.
func (h *Host) watch(ctx context.Context, digest string, watched []*attached, lost chan error) {
	tick := time.NewTicker(watchInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			close(lost)
			return
		case <-h.done:
			close(lost)
			return
		case now := <-tick.C:
			for _, a := range watched {
				if why := a.lost(digest, now); why != "" {
					// This attachment, and not whichever one is enforcing by
					// the time the watcher answers ([Host.DropEnforcing]).
					a.claimLost.Store(true)
					h.reportLost(lost, why)
					return
				}
			}
		}
	}
}

// DropEnforcing gives up the attachment whose claim was lost and leaves no
// policy in force (live.go). It is what a watcher that has been told the claim
// is lost calls to stop the claim being made.
//
// Which attachment that is, is the whole of it. A loss takes up to a quarter of
// a pulse to be seen and a moment more to be answered, and a fresh sandbox can
// attach and be replayed the policy in force inside that window. Closing
// whatever is enforcing now would close that sandbox for the dead one's failure,
// so an attachment that has not lost a claim is left alone — and so is the
// policy in force, which is the policy it took.
func (h *Host) DropEnforcing() {
	h.mu.Lock()
	a := h.enforcing()
	if a != nil && !a.claimLost.Load() {
		h.mu.Unlock()
		return
	}
	h.inForce = nil
	h.mu.Unlock()
	if a != nil {
		a.close()
	}
}

// reportLost writes the one error a watch carries, logs the line an operator
// reads it off, and closes the channel behind it.
func (h *Host) reportLost(lost chan error, why string) {
	h.log("SANDBOX liveness lost: %s", why)
	lost <- errors.New(why)
	close(lost)
}

// Close stops listening, drops every attached sandbox and removes the socket.
// Streams already handed over are not disturbed: the descriptor is the
// sandbox's, and the pump behind it ends when either end does.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	conns := h.conns
	h.conns = nil
	h.inForce = nil
	if h.enforcingWaiter != nil {
		close(h.enforcingWaiter)
		h.enforcingWaiter = nil
	}
	h.mu.Unlock()
	close(h.done)
	err := h.ln.Close()
	for _, a := range conns {
		a.close()
	}
	h.wg.Wait()
	return err
}

func (h *Host) accept() {
	defer h.wg.Done()
	for {
		c, err := h.ln.AcceptUnix()
		if err != nil {
			return
		}
		a := newAttached(h, c)
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			a.close()
			return
		}
		h.conns = append(h.conns, a)
		h.mu.Unlock()
		h.log("SANDBOX attached on %s", h.path)
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			a.serve()
		}()
	}
}

func (h *Host) log(format string, a ...any) {
	if h.logf != nil {
		h.logf(format, a...)
	}
}

func (h *Host) drop(a *attached) {
	h.mu.Lock()
	h.conns = slices.DeleteFunc(h.conns, func(c *attached) bool { return c == a })
	h.mu.Unlock()
}

// attached is one connected sandbox: the socket to it, the requests tunneld has
// outstanding on it, the context every request it makes runs under, and what it
// last said about the policy it is enforcing.
type attached struct {
	h    *Host
	w    *wire
	p    pending
	ctx  context.Context
	stop context.CancelFunc

	once sync.Once

	// role is what the attach message declared (contract v4). It is written
	// once, under the host's lock, and read under it.
	role string

	// declared says the attach message has been taken, which is role != "" for
	// a reader that holds no lock: serve, which has to refuse a stream to a
	// connection that has not attached and would otherwise take the host's lock
	// on every request to ask one question with a yes that never changes.
	declared atomic.Bool

	// gone says this attachment has given up its socket. It is one atomic and
	// not a field under a lock because its readers cannot share one: the host
	// reads it holding h.mu — the uniqueness check, Apply, Attached,
	// DropEnforcing — and a watch reads it holding nothing, while close() runs
	// on whichever goroutine gave the socket up and takes h.mu on its way out.
	// Reading it under a.mu, as this once did, was reading it under a lock none
	// of those writers hold.
	gone atomic.Bool

	// claimLost says this attachment's claim to the policy in force has been
	// given up on: a watch found it no longer enforcing what it acknowledged,
	// or it refused the policy it was replayed. It is what tells the attachment
	// a drop is about from whichever attachment is enforcing when the drop
	// arrives ([Host.DropEnforcing]).
	claimLost atomic.Bool

	// acked says this sandbox has acknowledged a policy at some point, which is
	// what makes it something there is a claim to lose. It is written once and
	// never cleared, and it is stored after the clock below so that a reader
	// which sees it also sees the moment it started counting from. A sandbox
	// that never acknowledged is not watched, so the clock starts at the
	// acknowledgement rather than at the connection.
	acked atomic.Bool

	// The heartbeat, under mu: when this sandbox last said anything about a
	// policy, and what it said.
	mu     sync.Mutex
	last   time.Time
	digest string
}

func (a *attached) isGone() bool { return a.gone.Load() }

func newAttached(h *Host, c *net.UnixConn) *attached {
	ctx, stop := context.WithCancel(context.Background())
	return &attached{h: h, w: &wire{c: c}, ctx: ctx, stop: stop}
}

// recordAttach takes one attach message (contract v4) and reports whether this
// attachment goes on being served.
//
// The decision is made under the lock and everything that talks — the console,
// the socket, the push that was waiting — happens outside it, because a logf
// this host was handed is somebody else's code and holding h.mu across it is a
// deadlock waiting for the one caller that asks the host a question from inside
// its own log.
func (h *Host) recordAttach(a *attached, role string) bool {
	refused, waiting := h.admit(a, role)
	if refused != "" {
		a.w.send(message{Type: msgError, Error: refused}, -1)
		h.log("SANDBOX attach refused on %s: %s", h.path, refused)
		a.close()
		return false
	}
	h.log("SANDBOX attached on %s role=%s", h.path, role)
	if role == RoleEnforcing {
		if waiting != nil {
			// Buffered, and nobody else holds it: this cannot block.
			waiting <- a
		}
		go h.replayInForce(a)
	}
	return true
}

// admit is the attach decision: the sentence this attachment is refused with, or
// "" and the push that has been waiting for an enforcing sandbox to arrive.
func (h *Host) admit(a *attached, role string) (string, chan *attached) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return "this host is closed", nil
	case role != RoleEnforcing && role != RoleNetwork:
		return fmt.Sprintf("unknown role %q", role), nil
	case a.role != "":
		// One attach message per connection. A second would be a second
		// declaration on a socket whose whole point is that there is one.
		return "this client has already attached", nil
	case role == RoleEnforcing && h.enforcing() != nil:
		return "a second enforcing client is not permitted on this socket", nil
	}
	a.role = role
	a.declared.Store(true)
	if role != RoleEnforcing {
		return "", nil
	}
	waiting := h.enforcingWaiter
	h.enforcingWaiter = nil
	return "", waiting
}

// replayInForce offers a freshly attached enforcing sandbox the policy in force,
// so that a sandbox which arrives after a push was acknowledged is enforcing the
// policy the pushing peer was told about.
//
// It is started for every enforcing attachment and is usually nothing: there is
// no policy in force, or a push was waiting for this attachment and handed it a
// newer one. Starting it unconditionally is what closes the gap between the two
// — a push that gave up in the same moment its attachment arrived leaves an
// attachment with nothing, and this is what hands it the policy anyway.
//
// It takes the push slot, so it cannot cross the push that a caller is making;
// and it reads the policy in force after taking it, so what it replays is the
// latest and never the one that was in force when the sandbox knocked.
func (h *Host) replayInForce(a *attached) {
	if err := h.holdPush(a.ctx); err != nil {
		return
	}
	defer h.releasePush()

	h.mu.Lock()
	policy := h.inForce
	h.mu.Unlock()
	if policy == nil || a.isGone() || a.acknowledgedPolicy() {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, h.applyWait)
	defer cancel()
	if err := a.apply(ctx, policy); err != nil {
		// The only sandbox that had this policy has gone and the one that
		// arrived will not have it, so nothing here is enforcing it any more.
		// Saying so is this host's business; whether a tunnel should go for it
		// is the watcher's, and there may well be one open.
		h.log("SANDBOX the enforcing sandbox that attached to %s refused the policy in force: %v; it has been dropped and no policy is in force", h.path, err)
		a.claimLost.Store(true)
		h.DropEnforcing()
	}
}

// acknowledgedPolicy reports whether this sandbox has ever acknowledged one,
// which is what makes it something there is a claim to lose.
func (a *attached) acknowledgedPolicy() bool { return a.acked.Load() }

// pulsed records one `alive`. It is answered with nothing: the message is a
// statement about now, and a reply would only say that it arrived.
func (a *attached) pulsed(digest string) {
	a.mu.Lock()
	a.last = time.Now()
	a.digest = digest
	a.mu.Unlock()
}

// acknowledged starts this attachment's heartbeat clock at the moment it
// acknowledged a policy, so that a sandbox which acknowledges and then says
// nothing at all is a loss rather than a silence nobody is counting.
func (a *attached) acknowledged() {
	a.mu.Lock()
	a.last = time.Now()
	a.mu.Unlock()
	a.acked.Store(true)
}

// lost reports why this attachment is no longer live for the given digest, or
// "" if it still is.
func (a *attached) lost(digest string, now time.Time) string {
	if a.isGone() {
		return "the sandbox closed its socket"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.digest != "" && a.digest != digest:
		return fmt.Sprintf("it pulsed %s, expected %s", a.digest, digest)
	case now.Sub(a.last) > DefaultMisses*DefaultPulse:
		return fmt.Sprintf("it missed %d pulses", DefaultMisses)
	}
	return ""
}

// serve reads this sandbox's messages until it goes away. Each request is
// answered on its own goroutine, because ACCEPT blocks until a peer opens a
// stream and everything else on this socket would otherwise wait behind it.
func (a *attached) serve() {
	defer a.close()
	for {
		m, f, err := a.w.receive()
		if err != nil {
			return
		}
		if f != nil {
			// Descriptors travel one way. A sandbox that sent one is refused
			// it rather than having it held.
			f.Close()
		}
		switch m.Type {
		case msgAttach:
			if !a.h.recordAttach(a, m.Role) {
				return
			}
		case msgOpen, msgAccept:
			if !a.declared.Load() {
				// Attach comes first (contract v4). A connection that asks for
				// a stream before it has said what it is has declared no role,
				// is in nobody's count of what is attached, and would be a
				// channel this host cannot name — so it is answered rather than
				// served, and may still attach.
				a.w.send(message{ID: m.ID, Type: msgError, Error: "this client has not attached"}, -1)
				continue
			}
			go a.stream(m)
		case msgAck, msgRefusal:
			a.p.deliver(reply{m: m})
		case msgAlive:
			a.pulsed(m.Digest)
		default:
			a.w.send(message{ID: m.ID, Type: msgError, Error: "unknown message type " + m.Type}, -1)
		}
	}
}

// stream answers one OPEN or ACCEPT: the stream itself becomes one end of a
// socketpair, and the descriptor for the other end goes back with the reply.
func (a *attached) stream(m message) {
	var (
		s   Stream
		who Attested
		err error
	)
	switch m.Type {
	case msgOpen:
		s, err = a.h.Open(a.ctx, m.Peer)
	case msgAccept:
		s, who, err = a.h.Accept(a.ctx)
	}
	if err != nil {
		a.w.send(message{ID: m.ID, Type: msgError, Error: err.Error()}, -1)
		return
	}
	f, err := handoff(s)
	if err != nil {
		s.Close()
		a.w.send(message{ID: m.ID, Type: msgError, Error: err.Error()}, -1)
		return
	}
	defer f.Close()
	reply := message{ID: m.ID, Type: msgStream}
	if m.Type == msgAccept {
		reply.Attested = &who
	}
	if err := a.w.send(reply, int(f.Fd())); err != nil {
		// The sandbox is gone or the socket broke. The pump ends on its own
		// once this end of the socketpair is closed, which the deferred close
		// does.
		a.h.log("SANDBOX handing over a stream: %v", err)
	}
}

// apply sends one policy and waits for the sandbox to answer it.
func (a *attached) apply(ctx context.Context, policy []byte) error {
	id, ch := a.p.begin()
	defer a.p.end(id, ch)
	if err := a.w.send(message{ID: id, Type: msgApply, Policy: policy}, -1); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.m.Type == msgAck {
			a.acknowledged()
			return nil
		}
		return fmt.Errorf("%w: the sandbox refused it: %s", ErrPolicyRefused, r.m.Error)
	case <-ctx.Done():
		return ctx.Err()
	case <-a.ctx.Done():
		return fmt.Errorf("%w: it went away before it answered the push", ErrNoEnforcingSandbox)
	}
}

func (a *attached) close() {
	a.once.Do(func() {
		a.gone.Store(true)
		a.stop()
		a.w.c.Close()
		a.h.drop(a)
	})
}
