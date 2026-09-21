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

	mu               sync.Mutex
	closed           bool
	conns            []*attached
	inForce          []byte
	enforcingWaiters []chan *attached
	wg               sync.WaitGroup
}

// ErrHostClosed is returned once the host has been closed.
var ErrHostClosed = errors.New("sandbox: host closed")

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
	h := &Host{Network: n, ln: ln, path: path, logf: logf, done: make(chan struct{}), applySem: make(chan struct{}, 1)}
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
// If no enforcing sandbox has attached yet, Apply waits up to the caller's
// deadline for one to attach. A push that lands before the enforcing sandbox
// attaches is acknowledged only when the enforcing sandbox has received it.
func (h *Host) Apply(ctx context.Context, policy []byte) error {
	select {
	case h.applySem <- struct{}{}:
		defer func() { <-h.applySem }()
	case <-ctx.Done():
		return ctx.Err()
	case <-h.done:
		return ErrHostClosed
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrHostClosed
	}
	var enforcing *attached
	for _, c := range h.conns {
		if c.role == RoleEnforcing && !c.isGone() {
			enforcing = c
			break
		}
	}
	if enforcing != nil {
		h.mu.Unlock()
		if err := enforcing.apply(ctx, policy); err != nil {
			return err
		}
		h.mu.Lock()
		h.inForce = policy
		h.mu.Unlock()
		h.said(policy)
		return nil
	}

	_, hasDeadline := ctx.Deadline()
	if !hasDeadline && ctx.Done() == nil {
		h.mu.Unlock()
		return fmt.Errorf("%w: no enforcing sandbox is attached to %s", ErrPolicyRefused, h.path)
	}

	waiter := make(chan *attached, 1)
	h.enforcingWaiters = append(h.enforcingWaiters, waiter)
	h.mu.Unlock()

	select {
	case <-ctx.Done():
		h.mu.Lock()
		h.removeEnforcingWaiter(waiter)
		h.mu.Unlock()
		return fmt.Errorf("%w: no enforcing sandbox is attached to %s", ErrPolicyRefused, h.path)
	case <-h.done:
		h.mu.Lock()
		h.removeEnforcingWaiter(waiter)
		h.mu.Unlock()
		return ErrHostClosed
	case a, ok := <-waiter:
		if !ok || a == nil {
			return ErrHostClosed
		}
		if err := a.apply(ctx, policy); err != nil {
			return err
		}
		h.mu.Lock()
		h.inForce = policy
		h.mu.Unlock()
		h.said(policy)
		return nil
	}
}

func (h *Host) removeEnforcingWaiter(w chan *attached) {
	kept := h.enforcingWaiters[:0]
	for _, waiter := range h.enforcingWaiters {
		if waiter != w {
			kept = append(kept, waiter)
		}
	}
	h.enforcingWaiters = kept
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
		h.reportLost(lost, "the sandbox closed its socket")
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
					h.reportLost(lost, why)
					return
				}
			}
		}
	}
}

// DropEnforcing closes any active enforcing attachment and marks the policy
// state not-live.
func (h *Host) DropEnforcing() {
	h.mu.Lock()
	h.inForce = nil
	var toClose []*attached
	for _, c := range h.conns {
		if c.role == RoleEnforcing && !c.isGone() {
			toClose = append(toClose, c)
		}
	}
	h.mu.Unlock()
	for _, c := range toClose {
		c.close()
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
	for _, w := range h.enforcingWaiters {
		close(w)
	}
	h.enforcingWaiters = nil
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
	kept := h.conns[:0]
	for _, c := range h.conns {
		if c != a {
			kept = append(kept, c)
		}
	}
	h.conns = kept
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

	// gone says this attachment has given up its socket. It is one atomic and
	// not a field under a lock because its readers cannot share one: the host
	// reads it holding h.mu — the uniqueness check, Apply, Attached,
	// DropEnforcing — and a watch reads it holding nothing, while close() runs
	// on whichever goroutine gave the socket up and takes h.mu on its way out.
	// Reading it under a.mu, as this once did, was reading it under a lock none
	// of those writers hold.
	gone atomic.Bool

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

func (h *Host) recordAttach(a *attached, role string) bool {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		a.close()
		return false
	}
	if role != RoleEnforcing && role != RoleNetwork {
		h.mu.Unlock()
		a.w.send(message{Type: msgError, Error: fmt.Sprintf("unknown role %q", role)}, -1)
		a.close()
		return false
	}
	if role == RoleEnforcing {
		for _, c := range h.conns {
			if c != a && c.role == RoleEnforcing && !c.isGone() {
				const why = "a second enforcing client is not permitted on this socket"
				h.mu.Unlock()
				a.w.send(message{Type: msgError, Error: why}, -1)
				h.log("SANDBOX attach refused on %s: %s", h.path, why)
				a.close()
				return false
			}
		}
	}
	a.role = role
	h.log("SANDBOX attached on %s role=%s", h.path, role)
	if role == RoleEnforcing {
		if len(h.enforcingWaiters) > 0 {
			w := h.enforcingWaiters[0]
			h.enforcingWaiters = h.enforcingWaiters[1:]
			w <- a
		} else if h.inForce != nil {
			go a.replay(h.inForce)
		}
	}
	h.mu.Unlock()
	return true
}

func (a *attached) replay(policy []byte) {
	if err := a.apply(a.ctx, policy); err != nil {
		a.h.log("SANDBOX late enforcing client refused policy in force: %v", err)
		a.close()
		return
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
		return fmt.Errorf("%w: the sandbox went away before it answered", ErrPolicyRefused)
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
