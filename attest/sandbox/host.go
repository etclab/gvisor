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
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
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

	mu     sync.Mutex
	closed bool
	conns  []*attached
	wg     sync.WaitGroup
}

// ErrHostClosed is returned once the host has been closed.
var ErrHostClosed = errors.New("sandbox: host closed")

var _ Sandbox = (*Host)(nil)

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
	h := &Host{Network: n, ln: ln, path: path, logf: logf}
	h.wg.Add(1)
	go h.accept()
	return h, nil
}

// Path is the socket a sandbox connects to.
func (h *Host) Path() string { return h.path }

// Attached is how many sandboxes are connected.
func (h *Host) Attached() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// Apply pushes the policy to every attached sandbox and returns the first
// refusal, or the fact that there is nobody to push to.
//
// A tunneld with no sandbox attached refusing the push is the honest answer: an
// acknowledgement means a sandbox has the policy, and there is no sandbox. The
// peer that pushed it learns that its push did not land, which is what it asked.
func (h *Host) Apply(ctx context.Context, policy []byte) error {
	h.mu.Lock()
	closed, conns := h.closed, append([]*attached(nil), h.conns...)
	h.mu.Unlock()
	if closed {
		return ErrHostClosed
	}
	if len(conns) == 0 {
		return fmt.Errorf("%w: no sandbox is attached to %s", ErrPolicyRefused, h.path)
	}
	for _, a := range conns {
		if err := a.apply(ctx, policy); err != nil {
			return err
		}
	}
	return nil
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
	h.mu.Unlock()
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
// outstanding on it, and the context every request it makes runs under.
type attached struct {
	h    *Host
	w    *wire
	p    pending
	ctx  context.Context
	stop context.CancelFunc

	once sync.Once
}

func newAttached(h *Host, c *net.UnixConn) *attached {
	ctx, stop := context.WithCancel(context.Background())
	return &attached{h: h, w: &wire{c: c}, ctx: ctx, stop: stop}
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
		case msgOpen, msgAccept:
			go a.stream(m)
		case msgAck, msgRefusal:
			a.p.deliver(reply{m: m})
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
		a.stop()
		a.w.c.Close()
		a.h.drop(a)
	})
}
