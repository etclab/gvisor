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

package cmd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
)

// serveWait bounds how long a test waits for serveSentry to come back. The
// thing under test is whether it comes back at all, so the bound only has to be
// longer than the machine is slow.
const serveWait = 30 * time.Second

// tunneldPair attaches a client over a socketpair and hands back tunneld's end
// of it, so a test can read what the helper wrote and write what tunneld would
// have answered. Nothing is dialled and no socket is created on disk.
func tunneldPair(t *testing.T) (*tunneldClient, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	var conns [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "tunneld")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatalf("net.FileConn: %v", err)
		}
		u, ok := c.(*net.UnixConn)
		if !ok {
			t.Fatalf("net.FileConn gave a %T, wanted a unix socket", c)
		}
		conns[i] = u
	}
	cl, err := attachTunneld(conns[0], tunneldRoleEnforcing, func([]byte) error { return nil }, func(string, ...any) {})
	if err != nil {
		t.Fatalf("attachTunneld: %v", err)
	}
	t.Cleanup(func() {
		cl.Close()
		conns[1].Close()
	})
	return cl, conns[1]
}

// readTunneldMessage reads one message off tunneld's end of the wire: a
// four-byte big-endian length and that many bytes of JSON.
func readTunneldMessage(t *testing.T, c *net.UnixConn) tunneldMessage {
	t.Helper()
	var header [tunneldHeaderSize]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		t.Fatalf("reading a message header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("reading a %d byte message: %v", len(body), err)
	}
	var m tunneldMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("a message that is not JSON: %v", err)
	}
	return m
}

// writeTunneldMessage writes one message from tunneld's end of the wire.
func writeTunneldMessage(t *testing.T, c *net.UnixConn, m tunneldMessage) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encoding a %s message: %v", m.Type, err)
	}
	buf := make([]byte, tunneldHeaderSize+len(body))
	binary.BigEndian.PutUint32(buf[:tunneldHeaderSize], uint32(len(body)))
	copy(buf[tunneldHeaderSize:], body)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("writing a %s message: %v", m.Type, err)
	}
}

// sentryChannel is the socketpair the helper serves the sentry on. The sentry's
// end is returned first and is never closed by the tests that want to prove the
// helper does not wait for it.
func sentryChannel(t *testing.T) (*unet.Socket, *unet.Socket) {
	t.Helper()
	sentry, helper, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair: %v", err)
	}
	t.Cleanup(func() {
		sentry.Close()
		helper.Close()
	})
	return sentry, helper
}

// TestTunnelHelperAttachesAsTheEnforcingClient is the first message on the
// wire, which is the whole of contract v4's handshake: one attach naming the
// role, and no reply expected.
func TestTunnelHelperAttachesAsTheEnforcingClient(t *testing.T) {
	_, tunneld := tunneldPair(t)
	m := readTunneldMessage(t, tunneld)
	if m.Type != tunneldMsgAttach {
		t.Errorf("the helper's first message is a %q, wanted %q", m.Type, tunneldMsgAttach)
	}
	if m.Role != tunneldRoleEnforcing {
		t.Errorf("the helper attached with role %q, wanted %q", m.Role, tunneldRoleEnforcing)
	}
	if m.ID != 0 {
		t.Errorf("the attach carried id %d, wanted 0: nothing answers it", m.ID)
	}
}

// TestTunnelHelperEndsWhenTunneldRefusesTheAttach is finding 5 of ticket 27. A
// refused attach used to be read off the wire, recorded and ignored: the helper
// went on serving the sentry's Open calls, so the sandbox ran on with the
// policy it booted with, no push could ever reach it, and nothing said so.
//
// The sentry's end of the channel is deliberately left open here. A helper that
// waited for the sentry would sit in this test until it timed out.
func TestTunnelHelperEndsWhenTunneldRefusesTheAttach(t *testing.T) {
	cl, tunneld := tunneldPair(t)
	if m := readTunneldMessage(t, tunneld); m.Type != tunneldMsgAttach {
		t.Fatalf("the helper's first message is a %q, wanted %q", m.Type, tunneldMsgAttach)
	}
	_, helperEnd := sentryChannel(t)

	// Word for word what attest/sandbox's Host answers a second enforcing
	// client with, on id 0 and followed by the close.
	const why = "a second enforcing client is not permitted on this socket"
	writeTunneldMessage(t, tunneld, tunneldMessage{Type: tunneldMsgError, Error: why})
	tunneld.Close()

	done := make(chan error, 1)
	go func() { done <- serveSentry(helperEnd, cl) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serveSentry ended successfully after tunneld refused the attach, so the helper would exit 0 and leave the sandbox unpoliced")
		}
		if !strings.Contains(err.Error(), why) {
			t.Errorf("serveSentry said %q, wanted the reason tunneld gave", err)
		}
	case <-time.After(serveWait):
		t.Fatalf("serveSentry is still waiting after %v, on a sentry that has not gone away", serveWait)
	}
}

// TestTunnelHelperEndsCleanlyWhenTheSentryGoesAway is the ordinary end, and it
// is here so that the check above cannot be satisfied by a helper that exits
// non-zero whatever happens: the workload finishing is not a failure.
func TestTunnelHelperEndsCleanlyWhenTheSentryGoesAway(t *testing.T) {
	cl, tunneld := tunneldPair(t)
	if m := readTunneldMessage(t, tunneld); m.Type != tunneldMsgAttach {
		t.Fatalf("the helper's first message is a %q, wanted %q", m.Type, tunneldMsgAttach)
	}
	sentry, helperEnd := sentryChannel(t)

	done := make(chan error, 1)
	go func() { done <- serveSentry(helperEnd, cl) }()
	sentry.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveSentry said %v, wanted a clean end when the sentry closed the channel", err)
		}
	case <-time.After(serveWait):
		t.Fatalf("serveSentry is still waiting %v after the sentry closed the channel", serveWait)
	}
}

// TestTunnelHelperOutlivesATunneldThatSaysNothing: a tunneld that merely goes
// away is not the end of the helper. Every later Open answers "unavailable",
// which the sandbox sees as ENETUNREACH, and the helper stays on the sentry's
// channel until the sandbox goes — so the close alone, with no reason on the
// wire, must not end it.
func TestTunnelHelperOutlivesATunneldThatSaysNothing(t *testing.T) {
	cl, tunneld := tunneldPair(t)
	if m := readTunneldMessage(t, tunneld); m.Type != tunneldMsgAttach {
		t.Fatalf("the helper's first message is a %q, wanted %q", m.Type, tunneldMsgAttach)
	}
	sentry, helperEnd := sentryChannel(t)

	done := make(chan error, 1)
	go func() { done <- serveSentry(helperEnd, cl) }()
	tunneld.Close()
	<-cl.Done()
	select {
	case err := <-done:
		t.Fatalf("serveSentry ended with %v when tunneld closed without a reason, but the sandbox is still running", err)
	case <-time.After(250 * time.Millisecond):
	}
	sentry.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveSentry said %v, wanted a clean end when the sentry closed the channel", err)
		}
	case <-time.After(serveWait):
		t.Fatalf("serveSentry is still waiting %v after the sentry closed the channel", serveWait)
	}
}

// controlSocketPair binds a path the way runsc binds the sentry's control
// socket — bound and not listening, so a connect to it is refused — and hands
// back the path and the socket, so that a test can start listening on it later.
func controlSocketPair(t *testing.T) (string, *unet.ServerSocket) {
	t.Helper()
	// Short, because a sockaddr_un holds 108 bytes and t.TempDir is already
	// most of one on some machines.
	dir, err := os.MkdirTemp("", "th")
	if err != nil {
		t.Fatalf("a directory for the control socket: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "runsc-c.sock")
	ss, err := unet.Bind(path, false)
	if err != nil {
		t.Fatalf("binding %s: %v", path, err)
	}
	t.Cleanup(func() { ss.Close() })
	return path, ss
}

// Policy is the object the fake control server registers, named for the sentry's
// own so that urpc resolves boot.PolicyNarrow — urpc takes a method's name from
// the type that carries it.
type Policy struct {
	digest string
}

// Narrow answers one push the way the sentry's does.
func (p *Policy) Narrow(args *boot.PolicyNarrowArgs, result *boot.PolicyNarrowResult) error {
	if len(args.Policy) == 0 {
		return fmt.Errorf("policy refused: no document")
	}
	result.Digest = p.digest
	return nil
}

// serveControl accepts one connection on a socket that is now listening and
// answers Policy.Narrow on it, which is the sentry's control server reduced to
// the one call this helper makes.
func serveControl(t *testing.T, ss *unet.ServerSocket, digest string) {
	t.Helper()
	if err := ss.Listen(); err != nil {
		t.Errorf("listening on the control socket: %v", err)
		return
	}
	go func() {
		conn, err := ss.Accept()
		if err != nil {
			return
		}
		server := urpc.NewServer()
		server.Register(&Policy{digest: digest})
		server.StartHandling(conn)
	}()
}

// TestTunnelHelperWaitsForTheSentryToListenOnItsControlSocket is ticket 27's
// finding 6, and the reason the loopback proof's early-push run was refused
// before it: runsc binds the control socket and donates it before the sandbox
// process starts, the sentry listens on it some hundreds of milliseconds later,
// and this helper attaches to tunneld as the enforcing client at once — inside
// that window. A push handed to it in there used to come back "reaching the
// sentry at …: connection refused", which is a refusal that says nothing about
// the document and leaves the workload running with no policy.
//
// What is asserted is both halves: that an apply made while the socket is only
// bound does not come back refused, and that once the sentry listens the same
// apply carries the digest the sentry named.
func TestTunnelHelperWaitsForTheSentryToListenOnItsControlSocket(t *testing.T) {
	path, ss := controlSocketPair(t)
	applier := newPolicyApplier(path)

	const digest = "3d1f2ab0"
	type answer struct {
		digest string
		err    error
		took   time.Duration
	}
	answered := make(chan answer, 1)
	began := time.Now()
	go func() {
		d, err := applier.narrow([]byte(`{"format":"policy","version":1}`))
		answered <- answer{digest: d, err: err, took: time.Since(began)}
	}()

	// Nothing is listening yet, so a helper that dialled once is already done
	// and refused.
	const refusedWindow = 300 * time.Millisecond
	select {
	case a := <-answered:
		t.Fatalf("narrow came back after %v with digest %q and err %v, while the control socket was bound and nobody was listening on it: a push that lands in that window is refused for a reason that is nothing about the document", a.took, a.digest, a.err)
	case <-time.After(refusedWindow):
	}

	serveControl(t, ss, digest)
	select {
	case a := <-answered:
		if a.err != nil {
			t.Fatalf("narrow said %v once the sentry was listening", a.err)
		}
		if a.digest != digest {
			t.Errorf("narrow carried digest %q, wanted the one the sentry named, %q", a.digest, digest)
		}
		if a.took < refusedWindow {
			t.Errorf("narrow answered in %v, which is less than the %v it spent waiting: it cannot have made the call after the sentry listened", a.took, refusedWindow)
		}
		if a.took > narrowConnectWait {
			t.Errorf("narrow answered in %v, past the %v it is bounded at", a.took, narrowConnectWait)
		}
	case <-time.After(serveWait):
		t.Fatalf("narrow is still waiting %v after the sentry started listening", serveWait)
	}
}

// TestTunnelHelperGivesUpOnASentryThatNeverListens is the other end of the wait:
// it is bounded, and what it says when it runs out names the socket and the
// reason, so a sandbox that never came up is told apart from one that was slow.
func TestTunnelHelperGivesUpOnASentryThatNeverListens(t *testing.T) {
	path, _ := controlSocketPair(t)
	applier := newPolicyApplier(path)

	began := time.Now()
	digest, err := applier.narrow([]byte(`{"format":"policy","version":1}`))
	took := time.Since(began)
	if err == nil {
		t.Fatalf("narrow carried digest %q from a sentry that never listened", digest)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("narrow said %q, which does not name the socket it could not reach", err)
	}
	if took < narrowConnectWait {
		t.Errorf("narrow gave up after %v, before the %v it waits", took, narrowConnectWait)
	}
	if took > 2*narrowConnectWait {
		t.Errorf("narrow took %v to give up on a %v wait", took, narrowConnectWait)
	}
}
