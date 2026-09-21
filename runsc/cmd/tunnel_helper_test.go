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
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
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
