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

// The tunnel helper's client for tunneld's local socket.
//
// This is attest/sandbox's Client, the OPEN half of it, written again here.
// It is written again rather than imported because attest/ is a separate Go
// module with no bazel packages, and runsc is built by bazel: the helper is a
// runsc subcommand, so it can carry nothing out of that module. The protocol
// it speaks is attest/sandbox/socket.go's and is deliberately small — a
// four-byte big-endian length, that many bytes of JSON, and for a stream reply
// one descriptor in the ancillary data of the message that carries the length.
// If attest/sandbox ever gains BUILD files this file should go and the package
// be imported instead; that is recorded as this ticket's one finding about
// attest/, which is out of scope here.

package cmd

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The message types this helper uses. The sandbox side of the contract also
// has accept, which a helper that only dials out never sends.
const (
	tunneldMsgAttach  = "attach"
	tunneldMsgOpen    = "open"
	tunneldMsgStream  = "stream"
	tunneldMsgError   = "error"
	tunneldMsgApply   = "apply"
	tunneldMsgAck     = "ack"
	tunneldMsgRefusal = "refusal"
	// tunneldMsgAlive is contract v3's one addition: a sandbox that has
	// acknowledged a policy says, once a second and with no reply, which
	// policy it is enforcing. It carries id 0 because it answers nothing and
	// nothing answers it.
	tunneldMsgAlive = "alive"
)

// Roles declared in an attach message (contract v4).
const (
	tunneldRoleEnforcing = "enforcing"
	tunneldRoleNetwork   = "network"
)

const (
	tunneldHeaderSize = 4
	tunneldMaxMessage = 4 << 20
)

// tunneldMessage is every field any message carries; the type says which of
// them mean anything.
type tunneldMessage struct {
	ID       uint64          `json:"id"`
	Type     string          `json:"type"`
	Role     string          `json:"role,omitempty"`
	Peer     string          `json:"peer,omitempty"`
	Attested json.RawMessage `json:"attested,omitempty"`
	Policy   []byte          `json:"policy,omitempty"`
	Error    string          `json:"error,omitempty"`
	Digest   string          `json:"digest,omitempty"`
}

// errTunneldClosed reports that the socket to tunneld has gone.
var errTunneldClosed = errors.New("the tunneld socket closed")

// tunneldReply is one answer as it comes off the socket.
type tunneldReply struct {
	m tunneldMessage
	f *os.File
}

// tunneldClient is one connection to tunneld.
type tunneldClient struct {
	c *net.UnixConn

	// apply answers a pushed policy. Ticket 25 logs and acknowledges; ticket
	// 26 is where a policy is enforced.
	apply func(policy []byte) error
	logf  func(string, ...any)

	sendMu sync.Mutex

	mu      sync.Mutex
	next    uint64
	wait    map[uint64]chan tunneldReply
	lastErr error
	closed  bool
	done    chan struct{}
}

// dialTunneld connects to tunneld's socket, sends an attach message declaring
// its role (contract v4), and starts reading it.
func dialTunneld(path string, role string, apply func([]byte) error, logf func(string, ...any)) (*tunneldClient, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("dialing tunneld at %s: %w", path, err)
	}
	cl, err := attachTunneld(c, role, apply, logf)
	if err != nil {
		return nil, fmt.Errorf("attaching to tunneld at %s: %w", path, err)
	}
	return cl, nil
}

// attachTunneld declares this client's role on a socket already connected and
// starts reading it. It takes ownership of c.
//
// dialTunneld is the only caller that has a path to dial; the attach and
// everything that happens after it are here so that a test can drive them over
// a socketpair, with tunneld's side of the wire in its own hands.
func attachTunneld(c *net.UnixConn, role string, apply func([]byte) error, logf func(string, ...any)) (*tunneldClient, error) {
	cl := &tunneldClient{
		c:     c,
		apply: apply,
		logf:  logf,
		wait:  map[uint64]chan tunneldReply{},
		done:  make(chan struct{}),
	}
	if err := cl.send(tunneldMessage{Type: tunneldMsgAttach, Role: role}, -1); err != nil {
		c.Close()
		return nil, err
	}
	go cl.serve()
	return cl, nil
}

// Close gives up the socket. Streams already received are unaffected: each is
// its own descriptor.
func (cl *tunneldClient) Close() error {
	cl.mu.Lock()
	if cl.closed {
		cl.mu.Unlock()
		return nil
	}
	cl.closed = true
	close(cl.done)
	cl.mu.Unlock()
	return cl.c.Close()
}

// open asks tunneld for a stream to a peer and returns the descriptor it sent.
//
// It is bounded. A tunneld that accepted the request and then wedged would
// otherwise hold this call for ever, and the call this one answers is the
// sentry's, made from the task that is inside connect(2) — so an unbounded
// wait here is a workload thread that cannot be interrupted and, because the
// sentry serialises calls on the helper channel, every other connect behind
// it. The deadline covers the whole exchange; the CONNECT/OK line has its own
// on top of it.
//
// The sentry side of that call is still a blocking Go call serialised by the
// Tunnel's mutex, so the worst case is one workload thread held for this long
// rather than for ever. Making it interruptible is a leftover.
func (cl *tunneldClient) open(peer string) (*os.File, error) {
	id, ch := cl.begin()
	// end disposes of a descriptor that arrives after this returns, so a
	// request abandoned at the deadline cannot leak the stream it was given.
	defer cl.end(id, ch)
	if err := cl.send(tunneldMessage{ID: id, Type: tunneldMsgOpen, Peer: peer}, -1); err != nil {
		return nil, err
	}
	timer := time.NewTimer(openDeadline)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.m.Type != tunneldMsgStream {
			if r.f != nil {
				r.f.Close()
			}
			if r.m.Error == "" {
				return nil, fmt.Errorf("tunneld sent a %q message where a stream was expected", r.m.Type)
			}
			return nil, errors.New(r.m.Error)
		}
		if r.f == nil {
			return nil, fmt.Errorf("tunneld's stream reply carried no descriptor")
		}
		return r.f, nil
	case <-timer.C:
		return nil, fmt.Errorf("tunneld did not answer an open for peer %q within %v", peer, openDeadline)
	case <-cl.done:
		return nil, errTunneldClosed
	}
}

func (cl *tunneldClient) begin() (uint64, chan tunneldReply) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.next++
	ch := make(chan tunneldReply, 1)
	cl.wait[cl.next] = ch
	return cl.next, ch
}

// end drops a request's slot and closes anything that arrived after the caller
// stopped waiting, so a cancelled request cannot leak the descriptor its answer
// was carrying.
func (cl *tunneldClient) end(id uint64, ch chan tunneldReply) {
	cl.mu.Lock()
	delete(cl.wait, id)
	cl.mu.Unlock()
	select {
	case r := <-ch:
		if r.f != nil {
			r.f.Close()
		}
	default:
	}
}

// send writes one message, with fd in its ancillary data when fd is not
// negative.
func (cl *tunneldClient) send(m tunneldMessage, fd int) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encoding a %s message: %w", m.Type, err)
	}
	buf := make([]byte, tunneldHeaderSize+len(body))
	binary.BigEndian.PutUint32(buf[:tunneldHeaderSize], uint32(len(body)))
	copy(buf[tunneldHeaderSize:], body)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	cl.sendMu.Lock()
	defer cl.sendMu.Unlock()
	n, _, err := cl.c.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return err
	}
	for n < len(buf) {
		more, err := cl.c.Write(buf[n:])
		if err != nil {
			return err
		}
		n += more
	}
	return nil
}

// serve reads tunneld's messages until the socket goes.
func (cl *tunneldClient) serve() {
	defer cl.Close()
	for {
		m, f, err := cl.receive()
		if err != nil {
			if f != nil {
				f.Close()
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				cl.logf("the tunneld socket ended: %v", err)
			}
			return
		}
		switch m.Type {
		case tunneldMsgStream, tunneldMsgError:
			cl.deliver(tunneldReply{m: m, f: f})
		case tunneldMsgApply:
			if f != nil {
				f.Close()
			}
			go cl.applied(m)
		default:
			if f != nil {
				f.Close()
			}
			cl.send(tunneldMessage{ID: m.ID, Type: tunneldMsgRefusal, Error: "unknown message type " + m.Type}, -1)
		}
	}
}

// applied answers one pushed policy. Ticket 25 accepts and logs it and
// enforces nothing: what a policy means to a sandbox is ticket 26's, and a
// helper that refused every push would make this sandbox look to tunneld like
// one that takes no policy at all.
func (cl *tunneldClient) applied(m tunneldMessage) {
	if err := cl.apply(m.Policy); err != nil {
		cl.send(tunneldMessage{ID: m.ID, Type: tunneldMsgRefusal, Error: err.Error()}, -1)
		return
	}
	cl.send(tunneldMessage{ID: m.ID, Type: tunneldMsgAck}, -1)
}

func (cl *tunneldClient) deliver(r tunneldReply) {
	if r.m.ID == 0 && r.m.Error != "" {
		cl.mu.Lock()
		cl.lastErr = errors.New(r.m.Error)
		cl.mu.Unlock()
	}
	cl.mu.Lock()
	ch := cl.wait[r.m.ID]
	delete(cl.wait, r.m.ID)
	cl.mu.Unlock()
	if ch == nil {
		if r.f != nil {
			r.f.Close()
		}
		return
	}
	ch <- r
}

// Done returns a channel that is closed when the socket to tunneld closes.
func (cl *tunneldClient) Done() <-chan struct{} {
	return cl.done
}

// Err returns the error that closed the connection, if any was recorded.
func (cl *tunneldClient) Err() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.lastErr
}

// receive reads one message and the descriptor it carried, if any.
func (cl *tunneldClient) receive() (tunneldMessage, *os.File, error) {
	var header [tunneldHeaderSize]byte
	f, err := cl.readHeader(header[:])
	if err != nil {
		return tunneldMessage{}, f, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > tunneldMaxMessage {
		return tunneldMessage{}, f, fmt.Errorf("tunneld declared %d bytes, over the %d byte maximum", length, tunneldMaxMessage)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(cl.c, body); err != nil {
		return tunneldMessage{}, f, err
	}
	var m tunneldMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return tunneldMessage{}, f, fmt.Errorf("a %d byte message from tunneld that is not JSON: %w", length, err)
	}
	return m, f, nil
}

// readHeader fills p, collecting the one descriptor a message may carry
// whichever read it arrives on.
func (cl *tunneldClient) readHeader(p []byte) (*os.File, error) {
	oob := make([]byte, unix.CmsgSpace(4))
	var f *os.File
	for read := 0; read < len(p); {
		n, oobn, _, _, err := cl.c.ReadMsgUnix(p[read:], oob)
		if oobn > 0 {
			got, perr := tunneldRights(oob[:oobn])
			if perr != nil {
				return f, perr
			}
			if f != nil {
				f.Close()
				got.Close()
				return nil, fmt.Errorf("a message from tunneld carried more than one descriptor")
			}
			f = got
		}
		if err != nil {
			return f, err
		}
		if n == 0 {
			return f, io.EOF
		}
		read += n
	}
	return f, nil
}

// tunneldRights turns one SCM_RIGHTS control message into the file it carries.
func tunneldRights(oob []byte) (*os.File, error) {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(scms) != 1 {
		return nil, fmt.Errorf("parsing the control message: %v (%d messages)", err, len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("parsing the rights: %v (%d descriptors)", err, len(fds))
	}
	return os.NewFile(uintptr(fds[0]), "tunneld-stream"), nil
}
