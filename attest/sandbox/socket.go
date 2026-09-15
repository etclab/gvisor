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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The local socket protocol: the same three verbs, with a process boundary in
// the middle.
//
// Tunneld listens on an AF_UNIX SOCK_STREAM socket; a sandbox beside it
// connects. Every message is a four-byte big-endian length and that many bytes
// of JSON, which is the same framing package tunnel uses on a stream and is
// deliberately the dullest thing that works — this socket carries three verbs
// between two processes on one machine, and a protocol worth studying here
// would be a protocol worth attacking here.
//
// Messages, and who sends them:
//
//	{"id":1,"type":"open","peer":"b"}                       sandbox → tunneld
//	{"id":1,"type":"stream"}                 + one fd       tunneld → sandbox
//	{"id":2,"type":"accept"}                                sandbox → tunneld
//	{"id":2,"type":"stream","attested":{…}}  + one fd       tunneld → sandbox
//	{"id":n,"type":"error","error":"…"}                     tunneld → sandbox
//	{"id":7,"type":"apply","policy":"<base64>"}             tunneld → sandbox
//	{"id":7,"type":"ack"}                                   sandbox → tunneld
//	{"id":7,"type":"refusal","error":"…"}                   sandbox → tunneld
//
// Requests travel in both directions — the sandbox asks for streams, tunneld
// pushes policy — so each side numbers its own requests and a reply carries the
// id of the request it answers. The two id spaces never meet, because the types
// say which direction a message came from: nothing the sandbox sends is a type
// tunneld sends. Requests may be outstanding concurrently and are answered in
// whatever order they finish; ACCEPT in particular blocks until a peer opens a
// stream, and an APPLY sent while it is outstanding is answered without waiting
// for it.
//
// The descriptor is the point of the whole thing. A `stream` reply is sent with
// one end of a socketpair in its ancillary data (SCM_RIGHTS), and tunneld keeps
// the other end and pumps it against the tunnel's stream. A QUIC stream cannot
// itself be passed — it is not a kernel object, and the one descriptor in the
// picture is the transport's UDP socket, which carries every connection at once
// and is useless without the keys in tunneld's heap (spike E1). The socketpair
// is the price of the boundary: one extra hop each way, measured at 40–80 µs of
// added round-trip latency and under a quarter of single-stream bulk
// throughput.
//
// Ancillary data and stream sockets agree on one thing this relies on: the
// kernel never merges bytes written with descriptors attached into a read of
// bytes written without them. Each message is written with a single sendmsg, so
// the receiver that reads a four-byte header gets that message's descriptor
// with it and never the next message's.

// The message types. Three from the sandbox, three from tunneld, and one —
// `stream` — that is a reply to either of the sandbox's two requests.
const (
	msgOpen    = "open"
	msgAccept  = "accept"
	msgAck     = "ack"
	msgRefusal = "refusal"

	msgStream = "stream"
	msgError  = "error"
	msgApply  = "apply"
)

// A message is every field any of the seven messages carries. One struct
// rather than seven keeps the decoder trivial; the type field says which fields
// mean anything.
type message struct {
	ID       uint64    `json:"id"`
	Type     string    `json:"type"`
	Peer     string    `json:"peer,omitempty"`
	Attested *Attested `json:"attested,omitempty"`
	Policy   []byte    `json:"policy,omitempty"`
	Error    string    `json:"error,omitempty"`
}

const (
	// headerSize is the width of the big-endian length prefix.
	headerSize = 4

	// maxMessage bounds a declared length, for the same reason package tunnel
	// bounds a frame: a four-byte prefix otherwise invites a peer to declare
	// four gigabytes and have the receiver allocate them. Four mebibytes is a
	// quarter of the tunnel's own frame bound and 64 times the largest policy
	// this design has pushed.
	maxMessage = 4 << 20
)

// ErrProtocol reports a peer on this socket that broke the framing. The
// connection it happened on does not survive it.
var ErrProtocol = errors.New("sandbox: local protocol violation")

// a wire is one end of the socket, with the write side serialised. Reads are
// not: one goroutine per connection does all of them.
type wire struct {
	c *net.UnixConn

	mu sync.Mutex
}

// send writes one message, with fd in its ancillary data when fd is not
// negative. The whole message goes out in one sendmsg where the socket buffer
// allows it, so that the descriptor arrives attached to the length prefix.
func (w *wire) send(m message, fd int) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("sandbox: encoding a %s message: %w", m.Type, err)
	}
	if len(body) > maxMessage {
		return fmt.Errorf("%w: a %s message of %d bytes exceeds the %d byte maximum", ErrProtocol, m.Type, len(body), maxMessage)
	}
	buf := make([]byte, headerSize+len(body))
	binary.BigEndian.PutUint32(buf[:headerSize], uint32(len(body)))
	copy(buf[headerSize:], body)

	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n, _, err := w.c.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return err
	}
	// A sendmsg may be short where a large policy meets a small socket buffer.
	// The rest is plain data: the descriptor went with the first byte.
	for n < len(buf) {
		more, err := w.c.Write(buf[n:])
		if err != nil {
			return err
		}
		n += more
	}
	return nil
}

// receive reads one message and the descriptor it carried, if any.
func (w *wire) receive() (message, *os.File, error) {
	var header [headerSize]byte
	f, err := w.readHeader(header[:])
	if err != nil {
		if f != nil {
			f.Close()
		}
		return message{}, nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxMessage {
		if f != nil {
			f.Close()
		}
		return message{}, nil, fmt.Errorf("%w: peer declared %d bytes, over the %d byte maximum", ErrProtocol, length, maxMessage)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(w.c, body); err != nil {
		if f != nil {
			f.Close()
		}
		return message{}, nil, err
	}
	var m message
	if err := json.Unmarshal(body, &m); err != nil {
		if f != nil {
			f.Close()
		}
		return message{}, nil, fmt.Errorf("%w: a %d byte message that is not JSON: %v", ErrProtocol, length, err)
	}
	return m, f, nil
}

// readHeader fills p, collecting the one descriptor a message may carry
// whichever read it arrives on.
func (w *wire) readHeader(p []byte) (*os.File, error) {
	oob := make([]byte, unix.CmsgSpace(4))
	var f *os.File
	for read := 0; read < len(p); {
		n, oobn, _, _, err := w.c.ReadMsgUnix(p[read:], oob)
		if oobn > 0 {
			got, perr := rights(oob[:oobn])
			if perr != nil {
				return f, perr
			}
			if f != nil {
				// Two descriptors for one message: refuse both rather than
				// guess which one the sender meant.
				f.Close()
				got.Close()
				return nil, fmt.Errorf("%w: a message carried more than one descriptor", ErrProtocol)
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

// rights turns one SCM_RIGHTS control message into the file it carries.
func rights(oob []byte) (*os.File, error) {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(scms) != 1 {
		return nil, fmt.Errorf("%w: parsing the control message: %v (%d messages)", ErrProtocol, err, len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("%w: parsing the rights: %v (%d descriptors)", ErrProtocol, err, len(fds))
	}
	return os.NewFile(uintptr(fds[0]), "sandbox-stream"), nil
}

// handoff makes the socketpair a stream crosses the process boundary on: it
// starts the pump on one end and returns the other, which the caller sends and
// then closes.
func handoff(s Stream) (*os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("sandbox: socketpair: %w", err)
	}
	local, err := connFromFD(fds[0], "sandbox-pump")
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		return nil, err
	}
	go pump(s, local)
	return os.NewFile(uintptr(fds[1]), "sandbox-stream"), nil
}

// pump carries bytes between a tunnel stream and the socketpair the sandbox
// holds the other end of, and carries the end of the byte stream in each
// direction with them.
//
// The two half-closes are the whole reason this is not one io.Copy per
// direction and nothing else. The sandbox finishing what it had to say arrives
// here as end-of-file on the socketpair and must become a half-close on the
// stream, or the peer waits for a request that is already complete; the peer
// finishing its answer arrives as end-of-file on the stream and must become a
// half-close toward the sandbox, or the sandbox waits for a response that has
// already arrived whole. A copy loop that moved only bytes would deadlock both
// sides of every request-response protocol anybody would put over this.
//
// What it cannot carry is a reset: SOCK_STREAM has no signal for one, so a
// peer that cancelled a stream and a peer that finished it look alike from
// inside the sandbox (spike E1).
func pump(s Stream, local *net.UnixConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(s, local)
		s.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, s)
		local.CloseWrite()
	}()
	wg.Wait()
	local.Close()
	s.Close()
}

// connFromFD turns a descriptor into a plain net.Conn. net.FileConn dups it,
// so the file this wraps is closed here and the caller keeps only the
// connection.
func connFromFD(fd int, name string) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("sandbox: %d is not a valid descriptor", fd)
	}
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("sandbox: %s: %w", name, err)
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("sandbox: %s is a %T, not a unix socket", name, c)
	}
	return u, nil
}

// a reply is one answer as it comes off the socket: the message, and the
// descriptor it carried if it was a stream.
type reply struct {
	m message
	f *os.File
}

func (r reply) discard() {
	if r.f != nil {
		r.f.Close()
	}
}

// pending is the reply table one side of the socket keeps for the requests it
// has outstanding. Both sides make requests, so both keep one.
type pending struct {
	mu   sync.Mutex
	next uint64
	wait map[uint64]chan reply
}

func (p *pending) begin() (uint64, chan reply) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wait == nil {
		p.wait = map[uint64]chan reply{}
	}
	p.next++
	ch := make(chan reply, 1)
	p.wait[p.next] = ch
	return p.next, ch
}

// end drops a request's slot and closes anything that arrived for it after the
// caller stopped waiting, so that a cancelled request cannot leak the
// descriptor its answer was carrying.
func (p *pending) end(id uint64, ch chan reply) {
	p.mu.Lock()
	delete(p.wait, id)
	p.mu.Unlock()
	select {
	case r := <-ch:
		r.discard()
	default:
	}
}

// deliver hands a reply to whoever is waiting for it, and drops one nobody is.
func (p *pending) deliver(r reply) {
	p.mu.Lock()
	ch := p.wait[r.m.ID]
	delete(p.wait, r.m.ID)
	p.mu.Unlock()
	if ch == nil {
		r.discard()
		return
	}
	ch <- r
}
