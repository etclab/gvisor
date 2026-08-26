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

// Package tunnel is the transport: QUIC with TLS 1.3, one exchange per stream.
//
// It knows nothing about attestation. The TLS configuration it is handed
// already decides who is admitted (see package ratls); this package's job is
// to refuse early data, carry an exchange under the framing below, and
// nothing more. Connection caching and idle and age limits arrive with
// ticket 12 and belong here when they do.
package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// establishmentTimeout bounds how long a peer that completed the handshake
// may take to open its establishment stream. Without it, one such peer would
// hold the listener's accept path. Ticket 12's idle timeout subsumes this.
const establishmentTimeout = 10 * time.Second

// ErrListenerClosed is what Accept returns once the listener is closed. It is
// the only error Accept returns other than the caller's context ending: a
// peer that fails establishment is dropped without disturbing Accept.
var ErrListenerClosed = errors.New("tunnel: listener closed")

// Early data is refused on both ends. A listener's Allow0RTT stays false, and
// the dial path is quic.DialAddr rather than DialAddrEarly, so a replayed
// privileged exchange has no 0-RTT slot to ride in on.
func config() *quic.Config {
	return &quic.Config{Allow0RTT: false}
}

// Listener accepts tunnels.
//
// Handshake-complete connections are taken off the QUIC listener as they
// arrive and each answers its establishment round trip on its own goroutine,
// so that neither a peer that never opens the stream nor one that breaks it
// can hold up any other peer's establishment.
type Listener struct {
	l           *quic.Listener
	established chan *Conn
	done        chan struct{}
}

// Listen binds a UDP address. Pass a port of 0 to take an ephemeral one and
// read it back through Addr.
func Listen(addr string, tlsConf *tls.Config) (*Listener, error) {
	l, err := quic.ListenAddr(addr, tlsConf, config())
	if err != nil {
		return nil, fmt.Errorf("tunnel: listening on %s: %w", addr, err)
	}
	ln := &Listener{l: l, established: make(chan *Conn), done: make(chan struct{})}
	go ln.run()
	return ln, nil
}

func (l *Listener) run() {
	defer close(l.done)
	for {
		c, err := l.l.Accept(context.Background())
		if err != nil {
			return // The only error a background Accept yields is closure.
		}
		go l.establish(c)
	}
}

func (l *Listener) establish(c *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), establishmentTimeout)
	defer cancel()
	if err := answerEstablishment(ctx, c); err != nil {
		c.CloseWithError(errProtocol, "establishment")
		return
	}
	select {
	case l.established <- &Conn{c: c}:
	case <-l.done:
		c.CloseWithError(0, "")
	}
}

// Addr is the bound address.
func (l *Listener) Addr() net.Addr { return l.l.Addr() }

// Accept returns the next connection whose handshake completed — which, with
// ratls in the TLS configuration, means this side verified the peer — and
// whose establishment round trip has been answered, which is what tells the
// peer that it happened. It returns an error only when ctx ends or the
// listener is closed.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.established:
		return c, nil
	case <-l.done:
		return nil, ErrListenerClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops accepting. Established connections are unaffected.
func (l *Listener) Close() error {
	err := l.l.Close()
	<-l.done
	return err
}

// Dial establishes a connection to addr. It returns only once both sides
// have accepted the other's evidence: ours by the time the QUIC handshake
// returns, the peer's by the time the establishment round trip completes.
//
// TLS 1.3 lets a client finish its handshake before the server has judged
// the client's certificate, so the QUIC dial alone can return a connection
// the peer is about to close with a refusal — a connection that exists and
// then rejects, which is the state this design forbids. One application
// round trip closes that window (spec, Transport): the peer only answers a
// stream on a connection it has admitted.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config) (*Conn, error) {
	c, err := quic.DialAddr(ctx, addr, tlsConf, config())
	if err != nil {
		return nil, fmt.Errorf("tunnel: dialing %s: %w", addr, err)
	}
	if err := establish(ctx, c); err != nil {
		c.CloseWithError(errProtocol, "establishment")
		return nil, fmt.Errorf("tunnel: dialing %s: %w", addr, err)
	}
	return &Conn{c: c}, nil
}

// errProtocol is the application error code a connection is closed with
// when its peer breaks the framing.
const errProtocol quic.ApplicationErrorCode = 1

// The establishment round trip is the dialer's first stream: empty in both
// directions, closed by the dialer, then closed by the listener. It carries
// nothing because it needs to carry nothing — the fact that the listener
// answered is the message. The dialer opens no other stream before it has
// completed, so the listener's first stream is always this one.

func establish(ctx context.Context, c *quic.Conn) error {
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	reply, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if len(reply) != 0 {
		return fmt.Errorf("peer sent %d bytes in reply to establishment", len(reply))
	}
	return nil
}

func answerEstablishment(ctx context.Context, c *quic.Conn) error {
	s, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	probe, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if len(probe) != 0 {
		return fmt.Errorf("peer sent %d bytes as establishment", len(probe))
	}
	return s.Close()
}

// The exchange frame
//
// An exchange occupies exactly one stream in each direction and is carried as
// a single frame: a four-byte big-endian payload length, that many payload
// bytes, and then end-of-stream. Nothing may follow the frame.
//
// The length prefix is what makes "trailing bytes are a protocol violation"
// (CONTEXT.md, Exchange) a check a receiver can actually make. A stream is a
// byte stream, so a sender that framed a second message behind the first —
// two lengths and two payloads on one stream — would be indistinguishable
// from one long message to a receiver that only read to end-of-stream, and
// would be two exchanges to a receiver that looped over frames. Reading
// exactly one frame and then requiring end-of-stream refuses both readings:
// one stream is one exchange, and a second message needs a second stream,
// where it is subject to every check the first was.

// frameHeaderSize is the width of the big-endian payload length prefix.
const frameHeaderSize = 4

// maxFramePayload bounds a declared length. Without it the four-byte prefix
// invites a peer to declare four gigabytes and have the receiver allocate
// them before a single payload byte arrives. It is a framing bound, not a
// policy one; nothing in this design needs an exchange anywhere near it.
const maxFramePayload = 16 << 20

// ErrFraming reports a peer that broke the exchange framing: a truncated
// frame, a length beyond the bound, or bytes after the frame. It is a
// protocol violation and the connection it happened on does not survive it.
var ErrFraming = errors.New("tunnel: framing violation")

// writeFrame sends payload as one frame and closes the write side, which is
// the end-of-stream the peer reads to.
func writeFrame(s *quic.Stream, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("%w: %d bytes exceeds the %d byte maximum", ErrFraming, len(payload), maxFramePayload)
	}
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := s.Write(header[:]); err != nil {
		return err
	}
	if _, err := s.Write(payload); err != nil {
		return err
	}
	return s.Close()
}

// readFrame reads one frame and then requires end-of-stream. Every way the
// bytes on the stream fail to be exactly one frame — short header, oversized
// length, short payload, or anything at all after the payload — comes back
// wrapping ErrFraming.
func readFrame(s *quic.Stream) ([]byte, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		if isEOF(err) {
			return nil, fmt.Errorf("%w: stream ended inside the frame header", ErrFraming)
		}
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFramePayload {
		return nil, fmt.Errorf("%w: peer declared %d bytes, over the %d byte maximum", ErrFraming, length, maxFramePayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(s, payload); err != nil {
		if isEOF(err) {
			return nil, fmt.Errorf("%w: stream ended inside a %d byte payload", ErrFraming, length)
		}
		return nil, err
	}
	// One exchange per stream: what follows the frame must be nothing.
	var trailing [1]byte
	switch _, err := io.ReadFull(s, trailing[:]); {
	case errors.Is(err, io.EOF):
		return payload, nil
	case err != nil:
		return nil, err
	default:
		return nil, fmt.Errorf("%w: peer sent trailing bytes after the frame", ErrFraming)
	}
}

// isEOF reports whether err is the stream ending where more of the frame was
// expected — a short frame either way, whether the peer stopped on a header
// boundary or inside a payload.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// Conn is one established tunnel.
type Conn struct {
	c *quic.Conn
}

// Exchange sends one request as a frame on a fresh stream and returns the
// peer's response frame. Concurrent calls on one Conn each take their own
// stream and neither waits on the other: that is the whole reason the
// transport is QUIC rather than one TLS connection per tunnel.
func (c *Conn) Exchange(ctx context.Context, request []byte) ([]byte, error) {
	s, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: opening a stream: %w", err)
	}
	if err := writeFrame(s, request); err != nil {
		s.CancelWrite(0)
		s.CancelRead(0)
		return nil, fmt.Errorf("tunnel: sending the request: %w", err)
	}
	response, err := readFrame(s)
	if err != nil {
		s.CancelRead(0)
		c.refuse(err)
		return nil, fmt.Errorf("tunnel: reading the response: %w", err)
	}
	return response, nil
}

// refuse ends the connection when err is a framing violation. A peer that
// cannot frame is not one to keep a tunnel to, and leaving the connection up
// would mean the bytes it smuggled were merely discarded rather than
// refused. Errors that are not framing violations leave it alone.
func (c *Conn) refuse(err error) {
	if errors.Is(err, ErrFraming) {
		c.c.CloseWithError(errProtocol, "framing")
	}
}

// Handler answers one exchange.
type Handler func(ctx context.Context, request []byte) ([]byte, error)

// Serve answers exchanges on c until the connection ends. Each stream is one
// exchange, answered on its own goroutine so that a slow handler holds up
// only its own caller; a handler error closes that stream without a
// response, and a peer that breaks the framing ends the connection.
func (c *Conn) Serve(handler Handler) error {
	for {
		s, err := c.c.AcceptStream(c.c.Context())
		if err != nil {
			return err
		}
		go func() {
			request, err := readFrame(s)
			if err != nil {
				s.CancelWrite(0)
				s.CancelRead(0)
				c.refuse(err)
				return
			}
			response, err := handler(c.c.Context(), request)
			if err != nil {
				s.CancelWrite(0)
				return
			}
			if err := writeFrame(s, response); err != nil {
				s.CancelWrite(0)
			}
		}()
	}
}

// Close ends the connection.
func (c *Conn) Close() error { return c.c.CloseWithError(0, "") }
