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

// Package tunnel is the transport: QUIC with TLS 1.3, one exchange per stream,
// and the cache that keeps at most one tunnel per peer alive.
//
// It knows nothing about attestation. The TLS configuration it is handed
// already decides who is admitted (see package ratls); this package's job is
// to refuse early data, carry an exchange under the framing below, hold a
// tunnel only as long as [Limits] allow, and nothing more.
package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ErrListenerClosed is what Accept returns once the listener is closed. It is
// the only error Accept returns other than the caller's context ending: a
// peer that fails establishment is dropped without disturbing Accept.
var ErrListenerClosed = errors.New("tunnel: listener closed")

// Limits bound the life of a tunnel. Both are configurable and neither may be
// switched off; a zero field takes the default beside it.
//
// The two bound different things and neither implies the other. The idle
// timeout answers "is anybody still using this", so that no component holds a
// connection open across a lull in traffic (spec, user story 42). The maximum
// age answers "how long ago was this peer judged", which is a question about
// the trust decision rather than about the traffic, and it is the one a busy
// tunnel would otherwise never be asked.
//
// Both ends enforce both. A dialer that skipped the maximum age would keep a
// tunnel forever; a listener that skipped it would let a peer keep one. A
// bound only one side enforces is a bound that depends on the other side
// choosing to respect it, which is not a bound.
type Limits struct {
	// IdleTimeout closes a tunnel that has carried nothing for this long. It
	// is the QUIC connection's own idle timeout, so both ends drop the tunnel
	// without either sending anything to keep it alive.
	//
	// Two things follow from it being QUIC's, and a two-guest deployment meets
	// both. The effective value is the *minimum* of what the two peers
	// advertise (RFC 9000 §10.1), so two tunnelds configured differently both
	// get the smaller one — configure a deployment's tunnelds alike or the
	// number in one of their configurations is fiction. And nothing is sent to
	// hold the path open, deliberately, so a middlebox between two guests that
	// drops a flow sooner than this closes the tunnel first: the re-dial covers
	// it, but in a packet trace it looks like a lost tunnel rather than like a
	// NAT.
	IdleTimeout time.Duration

	// MaxAge closes a tunnel this long after it was established, whatever it
	// is carrying, so that further traffic to that peer needs a new handshake
	// and therefore a fresh admission decision on both sides.
	MaxAge time.Duration
}

// DefaultIdleTimeout is how long a tunnel may carry nothing before it closes.
//
// A minute is long enough that a warm path survives the gaps between one
// agent's exchanges and short enough that an unused tunnel does not outlive
// the conversation that opened it. It costs a handshake to be wrong low and
// an idle connection to be wrong high, and neither is expensive.
const DefaultIdleTimeout = 60 * time.Second

// DefaultMaxAge is how long a tunnel may carry traffic before it is torn down
// and both sides have to attest to each other again.
//
// Fifteen minutes is a judgement, not a measurement, and it is worth saying
// what the judgement is. Until the freshness challenge of Milestone 5 exists,
// this number is the only bound on how long a verdict about a peer is relied
// on while traffic still flows: nothing else in this design ever re-examines a
// peer it admitted once. A tunnel that lived for a day would be a tunnel whose
// peer was last judged a day ago — against a reference value set that may
// since have been rolled, and a platform whose TCB may since have moved.
//
// It is deliberately conservative in the direction of re-attesting too often.
// Being wrong low costs one handshake and one verification, off the critical
// path of every exchange once the tunnel is warm. Being wrong high costs a
// peer that keeps a privileged channel after it should have lost it. Where the
// two costs are that asymmetric the number belongs at the cheap end, and the
// figure here is picked to sit an order of magnitude under the shortest
// operational cadence this design has — a reference value rollout — rather
// than derived from anything measured.
//
// What would change it, in the order it is likely to: the freshness challenge
// landing, which proves the platform is in the attested state now and makes
// tearing a tunnel down the wrong way to ask; a measured handshake cost that
// makes quarter-hourly re-attestation visible in the latency table (spec, user
// story 50); or a deployment whose reference value rollout is faster than
// fifteen minutes, which would want this under it.
//
// One thing it does not bound, and a reader here is the one who needs to know
// it. Re-attestation means the handshake-time gate runs again, not that fresher
// evidence exists: a tunneld acquires its evidence once at startup and holds it
// for the life of the process (spec, user story 33), so the new handshake
// re-judges the same report against each side's current reference value set.
// What this bounds is how long a verdict is relied on. How old the evidence
// under that verdict is stays bounded by process lifetime until the freshness
// challenge exists.
const DefaultMaxAge = 15 * time.Minute

func (l Limits) withDefaults() Limits {
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = DefaultIdleTimeout
	}
	if l.MaxAge <= 0 {
		l.MaxAge = DefaultMaxAge
	}
	return l
}

// Early data is refused on both ends. A listener's Allow0RTT stays false, and
// the dial path is quic.DialAddr rather than DialAddrEarly, so a replayed
// privileged exchange has no 0-RTT slot to ride in on.
//
// KeepAlivePeriod is deliberately left at zero. A keep-alive would manufacture
// exactly the traffic MaxIdleTimeout measures, so switching one on would
// quietly disable the other.
func config(l Limits) *quic.Config {
	return &quic.Config{
		Allow0RTT:      false,
		MaxIdleTimeout: l.IdleTimeout,
	}
}

// Listener accepts tunnels.
//
// Handshake-complete connections are taken off the QUIC listener as they
// arrive and each answers its establishment round trip on its own goroutine,
// so that neither a peer that never opens the stream nor one that breaks it
// can hold up any other peer's establishment.
type Listener struct {
	l           *quic.Listener
	limits      Limits
	established chan *Conn
	done        chan struct{}
}

// Listen binds a UDP address. Pass a port of 0 to take an ephemeral one and
// read it back through Addr. A zero field in limits takes its default.
func Listen(addr string, tlsConf *tls.Config, limits Limits) (*Listener, error) {
	limits = limits.withDefaults()
	l, err := quic.ListenAddr(addr, tlsConf, config(limits))
	if err != nil {
		return nil, fmt.Errorf("tunnel: listening on %s: %w", addr, err)
	}
	ln := &Listener{l: l, limits: limits, established: make(chan *Conn), done: make(chan struct{})}
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

// establishmentBound caps how long a handshake-complete peer may take to open
// its establishment stream. The idle timeout is the natural deadline — such a
// peer is an idle connection — but the idle timeout is an operator's number
// for a tunnel that has proven itself, and a peer that has not yet done so
// gets at most this much of the listener's patience.
const establishmentBound = 10 * time.Second

// establish answers one peer's establishment round trip, within the idle
// timeout or establishmentBound, whichever is shorter.
func (l *Listener) establish(c *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), min(l.limits.IdleTimeout, establishmentBound))
	defer cancel()
	if err := answerEstablishment(ctx, c); err != nil {
		c.CloseWithError(errProtocol, "establishment")
		return
	}
	select {
	case l.established <- newConn(c, l.limits):
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
//
// A zero field in limits takes its default. Dialing directly gives back a
// tunnel the caller owns and must close; [Cache] is the way to get one that is
// kept warm, re-dialed and re-attested on the caller's behalf.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config, limits Limits) (*Conn, error) {
	limits = limits.withDefaults()
	c, err := quic.DialAddr(ctx, addr, tlsConf, config(limits))
	if err != nil {
		return nil, fmt.Errorf("tunnel: dialing %s: %w", addr, err)
	}
	if err := establish(ctx, c); err != nil {
		c.CloseWithError(errProtocol, "establishment")
		return nil, fmt.Errorf("tunnel: dialing %s: %w", addr, err)
	}
	return newConn(c, limits), nil
}

// The application error codes a connection is closed with. A peer reads them,
// so they name what happened and nothing more: neither is a refusal reason,
// because a connection only reaches either state after both sides admitted
// each other.
const (
	// errProtocol closes a connection whose peer broke the framing.
	errProtocol quic.ApplicationErrorCode = 1
	// errExpired closes a connection that reached its maximum age.
	errExpired quic.ApplicationErrorCode = 2
)

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
	reply, err := readAllUntil(ctx, s)
	if err != nil {
		return err
	}
	if len(reply) != 0 {
		return fmt.Errorf("peer sent %d bytes in reply to establishment", len(reply))
	}
	return nil
}

// readAllUntil reads s to end-of-stream, giving up when ctx ends. A stream
// read does not watch a context on its own, so a peer that opens the
// establishment stream and then says nothing would otherwise hold the reader
// until the idle timeout rather than until the caller's deadline.
func readAllUntil(ctx context.Context, s *quic.Stream) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { s.SetReadDeadline(time.Now()) })
	defer stop()
	b, err := io.ReadAll(s)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return b, err
}

func answerEstablishment(ctx context.Context, c *quic.Conn) error {
	s, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	probe, err := readAllUntil(ctx, s)
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

// rawStreamMarker is the four bytes a raw stream opens with, where an exchange
// would have put its payload length. It is the whole of the wire change ticket
// 22 needed, and it is a change no existing exchange can see.
//
// A frame header is a length and a length is at most maxFramePayload, so every
// value above that bound was already a framing violation — "peer declared N
// bytes, over the maximum" — and exactly one of them is now a stream kind
// instead. An exchange's bytes are therefore byte-identical to what they were
// before this constant existed: the sender still writes a length it could
// always have written, and the receiver still reads it the same way. What
// changes is only what happens to a peer that writes 0x52415731 ("RAW1") as a
// length, which was a torn-down connection and is now a stream the sandbox
// beside this tunneld may accept.
//
// Only the side that runs [Conn.Serve] recognises it, which is the side that
// accepted the connection. A raw stream is therefore opened by the dialer and
// accepted by the listener, the same way an exchange is; bytes then flow both
// ways on it. A marker arriving where an exchange *response* was expected is
// still a framing violation, because [Conn.Exchange] reads a frame and nothing
// else.
const rawStreamMarker uint32 = 0x52415731

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
	header, err := readHeader(s)
	if err != nil {
		return nil, err
	}
	return readFramePayload(s, header)
}

// readHeader reads the four bytes every stream starts with. It is split out of
// readFrame because those four bytes are also what says whether this is a frame
// at all: [Conn.Serve] reads them once and then either finishes the frame or
// hands a raw stream over.
func readHeader(s *quic.Stream) ([frameHeaderSize]byte, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		if isEOF(err) {
			return header, fmt.Errorf("%w: stream ended inside the frame header", ErrFraming)
		}
		return header, err
	}
	return header, nil
}

// readFramePayload is the rest of the frame, given its header.
func readFramePayload(s *quic.Stream, header [frameHeaderSize]byte) ([]byte, error) {
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
	c             *quic.Conn
	establishedAt time.Time
	maxAge        time.Duration
	expiry        *time.Timer

	// raw carries the streams Serve found a rawStreamMarker on, from the
	// goroutine that read the marker to whoever is in AcceptStream. It is
	// unbuffered on purpose: a stream nobody is waiting for is a stream that
	// waits, and the goroutine holding it is one per stream, so nothing else
	// is held up by it. A peer that opens raw streams nobody accepts leaves
	// them parked until the connection reaches its idle timeout or its maximum
	// age, which is the bound on how many there can be.
	raw chan *quic.Stream
}

// newConn wraps an established QUIC connection and starts the clock on it.
//
// The maximum age is enforced here, by the connection on itself, rather than
// by whoever is holding it. That is what makes it a bound on a connection
// nobody is consulting: a listener has no cache to check ages in, and it is a
// listener that faces the peer with a reason not to give a tunnel up. A holder
// that does consult its connections — [Cache] — checks the age again when it
// hands one out, so that "before further use" does not rest on a timer having
// been scheduled promptly.
//
// A tunnel that reaches its maximum age mid-exchange takes that exchange down
// with it. That is deliberate: the alternative is waiting for quiescence,
// which is waiting for a peer to stop talking, which is exactly how a verdict
// on a busy peer would come to be relied on indefinitely. The caller sees a
// failed exchange and its next one runs over a freshly attested tunnel.
func newConn(c *quic.Conn, limits Limits) *Conn {
	conn := &Conn{c: c, establishedAt: time.Now(), maxAge: limits.MaxAge, raw: make(chan *quic.Stream)}
	conn.expiry = time.AfterFunc(limits.MaxAge, conn.closeExpired)
	// A tunnel that ends before its time — closed by either side, or dropped
	// for idleness — has nothing left to expire.
	context.AfterFunc(c.Context(), func() { conn.expiry.Stop() })
	return conn
}

// closeExpired ends the tunnel because it reached its maximum age, saying so
// on the wire. Both the timer and a holder that finds the tunnel too old use
// this, so the peer reads one code for one event.
func (c *Conn) closeExpired() { c.c.CloseWithError(errExpired, "maximum age") }

// Age is how long ago this tunnel was established.
func (c *Conn) Age() time.Duration { return time.Since(c.establishedAt) }

// Expired reports whether this tunnel has reached its maximum age and must be
// re-established, and with it re-attested, before it carries anything else.
func (c *Conn) Expired() bool { return c.Age() >= c.maxAge }

// Live reports whether this tunnel is still open — not closed by either end,
// not dropped for idleness, not expired and torn down by the timer above.
//
// It is a report about the last thing this side heard, not a promise about the
// next instant: a peer that closed a moment ago is still Live here until the
// packet saying so has been processed. A holder uses it to avoid handing out a
// tunnel already known to be gone, never to conclude that an exchange will
// succeed.
func (c *Conn) Live() bool {
	select {
	case <-c.c.Context().Done():
		return false
	default:
		return true
	}
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

// A Stream is a raw byte stream on a tunnel: bytes both ways, an end in each
// direction, and none of the exchange framing.
//
// It exists because a sandbox beside this tunneld consumes a stream and not a
// request-response (ticket 22). Everything above this package sees it through
// an interface of exactly these seven methods, so that the same sandbox runs
// against one end of a socketpair in another process, where a *quic.Stream
// cannot go (spike E1).
type Stream struct {
	s *quic.Stream
}

// Read reads what the peer has sent, ending in io.EOF once the peer has
// half-closed.
func (s *Stream) Read(p []byte) (int, error) { return s.s.Read(p) }

// Write sends to the peer.
func (s *Stream) Write(p []byte) (int, error) { return s.s.Write(p) }

// CloseWrite ends this side's half of the stream, which the peer reads as
// end-of-file. It is QUIC's own FIN: this side may still read.
func (s *Stream) CloseWrite() error { return s.s.Close() }

// Close gives up the stream in both directions: this side's half is ended and
// the peer is told to stop sending.
//
// The two are asymmetric on the wire — a FIN out, a STOP_SENDING back — and
// deliberately not surfaced as such. A caller that wants only the first calls
// CloseWrite; a caller that is done calls this.
func (s *Stream) Close() error {
	err := s.s.Close()
	s.s.CancelRead(0)
	return err
}

// SetDeadline, SetReadDeadline and SetWriteDeadline are QUIC's own, unchanged
// and unwrapped.
//
// They are here because whatever a sandbox runs over a stream is likely to be
// a net.Conn consumer that sets them — an HTTP client bounding a read, or a TLS
// handshake interrupting one when its context ends (ticket 23) — and a stream
// that took them and did nothing would be believed. Nothing is invented: a
// *quic.Stream has had all three since before this package existed, exactly as
// the socketpair end the other implementation hands out has.
func (s *Stream) SetDeadline(t time.Time) error { return s.s.SetDeadline(t) }

// SetReadDeadline bounds a blocked Read, which then fails with an error for
// which errors.Is(err, os.ErrDeadlineExceeded) is true.
func (s *Stream) SetReadDeadline(t time.Time) error { return s.s.SetReadDeadline(t) }

// SetWriteDeadline bounds a blocked Write the same way.
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.s.SetWriteDeadline(t) }

// OpenStream opens a raw stream to the peer.
//
// The four-byte marker goes out here rather than with the first write, so that
// a stream exists on the peer's side as soon as it exists here — a sandbox that
// opened a stream and then waited to be spoken to first would otherwise wait
// for a stream the peer has not been told about.
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	s, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: opening a stream: %w", err)
	}
	var marker [frameHeaderSize]byte
	binary.BigEndian.PutUint32(marker[:], rawStreamMarker)
	if _, err := s.Write(marker[:]); err != nil {
		s.CancelWrite(0)
		s.CancelRead(0)
		return nil, fmt.Errorf("tunnel: opening a stream: %w", err)
	}
	return &Stream{s: s}, nil
}

// AcceptStream returns the next raw stream the peer opened. It is answered out
// of [Conn.Serve], which is what tells a stream that carries an exchange from
// one that does not, so a connection nobody is serving accepts no streams.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case s := <-c.raw:
		return &Stream{s: s}, nil
	case <-c.c.Context().Done():
		return nil, fmt.Errorf("tunnel: accepting a stream: %w", c.c.Context().Err())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// PeerCertificate is the DER of the leaf certificate the peer presented at the
// handshake, or nil if it presented none.
//
// This package knows nothing about attestation and this does not change that:
// it is the TLS leaf as TLS saw it, handed up to whoever does know — package
// ratls reads the evidence and the binding out of it, and package tunneld
// reads the identity out of that. It is here because a connection is where the
// certificate is, and because re-deriving it anywhere else would mean holding
// the peer's identity in a second place.
func (c *Conn) PeerCertificate() []byte {
	certs := c.c.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0].Raw
}

// RemoteAddr is the address the peer reached this side from. It is the peer's
// source address, which for an accepted connection is an ephemeral port and not
// the address that peer listens on.
func (c *Conn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

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

// Serve answers exchanges on c until the connection ends, and hands every
// stream that is not an exchange to [Conn.AcceptStream]. Each stream is read on
// its own goroutine so that a slow handler holds up only its own caller; a
// handler error closes that stream without a response, and a peer that breaks
// the framing ends the connection.
//
// The two kinds are told apart by the four bytes every stream opens with, and
// by nothing else: a length is an exchange, and rawStreamMarker is a raw
// stream. Reading those four bytes is the first thing done to any stream either
// way, so neither kind pays for the other's existence.
func (c *Conn) Serve(handler Handler) error {
	for {
		s, err := c.c.AcceptStream(c.c.Context())
		if err != nil {
			return err
		}
		go func() {
			header, err := readHeader(s)
			if err != nil {
				s.CancelWrite(0)
				s.CancelRead(0)
				c.refuse(err)
				return
			}
			if binary.BigEndian.Uint32(header[:]) == rawStreamMarker {
				c.handOver(s)
				return
			}
			request, err := readFramePayload(s, header)
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

// handOver parks a raw stream until somebody accepts it, or until the
// connection ends and there is nobody left who could.
func (c *Conn) handOver(s *quic.Stream) {
	select {
	case c.raw <- s:
	case <-c.c.Context().Done():
		s.CancelWrite(0)
		s.CancelRead(0)
	}
}

// Close ends the connection.
func (c *Conn) Close() error {
	c.expiry.Stop()
	return c.c.CloseWithError(0, "")
}

// A Cache is the warm path: at most one tunnel per peer, dialed on first use
// and dialed again whenever the one it held is gone.
//
// One Cache belongs to one tunneld, and a tunneld is one sandbox, so "at most
// one tunnel per peer" is per sandbox by construction — two tunnelds in one
// process hold two caches, two identities and two tunnels to the same peer,
// and neither can reach the other's.
//
// A peer is keyed by address rather than by name. The peer table is not
// security-critical and naming binds to nothing (spec, Reference values and
// naming), so two names for one address are one peer and should share one warm
// path rather than open two tunnels to it.
//
// Nothing here is a background process. Tunnels are dialed when they are asked
// for and dropped when they are next asked for and found gone, so an idle
// tunneld runs no timer of its own beyond the expiry each connection carries.
type Cache struct {
	tlsConf *tls.Config
	limits  Limits

	mu      sync.Mutex
	closed  bool
	tunnels map[string]*pending
}

// pending is one cache slot. It exists before the tunnel does so that callers
// who arrive during a dial wait for it instead of starting a second one:
// "cached per peer" has to hold under concurrent first use, or the cache is
// only a cache once the race is over.
type pending struct {
	ready chan struct{} // closed once conn and err are set
	conn  *Conn
	err   error
}

// ErrCacheClosed is returned by Get once the cache has been closed.
var ErrCacheClosed = errors.New("tunnel: connection cache closed")

// NewCache returns a cache that dials with tlsConf under limits. A zero field
// in limits takes its default.
func NewCache(tlsConf *tls.Config, limits Limits) *Cache {
	return &Cache{tlsConf: tlsConf, limits: limits.withDefaults(), tunnels: map[string]*pending{}}
}

// Get returns the tunnel to addr, dialing one if there is none, if the one
// held has been lost, or if it has reached its maximum age. The returned
// connection belongs to the cache: use it, do not close it.
//
// This is where three of ticket 12's properties actually live, and they are
// one line of code apart because they are one mechanism. Lazily dialed: a
// tunnel exists because somebody asked for this peer, never because the peer
// table mentions it. Re-dialed transparently: a caller that asks again after a
// tunnel was lost gets a new one and is not told. Re-attested before further
// use: a new tunnel is a new handshake, and a new handshake is both sides
// judging the other's evidence against their current reference value set.
//
// A dial that fails is not remembered. The next caller dials again rather than
// inheriting a refusal — a cached refusal would outlive the reason for it, and
// this cache has no business holding a trust decision.
func (c *Cache) Get(ctx context.Context, addr string) (*Conn, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, ErrCacheClosed
		}
		if p, ok := c.tunnels[addr]; ok {
			c.mu.Unlock()
			select {
			case <-p.ready:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if p.err != nil {
				// The dial that made this slot failed and took the slot with
				// it; everyone waiting on it fails together and the next
				// caller starts over.
				return nil, p.err
			}
			if p.conn.Live() && !p.conn.Expired() {
				return p.conn, nil
			}
			// Gone, or old enough that it must not be used again. The age is
			// asked here as well as enforced by the connection's own expiry
			// because a timer fires when the runtime gets to it, and a tunnel
			// past its maximum age must not carry an exchange in the meantime.
			c.discard(addr, p)
			if p.conn.Expired() {
				p.conn.closeExpired()
			} else {
				p.conn.Close()
			}
			continue
		}
		p := &pending{ready: make(chan struct{})}
		c.tunnels[addr] = p
		c.mu.Unlock()

		p.conn, p.err = Dial(ctx, addr, c.tlsConf, c.limits)
		close(p.ready)
		if p.err != nil {
			c.discard(addr, p)
			return nil, p.err
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			// Closed while this dial was in flight: the tunnel was never in
			// anybody's hands, so it ends here rather than outliving the
			// tunneld that opened it.
			c.discard(addr, p)
			p.conn.Close()
			return nil, ErrCacheClosed
		}
		return p.conn, nil
	}
}

// discard drops a slot, unless it has already been replaced by another
// caller's.
func (c *Cache) discard(addr string, p *pending) {
	c.mu.Lock()
	if c.tunnels[addr] == p {
		delete(c.tunnels, addr)
	}
	c.mu.Unlock()
}

// Close ends every tunnel the cache holds. A dial still in flight is ended by
// the caller that started it, which finds the cache closed when it returns.
func (c *Cache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	tunnels := c.tunnels
	c.tunnels = nil
	c.mu.Unlock()
	for _, p := range tunnels {
		select {
		case <-p.ready:
			if p.conn != nil {
				p.conn.Close()
			}
		default:
		}
	}
	return nil
}
