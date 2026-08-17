// transport.go - the two planes, and the cached connections between them.
//
// Rung 5a, spec section 2. Two planes with different lifetimes, deliberately not
// collapsed into one layer:
//
//	Connect   machine-pace, lazy, cached. One QUIC connection per host pair, TLS 1.3
//	          with pinned static keys, mutual auth, 0-RTT off, idle timeout and
//	          transparent re-dial. At most N^2 connections for N hosts.
//	Converse  agent-pace, ephemeral, bursty. One stream per exchange. Stream-open on a
//	          warm connection costs no round trip, and streams have no cross-stream
//	          head-of-line blocking -- which is what absorbs a burst without 0-RTT.
//
// The whole latency argument of the rung lives in that split, and CONTROL measures it
// rather than asserting it: a cold handshake is milliseconds and happens once per host
// pair; an exchange on a warm connection is hundreds of microseconds.
//
// # 0-RTT is off, and how
//
// Two independent things, both needed. quic.Config.Allow0RTT is server-side and its
// zero value is false, so no session ticket ever permits early data. On the client,
// 0-RTT is opt-in BY ENTRY POINT: quic.Dial and quic.DialAddr never send early data,
// only the *Early variants do. This file uses quic.Dial.
//
// It is off because replay of a privileged request is the core threat this substrate
// exists to stop, and replay is precisely 0-RTT's known weakness. Turning it on to buy
// back a round trip on a connection that is already warm would be trading the thing we
// are defending for a latency win the stream design already provides.
//
// # The gotcha that costs an hour
//
// quic.Dial returns a nil error even when the SERVER is about to reject the client's
// key. In TLS 1.3 the client's handshake completes once it has SENT its
// Certificate/Finished; the server has not looked at the client's key yet. The
// rejection surfaces on the first stream operation as CRYPTO_ERROR 0x12a. So
// "Dial returned" is not "we are mutually authenticated", and DialConfirmed forces one
// application round trip before handing the connection to anything that would trust it.
// The demo's impostor check depends on this: without it, the impostor's dial "succeeds".
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// IdleTimeout closes a connection nobody has used. Re-dial is transparent, so this is a
// resource bound and not a policy.
const IdleTimeout = 60 * time.Second

func quicConfig() *quic.Config {
	return &quic.Config{
		Allow0RTT:            false, // see the package comment; this is the server half
		MaxIdleTimeout:       IdleTimeout,
		HandshakeIdleTimeout: 10 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}
}

// Conn is one authenticated connection to a peer host, plus what the handshake taught us.
type Conn struct {
	Host    string
	PeerKey ed25519.PublicKey
	Binding []byte // this connection's exporter output, computed locally
	quic    *quic.Conn
	pc      net.PacketConn
}

// Close tears the connection down.
func (c *Conn) Close() {
	if c.quic != nil {
		_ = c.quic.CloseWithError(0, "")
	}
	if c.pc != nil {
		_ = c.pc.Close()
	}
}

// exporterBinding derives the channel binding from a live connection.
//
// ExportKeyingMaterial has a POINTER receiver and ConnectionState() returns a value, so
// the obvious one-liner does not compile. Bind to a local first; this comment is here so
// nobody spends ten minutes on that twice.
func exporterBinding(conn *quic.Conn) ([]byte, error) {
	cs := conn.ConnectionState().TLS
	return cs.ExportKeyingMaterial(ExporterLabel, nil, ExporterLen)
}

// Dialer holds one host's identity and its cache of outbound connections.
type Dialer struct {
	me  *Identity
	reg *Registry

	mu    sync.Mutex
	conns map[string]*Conn // peer host -> warm connection
}

// NewDialer returns a dialer for this host.
func NewDialer(me *Identity, reg *Registry) *Dialer {
	return &Dialer{me: me, reg: reg, conns: map[string]*Conn{}}
}

// DialResult reports what a cold connect cost, for the latency table.
type DialResult struct {
	Handshake time.Duration
	Confirm   time.Duration
	Reused    bool
}

// Get returns a warm connection to host, dialing lazily and re-dialing transparently if
// the cached one has died. addr is where to reach it; the registry decides whether the
// key on the other end is acceptable, so a wrong address fails to connect and a right
// address to a wrong key fails the handshake.
func (d *Dialer) Get(ctx context.Context, host, addr string) (*Conn, DialResult, error) {
	d.mu.Lock()
	c := d.conns[host]
	d.mu.Unlock()
	if c != nil {
		if c.quic.Context().Err() == nil {
			return c, DialResult{Reused: true}, nil
		}
		// Dead. Drop it and re-dial: section 2 asks for transparent re-dial, and a
		// caller that had to know about connection state would be a caller that had to
		// know about the Connect plane, which is the split this file exists to keep.
		d.mu.Lock()
		if d.conns[host] == c {
			delete(d.conns, host)
		}
		d.mu.Unlock()
		c.Close()
	}

	c, res, err := d.dialConfirmed(ctx, host, addr)
	if err != nil {
		return nil, res, err
	}
	d.mu.Lock()
	if existing := d.conns[host]; existing != nil && existing.quic.Context().Err() == nil {
		// Lost a race; keep the one already cached rather than leaking two.
		d.mu.Unlock()
		c.Close()
		return existing, DialResult{Reused: true}, nil
	}
	d.conns[host] = c
	d.mu.Unlock()
	return c, res, nil
}

func (d *Dialer) dialConfirmed(ctx context.Context, host, addr string) (*Conn, DialResult, error) {
	var res DialResult
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, res, fmt.Errorf("resolving %s: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, res, err
	}
	seen := &peerAuth{}
	start := time.Now()
	// quic.Dial, never quic.DialEarly: the client half of "0-RTT is off".
	qc, err := quic.Dial(ctx, pc, udpAddr, clientTLS(d.me, d.reg, seen), quicConfig())
	res.Handshake = time.Since(start)
	if err != nil {
		_ = pc.Close()
		// If our own pin check is what refused, report THAT rather than the TLS alert:
		// "the peer's key is not enrolled" is the evidence, "bad certificate" is the
		// symptom.
		if _, _, perr := seen.get(); perr != nil {
			return nil, res, perr
		}
		return nil, res, err
	}

	bind, err := exporterBinding(qc)
	if err != nil {
		qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, res, fmt.Errorf("exporting keying material: %w", err)
	}
	peerHost, peerKey, _ := seen.get()

	// The confirmation round trip. See the package comment: without this, a connection
	// the far side is about to refuse looks established.
	confirmStart := time.Now()
	if err := ping(ctx, qc); err != nil {
		res.Confirm = time.Since(confirmStart)
		qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, res, fmt.Errorf("the peer refused this connection after the handshake: %w", err)
	}
	res.Confirm = time.Since(confirmStart)

	if peerHost != "" && peerHost != host {
		qc.CloseWithError(0, "")
		_ = pc.Close()
		return nil, res, fmt.Errorf("dialed %s at %s but its key is enrolled as %q", host, addr, peerHost)
	}
	return &Conn{Host: host, PeerKey: peerKey, Binding: bind, quic: qc, pc: pc}, res, nil
}

// pingPayload is the confirmation exchange. It is a frame the receiver recognises and
// drops; it carries no envelope, so it cannot be confused with a message.
var pingPayload = []byte("LFED-PING")

func ping(ctx context.Context, qc *quic.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := st.Write(pingPayload); err != nil {
		return err
	}
	// quic-go's Stream.Close closes the SEND direction only -- it is CloseWrite under
	// another name. The receiver's read-to-EOF depends on it.
	if err := st.Close(); err != nil {
		return err
	}
	buf := make([]byte, 8)
	n, err := st.Read(buf)
	if err != nil && n == 0 {
		return err
	}
	return nil
}

// CloseAll drops every cached connection.
func (d *Dialer) CloseAll() {
	d.mu.Lock()
	conns := make([]*Conn, 0, len(d.conns))
	for _, c := range d.conns {
		conns = append(conns, c)
	}
	d.conns = map[string]*Conn{}
	d.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Warm reports how many host pairs are currently connected, for the latency table.
func (d *Dialer) Warm() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

// Listener accepts authenticated connections.
type Listener struct {
	ln   *quic.Listener
	pc   net.PacketConn
	me   *Identity
	reg  *Registry
	seen *peerAuth
}

// ListenQUIC binds addr and accepts only peers whose key is in the registry. onReject,
// when set, is called with the reason every time a peer is turned away -- see peerAuth.
func ListenQUIC(me *Identity, reg *Registry, addr string, onReject func(error)) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	seen := &peerAuth{onReject: onReject}
	ln, err := quic.Listen(pc, serverTLS(me, reg, seen), quicConfig())
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &Listener{ln: ln, pc: pc, me: me, reg: reg, seen: seen}, nil
}

// Accept returns the next authenticated connection. A peer that failed the pin check
// never gets here -- that is what "refused at the handshake" means, and it is the
// difference between rung 5a and a system that authenticates messages after accepting
// whoever dialled.
func (l *Listener) Accept(ctx context.Context) (*quic.Conn, string, ed25519.PublicKey, []byte, error) {
	qc, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, "", nil, nil, err
	}
	host, key, _ := l.seen.get()
	bind, err := exporterBinding(qc)
	if err != nil {
		qc.CloseWithError(0, "")
		return nil, "", nil, nil, err
	}
	return qc, host, key, bind, nil
}

// Addr is where this listener actually bound, which matters because the demo asks for
// port 0 in places.
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Close stops accepting.
func (l *Listener) Close() {
	_ = l.ln.Close()
	_ = l.pc.Close()
}

// HandshakeRefused reports whether an error is a peer refusing the connection rather
// than a network problem, so the demo can say "refused at the handshake" and mean it.
// String matching on a transport error is fine for an evidence line and would not be
// for a control decision; nothing branches on this.
func HandshakeRefused(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, needle := range []string{
		"bad certificate",
		"crypto_error",
		"certificate required",
		"not in the enrollment registry",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
