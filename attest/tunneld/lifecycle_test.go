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

// The life of a tunnel, driven through tunneld: lazily dialed, cached per peer
// per sandbox, re-dialed transparently when lost, closed when idle, and torn
// down and re-attested when it reaches its maximum age.
//
// Every test here counts handshakes rather than inspecting a cache, because a
// handshake is what the properties are actually about. A tunnel that is reused
// is one nobody was judged for a second time; a tunnel that was re-attested is
// one somebody was. The count comes from a verifier wrapped around the fake
// vendor's, which is the same substitution point every other test in this
// package uses — nothing here reaches inside the transport.
//
// The counts are paired with the traffic that produced them. "One handshake"
// is only evidence of caching if exchanges were also answered over it, and a
// tunnel that established and then dropped everything would satisfy the first
// half of every assertion below and fail the second.

package tunneld_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/tunnel"
	"gvisor.dev/gvisor/attest/tunneld"
)

// counting wraps the vendor verifier and counts the peers it judged. One call
// is one handshake: a tunneld runs its verification once per peer certificate,
// and there is one of those per handshake.
type counting struct {
	attest.Verifier
	n atomic.Int32
}

func (c *counting) Verify(ctx context.Context, ev attest.Evidence, set attest.ReferenceValueSet) (attest.Attested, error) {
	c.n.Add(1)
	return c.Verifier.Verify(ctx, ev, set)
}

// handshakes is how many peers this tunneld has judged since it started.
func (c *counting) handshakes() int { return int(c.n.Load()) }

// lifecycleNode is one tunneld under test, with the peers it judged counted
// and the exchanges it answered counted.
type lifecycleNode struct {
	*tunneld.Tunneld
	name     string
	verifier *counting
	served   atomic.Int32
}

// startLifecycle runs a tunneld with limits and, optionally, a fixed address —
// which only the peer-restart case needs, because it has to put a second
// tunneld where the first one was.
func startLifecycle(t *testing.T, sandbox string, image []byte, admits attest.ReferenceValueSet, peers tunneld.PeerTable, limits tunneld.Limits, addr string) *lifecycleNode {
	t.Helper()
	p := platform(t, image)
	n := &lifecycleNode{name: sandbox, verifier: &counting{Verifier: verifierFor(t, p)}}
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	td, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             sandbox,
		Acquirer:              p,
		Verifier:              n.verifier,
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		AuthorPublicKey:       authorPub,
		Peers:                 peers,
		ListenAddr:            addr,
		Limits:                limits,
		Handler: func(_ context.Context, request []byte) ([]byte, error) {
			n.served.Add(1)
			return append([]byte(sandbox+":"), request...), nil
		},
	})
	if err != nil {
		t.Fatalf("tunneld.New(%s): %v", sandbox, err)
	}
	n.Tunneld = td
	t.Cleanup(func() { td.Close() })
	return n
}

// exchanges runs one exchange over ch and requires the bytes to come back from
// the peer named. Every assertion in this file about how many tunnels exist is
// paired with one of these, so that a broken tunnel cannot pass for a cached
// one.
func exchanges(t *testing.T, ch *tunneld.Channel, peer, request string) {
	t.Helper()
	got, err := ch.Exchange(ctx(t), []byte(request))
	if err != nil {
		t.Fatalf("exchange %q with %s: %v", request, peer, err)
	}
	if want := peer + ":" + request; string(got) != want {
		t.Fatalf("exchange %q returned %q; want %q", request, got, want)
	}
}

// TestATunnelIsDialedOnFirstUseAndReusedAfterwards is the cache: no tunnel
// exists because a peer is in the table, one exists once somebody asks for that
// peer, and asking again — or exchanging again — is not another handshake.
func TestATunnelIsDialedOnFirstUseAndReusedAfterwards(t *testing.T) {
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, "")
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": b.Addr().String()}, tunneld.Limits{}, "")

	// Lazily: b is in a's peer table and a is running, and nothing has been
	// dialed.
	if n := b.verifier.handshakes(); n != 0 {
		t.Fatalf("b judged %d peers before anyone asked for a tunnel to it; want 0", n)
	}

	first, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer first.Close()
	if n := b.verifier.handshakes(); n != 1 {
		t.Fatalf("the first use of a peer took %d handshakes; want 1", n)
	}

	// Cached: a second channel to the same peer, and four exchanges across the
	// two of them, all ride the tunnel that is already there.
	second, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b) a second time: %v", err)
	}
	defer second.Close()
	for i := range 2 {
		exchanges(t, first, "b", fmt.Sprintf("first-%d", i))
		exchanges(t, second, "b", fmt.Sprintf("second-%d", i))
	}
	if n := b.verifier.handshakes(); n != 1 {
		t.Errorf("two channels and four exchanges to one peer took %d handshakes; want 1 — the tunnel is not cached", n)
	}
	if n := b.served.Load(); n != 4 {
		t.Errorf("b answered %d exchanges; want 4", n)
	}
}

// TestEachSandboxDialsItsOwnTunnel is the "per sandbox" half of the cache. Two
// tunnelds in one process are two sandboxes with two identities, and the warm
// path of one is not available to the other: the peer they share judges each of
// them separately.
func TestEachSandboxDialsItsOwnTunnel(t *testing.T) {
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, "")
	peers := tunneld.PeerTable{"b": b.Addr().String()}
	one := startLifecycle(t, "sandbox-1", imageA, admitting(imageB), peers, tunneld.Limits{}, "")
	two := startLifecycle(t, "sandbox-2", imageA, admitting(imageB), peers, tunneld.Limits{}, "")

	for _, a := range []*lifecycleNode{one, two} {
		ch, err := a.Peer(ctx(t), "b")
		if err != nil {
			t.Fatalf("%s.Peer(b): %v", a.name, err)
		}
		defer ch.Close()
		exchanges(t, ch, "b", a.name)
	}
	if n := b.verifier.handshakes(); n != 2 {
		t.Errorf("two sandboxes reaching one peer took %d handshakes; want 2 — a tunnel was shared across sandboxes", n)
	}
	if n := b.served.Load(); n != 2 {
		t.Errorf("b answered %d exchanges; want 2", n)
	}
}

// TestConcurrentFirstUsesShareOneTunnel is the cache under the race it has to
// survive to be a cache at all. Callers arriving together for a peer nobody has
// dialed yet must wait for the one dial rather than each starting their own.
func TestConcurrentFirstUsesShareOneTunnel(t *testing.T) {
	const callers = 16
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, "")
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": b.Addr().String()}, tunneld.Limits{}, "")

	c := ctx(t)
	errs := make([]error, callers)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release // Start together, so the first uses genuinely overlap.
			ch, err := a.Peer(c, "b")
			if err != nil {
				errs[i] = err
				return
			}
			defer ch.Close()
			_, errs[i] = ch.Exchange(c, fmt.Appendf(nil, "caller-%02d", i))
		}()
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if n := b.verifier.handshakes(); n != 1 {
		t.Errorf("%d callers arriving at once took %d handshakes; want 1", callers, n)
	}
	if n := b.served.Load(); n != callers {
		t.Errorf("b answered %d exchanges; want %d", n, callers)
	}
}

// lossSettles is how long the test waits for a peer's disappearance to reach
// the side that was talking to it.
//
// There is nothing to synchronise on. The loss arrives as a packet the dialer's
// own connection processes, and no API this test can reach reports that it has
// — which is the same reason the transport treats a tunnel as live until it
// hears otherwise. On loopback the packet is delivered immediately; this is
// slack, not a measured interval.
const lossSettles = 250 * time.Millisecond

// TestALostTunnelIsRedialedTransparently loses a tunnel the way a tunnel is
// actually lost: the peer on the far end goes away and another one comes up
// where it was. The caller keeps the channel it already had and asks it for
// another exchange, and does not learn that anything happened.
func TestALostTunnelIsRedialedTransparently(t *testing.T) {
	addr := reservedAddr(t)
	before := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, addr)
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": addr}, tunneld.Limits{}, "")

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	exchanges(t, ch, "b", "before")

	before.Close()
	time.Sleep(lossSettles)

	after := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, addr)
	// The same channel, no second Peer call, no error handed to the caller.
	exchanges(t, ch, "b", "after")

	if n := after.verifier.handshakes(); n != 1 {
		t.Errorf("the replacement peer judged %d peers; want 1 — the tunnel was not re-dialed to it", n)
	}
	if n := after.served.Load(); n != 1 {
		t.Errorf("the replacement peer answered %d exchanges; want 1", n)
	}
	if n := before.served.Load(); n != 1 {
		t.Errorf("the original peer answered %d exchanges; want 1", n)
	}
}

// TestAChannelWhosePeerIsGoneReportsNotEstablished is the other half of the
// transparent re-dial: when there is nothing to re-dial to, the caller gets
// this design's one word for that and not a transport error. A channel that
// worked a moment ago is not a channel that works, and what it fails with has
// to be the same thing a first attempt would have failed with.
func TestAChannelWhosePeerIsGoneReportsNotEstablished(t *testing.T) {
	addr := reservedAddr(t)
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, addr)
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": addr}, tunneld.Limits{}, "")

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	exchanges(t, ch, "b", "while the peer is up")

	b.Close()
	time.Sleep(lossSettles)

	// A dial to an address nobody answers ends when the caller stops waiting,
	// so the caller here brings its own deadline rather than sitting out the
	// transport's handshake timeout.
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := ch.Exchange(deadline, []byte("after the peer is gone")); !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Errorf("the exchange returned %q, %v; want ErrNotEstablished", got, err)
	}
}

// reservedAddr takes an ephemeral port from the kernel and gives it back, so
// that two tunnelds can be put at the same address one after the other. Ports
// stay ephemeral for the reason attest/README.md gives — other suites run
// concurrently on this machine — and a collision here fails loudly at bind
// rather than quietly at assert.
func reservedAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving an address: %v", err)
	}
	addr := c.LocalAddr().String()
	if err := c.Close(); err != nil {
		t.Fatalf("releasing the reserved address: %v", err)
	}
	return addr
}

// TestAnIdleTunnelClosesAndTheNextUseDialsAgain is the idle timeout with its
// own control either side of it: an exchange inside the window rides the tunnel
// that is there, and one after the window has to dial a new one.
func TestAnIdleTunnelClosesAndTheNextUseDialsAgain(t *testing.T) {
	const idle = 400 * time.Millisecond
	limits := tunneld.Limits{IdleTimeout: idle, MaxAge: time.Minute}
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, limits, "")
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": b.Addr().String()}, limits, "")

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	exchanges(t, ch, "b", "first")

	// Control: a tunnel that has been idle for less than its timeout is still
	// there, so the timeout is what closes it below and not merely time.
	time.Sleep(idle / 4)
	exchanges(t, ch, "b", "still warm")
	if n := b.verifier.handshakes(); n != 1 {
		t.Fatalf("an exchange inside the idle window took %d handshakes; want 1", n)
	}

	time.Sleep(2 * idle)
	exchanges(t, ch, "b", "after the idle timeout")
	if n := b.verifier.handshakes(); n != 2 {
		t.Errorf("after %v idle the next exchange took %d handshakes in total; want 2 — the idle tunnel was not closed", 2*idle, n)
	}
	if n := b.served.Load(); n != 3 {
		t.Errorf("b answered %d exchanges; want 3", n)
	}
}

// TestATunnelPastItsMaximumAgeIsTornDownAndReattested is the staleness bound,
// enforced by the side holding the tunnel.
//
// Only the dialer's maximum age is short here; the peer's is long enough that
// it would happily keep this tunnel for the whole test. So what tears the
// tunnel down is the dialer's own bound rather than its peer's courtesy, and
// what follows is a full handshake in which both sides judge the other's
// evidence again. The tunnel is never idle long enough to matter either — both
// idle timeouts are far above the maximum age — so age is the only thing left
// that can end it. The listener's half of this bound is the test below.
func TestATunnelPastItsMaximumAgeIsTornDownAndReattested(t *testing.T) {
	const maxAge = 500 * time.Millisecond
	limits := tunneld.Limits{IdleTimeout: 30 * time.Second, MaxAge: maxAge}
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil,
		tunneld.Limits{IdleTimeout: 30 * time.Second, MaxAge: time.Minute}, "")
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": b.Addr().String()}, limits, "")

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()

	// Control: inside the maximum age, exchanges keep using the one tunnel.
	exchanges(t, ch, "b", "young")
	exchanges(t, ch, "b", "still young")
	if n := b.verifier.handshakes(); n != 1 {
		t.Fatalf("exchanges inside the maximum age took %d handshakes; want 1", n)
	}
	if n := a.verifier.handshakes(); n != 1 {
		t.Fatalf("a judged %d peers inside the maximum age; want 1", n)
	}

	time.Sleep(maxAge + maxAge/2)
	exchanges(t, ch, "b", "old")

	// Both sides, because re-attestation that only one side performed would
	// leave the other relying on a verdict it never revisited.
	if n := b.verifier.handshakes(); n != 2 {
		t.Errorf("past the maximum age the peer judged %d peers in total; want 2", n)
	}
	if n := a.verifier.handshakes(); n != 2 {
		t.Errorf("past the maximum age the dialer judged %d peers in total; want 2", n)
	}
	if n := b.served.Load(); n != 3 {
		t.Errorf("b answered %d exchanges; want 3", n)
	}
}

// TestTheListenerTearsDownATunnelAtItsMaximumAge is why the bound is a bound.
// The dialer above tore down its own tunnel, which a peer that did not want to
// be re-attested would simply not do. This peer is an attested one that
// establishes correctly and then holds the tunnel: the listener ends it anyway,
// at its maximum age, having first shown it was carrying traffic.
func TestTheListenerTearsDownATunnelAtItsMaximumAge(t *testing.T) {
	const maxAge = 500 * time.Millisecond
	admits := admitting(imageA)
	// The idle timeout is far above the maximum age, so idleness cannot be
	// what closes this and the hostile peer's own idle timer cannot either.
	listener := startLifecycle(t, "listener", imageA, admits, nil,
		tunneld.Limits{IdleTimeout: 30 * time.Second, MaxAge: maxAge}, "")

	establishedPeer(t, listener.Addr().String(), admits, func(c *quic.Conn) {
		// Control: the tunnel carries an exchange while it is young.
		s, err := c.OpenStreamSync(ctx(t))
		if err != nil {
			t.Fatalf("opening an exchange stream: %v", err)
		}
		if _, err := s.Write(framed("hello")); err != nil {
			t.Fatalf("writing the exchange: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("finishing the exchange: %v", err)
		}
		if got, want := string(readFramed(t, s)), "listener:hello"; got != want {
			t.Fatalf("the exchange returned %q; want %q", got, want)
		}
		select {
		case <-c.Context().Done():
		case <-time.After(10 * maxAge):
			t.Errorf("the listener held a tunnel past its %v maximum age for a peer that would not give it up", maxAge)
		}
	})
	if n := listener.served.Load(); n != 1 {
		t.Errorf("the listener answered %d exchanges; want 1", n)
	}
}

// sessionRecorder counts the TLS sessions a server offers a returning client.
// A session is what early data rides on, so counting them is how a test asks
// whether there is a slot to replay a privileged exchange in.
type sessionRecorder struct {
	mu   sync.Mutex
	put  int
	sess map[string]*tls.ClientSessionState
}

func newSessionRecorder() *sessionRecorder {
	return &sessionRecorder{sess: map[string]*tls.ClientSessionState{}}
}

func (r *sessionRecorder) Put(key string, cs *tls.ClientSessionState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.put++
	r.sess[key] = cs
}

func (r *sessionRecorder) Get(key string) (*tls.ClientSessionState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs, ok := r.sess[key]
	return cs, ok
}

func (r *sessionRecorder) offered() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.put
}

// TestEarlyDataHasNothingToRideOn is the replay property, asserted against a
// peer that is trying to resume rather than against the configuration that
// forbids it. The peer dials the early entry point, keeps a session cache
// across two connections and asks for 0-RTT on both. It gets no session to
// resume from, does not resume, and sends no early data — and its exchanges
// complete regardless, so this is not a broken listener refusing everything.
func TestEarlyDataHasNothingToRideOn(t *testing.T) {
	admits := admitting(imageA)
	listener := startLifecycle(t, "listener", imageA, admits, nil, tunneld.Limits{}, "")
	sessions := newSessionRecorder()

	for _, attempt := range []string{"first", "returning"} {
		c := earlyDial(t, listener.Addr().String(), admits, sessions)
		state := c.ConnectionState()
		if state.Used0RTT {
			t.Errorf("%s connection: early data was accepted", attempt)
		}
		if state.TLS.DidResume {
			t.Errorf("%s connection: the TLS session resumed", attempt)
		}
		// Control: the connection is a working tunnel, not a refused one.
		if got, want := string(exchangeOn(t, c, "hello")), "listener:hello"; got != want {
			t.Fatalf("%s connection: the exchange returned %q; want %q", attempt, got, want)
		}
		c.CloseWithError(0, "")
	}
	if n := sessions.offered(); n != 0 {
		t.Errorf("the listener offered %d resumable sessions; want 0 — a returning peer would have a 0-RTT slot to replay in", n)
	}
	if n := listener.served.Load(); n != 2 {
		t.Errorf("the listener answered %d exchanges; want 2", n)
	}
}

// earlyDial is an attested peer that asks for everything the transport is
// supposed to refuse: the early dial entry point, 0-RTT enabled, and a session
// cache carried across connections. It completes the establishment round trip
// so that what it holds afterwards is a tunnel the listener admitted.
func earlyDial(t *testing.T, addr string, admits attest.ReferenceValueSet, sessions tls.ClientSessionCache) *quic.Conn {
	t.Helper()
	p := platform(t, imageA)
	identity, err := ratls.NewIdentity(ctx(t), p)
	if err != nil {
		t.Fatalf("building the peer: %v", err)
	}
	verification, err := attest.New(verifierFor(t, p), admits)
	if err != nil {
		t.Fatalf("building the peer's verification: %v", err)
	}
	conf := identity.ClientConfig(verification)
	conf.ClientSessionCache = sessions
	c, err := quic.DialAddrEarly(ctx(t), addr, conf, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatalf("the early dialer's handshake should complete; it is attested: %v", err)
	}
	t.Cleanup(func() { c.CloseWithError(0, "") })

	s, err := c.OpenStreamSync(ctx(t))
	if err != nil {
		t.Fatalf("opening the establishment stream: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("closing the establishment stream: %v", err)
	}
	if reply := readAll(t, s); len(reply) != 0 {
		t.Fatalf("the establishment reply carried %d bytes", len(reply))
	}
	return c
}

func readAll(t *testing.T, s *quic.Stream) []byte {
	t.Helper()
	var all []byte
	buf := make([]byte, 512)
	for {
		n, err := s.Read(buf)
		all = append(all, buf[:n]...)
		if err != nil {
			return all
		}
	}
}

// exchangeOn runs one framed exchange over a raw connection.
func exchangeOn(t *testing.T, c *quic.Conn, request string) []byte {
	t.Helper()
	s, err := c.OpenStreamSync(ctx(t))
	if err != nil {
		t.Fatalf("opening an exchange stream: %v", err)
	}
	if _, err := s.Write(framed(request)); err != nil {
		t.Fatalf("writing the exchange: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("finishing the exchange: %v", err)
	}
	return readFramed(t, s)
}

// TestARefusedTunnelIsNotRemembered is the cache's obligation not to hold a
// trust decision. A refusal is not cached in either direction: the peer is
// judged again on the next attempt rather than the first verdict being reused,
// and a legitimate peer reaching the same listener afterwards is unaffected.
func TestARefusedTunnelIsNotRemembered(t *testing.T) {
	// The listener admits imageNone, so it refuses everybody here.
	listener := startLifecycle(t, "listener", imageB, admitting(imageNone), nil, tunneld.Limits{}, "")
	peers := tunneld.PeerTable{"listener": listener.Addr().String()}
	refused := startLifecycle(t, "refused", imageA, admitting(imageB), peers, tunneld.Limits{}, "")

	for attempt := range 2 {
		ch, err := refused.Peer(ctx(t), "listener")
		if !errors.Is(err, tunneld.ErrNotEstablished) {
			if ch != nil {
				ch.Close()
			}
			t.Fatalf("attempt %d: Peer(listener) = %v, %v; want ErrNotEstablished", attempt, ch, err)
		}
	}
	if n := listener.verifier.handshakes(); n != 2 {
		t.Errorf("two refused attempts reached the listener as %d handshakes; want 2 — a verdict was cached", n)
	}
	if n := listener.served.Load(); n != 0 {
		t.Errorf("the listener answered %d exchanges over a refused tunnel", n)
	}
}

// TestTheDefaultLimitsAreTheChosenNumbers is a change detector, and it is here
// because these two are the kind of constant that gets adjusted to make a test
// faster. The maximum age in particular is a security parameter: until the
// freshness challenge exists it is the only bound on how stale an attestation
// can be while traffic still flows, so moving it is a decision somebody should
// have to make on purpose. tunnel.DefaultMaxAge records why it is this number
// and what would change it.
func TestTheDefaultLimitsAreTheChosenNumbers(t *testing.T) {
	if got, want := tunnel.DefaultIdleTimeout, 60*time.Second; got != want {
		t.Errorf("the default idle timeout is %v; the spec's Transport decision says %v", got, want)
	}
	if got, want := tunnel.DefaultMaxAge, 15*time.Minute; got != want {
		t.Errorf("the default maximum age is %v; the spec's Transport decision says %v", got, want)
	}
}

// TestAClosedChannelDoesNotEndTheTunnel pins what Close means now that a tunnel
// outlives the channels over it. Closing a channel gives up that handle and
// nothing else: another holder of the same peer keeps exchanging over the tunnel
// that is already there.
func TestAClosedChannelDoesNotEndTheTunnel(t *testing.T) {
	b := startLifecycle(t, "b", imageB, admitting(imageA), nil, tunneld.Limits{}, "")
	a := startLifecycle(t, "a", imageA, admitting(imageB),
		tunneld.PeerTable{"b": b.Addr().String()}, tunneld.Limits{}, "")

	first, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	second, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b) a second time: %v", err)
	}
	defer second.Close()
	exchanges(t, first, "b", "before the close")

	if err := first.Close(); err != nil {
		t.Fatalf("closing the first channel: %v", err)
	}
	if _, err := first.Exchange(ctx(t), []byte("after the close")); !errors.Is(err, tunneld.ErrChannelClosed) {
		t.Errorf("a closed channel returned %v; want ErrChannelClosed", err)
	}
	exchanges(t, second, "b", "after the close")

	if n := b.verifier.handshakes(); n != 1 {
		t.Errorf("closing one channel cost %d handshakes in total; want 1 — it ended a tunnel another holder was using", n)
	}
	if n := b.served.Load(); n != 2 {
		t.Errorf("b answered %d exchanges; want 2", n)
	}
}
