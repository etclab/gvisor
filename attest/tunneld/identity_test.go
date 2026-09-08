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

// Two tunnelds on one VM: distinct identities, and neither able to use the
// other's channel (spec, user story 45).
//
// Every test here runs both tunnelds on one fake platform — literally the same
// [snpfake.Platform] value handed to both as their acquirer. That is what "on
// one VM" means and it is the whole difficulty of the ticket: one chip, one
// certificate chain, one launch measurement, one guest policy. Two tunnelds
// built that way are indistinguishable to anything this design uses to admit a
// peer. What separates them is the key each generates at startup, the evidence
// that key is bound into, and the tunnels each establishes with it.
//
// # What these tests rule out, and what they do not
//
// Ruled out: two tunnelds on one VM sharing a key; sharing evidence; sharing a
// cached tunnel; resolving a channel through each other's cache; and reaching
// each other's handler over a tunnel established to one of them. Each is a way
// one sandbox's identity could be used by another sandbox in the same process,
// and each is shown here not to happen.
//
// Not ruled out, and not addressable at this layer: a peer telling the two
// apart. Membership in this design is "runs the measured image" (spec,
// Reference values and naming), so a peer that admits one of these tunnelds
// admits the other on identical grounds, and a host that redirects a name from
// one to the other produces a successful handshake with the wrong party. A name
// binds to no platform, and that is an explicit non-goal rather than a gap
// these tests failed to cover; the narrower-federation answer, if it is ever
// wanted, is the image-signing key digest the reference value format already
// reserves. The refusal in TestATunnelOneTunneldEstablishedIsNotUsableByTheOther
// is therefore the *dialer's* — each tunneld's own reference value set is the
// one thing here that is per tunneld and decides who it will talk to.
//
// The claim these tests establish is non-confusion inside the process. It is
// not distinguishability from outside it.
//
// # Observing a key
//
// No tunneld API hands out its key, and none should. The only place a key is
// observable is the peer it is presented to, so the first test brings its own:
// a listener built from ratls and tunnel exactly as tunneld builds one, with
// the peer-certificate callback wrapped so that it writes down what each peer
// it admitted presented. It admits and refuses on the same terms a tunneld
// does. Building a peer by hand is the instrument ticket 09 introduced with
// hostileDial and it is here for the same reason: some properties can only be
// shown by a peer doing something no tunneld does.
//
// Nothing here is parallel. lifecycle_test.go records why, and it applies to
// this file too.

package tunneld_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/tunnel"
	"gvisor.dev/gvisor/attest/tunneld"
)

// vmNode is one tunneld under test in this file. Which platform it runs on is
// the caller's, which is the only thing it adds over the nodes the other files
// start: two vmNodes can be given one platform and are then two sandboxes on
// one VM.
//
// It counts the peers it judged, the exchanges it answered and the refusals it
// logged, reusing the counting verifier from lifecycle_test.go and the operator
// log recorder from refusal_test.go, because the claims here are all about
// which tunneld did what.
type vmNode struct {
	*tunneld.Tunneld
	name     string
	verifier *counting
	refusals *refusalRecorder
	served   atomic.Int32
}

func startOnVM(t *testing.T, sandbox string, vm *snpfake.Platform, admits attest.ReferenceValueSet, peers tunneld.PeerTable) *vmNode {
	t.Helper()
	n := &vmNode{
		name:     sandbox,
		verifier: &counting{Verifier: verifierFor(t, vm)},
		refusals: newRefusalRecorder(),
	}
	td, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             sandbox,
		Acquirer:              vm,
		Verifier:              n.verifier,
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		AuthorPublicKey:       authorPub,
		Peers:                 peers,
		ListenAddr:            "127.0.0.1:0",
		RefusalLog:            n.refusals.record,
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

// presented is what one peer showed at one handshake.
type presented struct {
	openErr        error                 // set when ratls.Open failed on an admitted envelope
	publicKey      []byte                // the key exactly as the peer presented it
	bindingContext attest.BindingContext // the binding context it claimed
	evidence       []byte                // the evidence bound to that key
	chain          []byte                // the chain that evidence is verified against
}

// watchingPeer is a peer that admits on exactly the terms a tunneld does and
// records what each admitted peer presented. It is a tunneld's listening half
// with one line added: the callback that decides is the one ratls builds, and
// the recording happens after it has already said yes.
type watchingPeer struct {
	listener *tunnel.Listener
	served   atomic.Int32

	mu    sync.Mutex
	seen  []presented
	conns []*tunnel.Conn
}

func startWatchingPeer(t *testing.T, image []byte, admits attest.ReferenceValueSet) *watchingPeer {
	t.Helper()
	p := platform(t, image)
	identity, err := ratls.NewIdentity(ctx(t), p, somePolicyDigest("watching peer"))
	if err != nil {
		t.Fatalf("building the watching peer's identity: %v", err)
	}
	verification, err := attest.New(verifierFor(t, p), admits)
	if err != nil {
		t.Fatalf("building the watching peer's verification: %v", err)
	}
	w := &watchingPeer{}
	conf := identity.ServerConfig(verification)
	admit := conf.VerifyPeerCertificate
	conf.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if err := admit(raw, chains); err != nil {
			return err // Refused on the ordinary terms; there is nothing to record.
		}
		w.record(t, raw[0])
		return nil
	}
	ln, err := tunnel.Listen("127.0.0.1:0", conf, tunnel.Limits{})
	if err != nil {
		t.Fatalf("the watching peer could not listen: %v", err)
	}
	w.listener = ln
	t.Cleanup(w.close)
	go w.accept()
	return w
}

// record opens an admitted peer's envelope with the same reader the handshake
// used and writes down what was in it. It runs on that peer's handshake
// goroutine, so it reports nothing itself: an envelope it cannot open is
// recorded as such and surfaces from admitted, on the test's own goroutine.
func (w *watchingPeer) record(t *testing.T, der []byte) {
	ev, binding, err := ratls.Open(der)
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		w.seen = append(w.seen, presented{openErr: err})
		return
	}
	w.seen = append(w.seen, presented{
		publicKey:      binding.PublicKey,
		bindingContext: binding.Context,
		evidence:       ev.Bytes,
		chain:          ev.Chain,
	})
}

func (w *watchingPeer) accept() {
	for {
		c, err := w.listener.Accept(context.Background())
		if err != nil {
			return
		}
		w.mu.Lock()
		w.conns = append(w.conns, c)
		w.mu.Unlock()
		go c.Serve(func(_ context.Context, request []byte) ([]byte, error) {
			w.served.Add(1)
			return append([]byte("peer:"), request...), nil
		})
	}
}

// Addr is the address peers reach the watching peer at.
func (w *watchingPeer) Addr() string { return w.listener.Addr().String() }

// admitted is what every peer this listener let in presented, in the order it
// was admitted. An admitted envelope the reader could not open fails the test
// here, on the test's goroutine.
func (w *watchingPeer) admitted(t *testing.T) []presented {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.seen {
		if p.openErr != nil {
			t.Fatalf("the watching peer admitted an envelope it cannot open: %v", p.openErr)
		}
	}
	return append([]presented(nil), w.seen...)
}

func (w *watchingPeer) close() {
	w.listener.Close()
	w.mu.Lock()
	conns := w.conns
	w.conns = nil
	w.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// TestTwoTunneldsOnOneVMPresentDistinctKeysAndDistinctEvidence is the first
// criterion. Two tunnelds are given one platform — one chip, one chain, one
// launch measurement — and each is asked for the same peer. The peer writes
// down what each of them presented.
//
// What must differ is the key and the evidence: a key is generated per tunneld
// at startup and is bound into the evidence through the caller-supplied bytes
// (ADR-0002), so two sandboxes that shared either would be one identity wearing
// two names. What must not differ is the platform underneath, and the chain is
// how that is checked rather than merely arranged: it is issued per chip and
// per TCB (ADR-0005), so one chain is one chip. Both were also admitted by a
// set holding exactly one reference value, so both attested the same launch
// measurement.
func TestTwoTunneldsOnOneVMPresentDistinctKeysAndDistinctEvidence(t *testing.T) {
	vm := platform(t, imageA)
	peer := startWatchingPeer(t, imageB, admitting(imageA))
	peers := tunneld.PeerTable{"peer": peer.Addr()}
	one := startOnVM(t, "sandbox-1", vm, admitting(imageB), peers)
	two := startOnVM(t, "sandbox-2", vm, admitting(imageB), peers)

	// Control: both reach the peer and both exchanges come back. Distinct
	// identities that could not carry traffic would satisfy every assertion
	// below and mean nothing.
	for _, td := range []*vmNode{one, two} {
		ch, err := td.Peer(ctx(t), "peer")
		if err != nil {
			t.Fatalf("%s.Peer(peer): %v", td.name, err)
		}
		defer ch.Close()
		got, err := ch.Exchange(ctx(t), []byte(td.name))
		if err != nil {
			t.Fatalf("%s exchanging with peer: %v", td.name, err)
		}
		if want := "peer:" + td.name; string(got) != want {
			t.Fatalf("%s got %q back; want %q", td.name, got, want)
		}
	}

	seen := peer.admitted(t)
	if len(seen) != 2 {
		t.Fatalf("the peer admitted %d tunnelds; want 2", len(seen))
	}
	if bytes.Equal(seen[0].publicKey, seen[1].publicKey) {
		t.Errorf("both tunnelds presented the same public key; each sandbox generates its own at startup")
	}
	if bytes.Equal(seen[0].evidence, seen[1].evidence) {
		t.Errorf("both tunnelds presented byte-identical evidence; each key is bound into its own report")
	}
	// The keys differ under one binding context, so the evidence differs
	// because the keys do and not because the two are speaking different
	// versions of the binding.
	for i, p := range seen {
		if p.bindingContext != attest.BindingContextV2 {
			t.Errorf("tunneld %d claimed binding context %x; want v2", i, p.bindingContext[:])
		}
	}
	if !bytes.Equal(seen[0].chain, seen[1].chain) {
		t.Errorf("the two tunnelds presented different certificate chains; the chain is per chip, so they were not put on one VM and this test proved nothing")
	}
	if n := peer.served.Load(); n != 2 {
		t.Errorf("the peer answered %d exchanges; want 2", n)
	}
}

// TestNeitherTunneldSharesTheOthersCachedTunnel is the third criterion, and it
// asks the question by counting handshakes at the peer rather than by looking
// at a cache — a tunnel that was shared is one nobody was judged a second time
// for.
//
// Ticket 12's TestEachSandboxDialsItsOwnTunnel established the first half: two
// sandboxes reaching one peer cost two handshakes. What is added here is that
// the two tunnels have separate lives. One tunneld ends; the other's tunnel is
// still there and still warm, which it would not be if the two had been one.
// And the channel the ended tunneld handed out does not fall through to the
// tunnel its neighbour is holding to the same address — a channel resolves
// through its own tunneld's cache and through nothing else.
func TestNeitherTunneldSharesTheOthersCachedTunnel(t *testing.T) {
	vm := platform(t, imageA)
	b := startOnVM(t, "b", platform(t, imageB), admitting(imageA), nil)
	peers := tunneld.PeerTable{"b": b.Addr().String()}
	one := startOnVM(t, "sandbox-1", vm, admitting(imageB), peers)
	two := startOnVM(t, "sandbox-2", vm, admitting(imageB), peers)

	chOne, err := one.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("sandbox-1.Peer(b): %v", err)
	}
	defer chOne.Close()
	chTwo, err := two.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("sandbox-2.Peer(b): %v", err)
	}
	defer chTwo.Close()
	exchanges(t, chOne, "b", "from-sandbox-1")
	exchanges(t, chTwo, "b", "from-sandbox-2")
	if n := b.verifier.handshakes(); n != 2 {
		t.Fatalf("two sandboxes on one VM reaching one peer took %d handshakes; want 2 — a tunnel was shared across sandboxes", n)
	}

	// One sandbox's tunneld ends, taking its tunnel with it. The other's is a
	// different tunnel, so it is still there: the exchange succeeds and costs
	// no handshake.
	one.Close()
	exchanges(t, chTwo, "b", "after-sandbox-1-is-gone")
	if n := b.verifier.handshakes(); n != 2 {
		t.Errorf("the surviving sandbox's exchange took the handshake count to %d; want 2 — its tunnel was the one the other sandbox opened", n)
	}

	// And the ended tunneld's channel does not reach through to the tunnel the
	// surviving one holds to that same address.
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := chOne.Exchange(deadline, []byte("through the other sandbox")); !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Errorf("a channel from the ended tunneld returned %q, %v; want ErrNotEstablished — it resolved through another sandbox's cache", got, err)
	}
	if n := b.served.Load(); n != 3 {
		t.Errorf("the peer answered %d exchanges; want 3", n)
	}
}

// TestATunnelOneTunneldEstablishedIsNotUsableByTheOther is the second
// criterion, from the dialing side.
//
// Both tunnelds are on one VM, hold the same peer table, and ask for the same
// name at the same address. The only difference between them is the one thing
// this design puts in each tunneld's own hands: its reference value set, which
// says who it will talk to. One admits the peer; the other does not.
//
// The admitting one establishes a tunnel and keeps it warm. The refusing one
// then asks for that same peer while that tunnel is up, and must get nothing:
// its own set refuses the peer, and a tunnel its neighbour established is not
// a tunnel it can be handed. A cache shared across the two sandboxes would
// hand it over without a handshake and with no reference value set consulted
// at all, which is exactly the confusion this criterion is about.
//
// The refusal here is the dialer's own and it has to be. Both tunnelds present
// the same measurement from the same chip, so the peer has no grounds to admit
// one and refuse the other — see this file's header on what that does and does
// not leave open.
func TestATunnelOneTunneldEstablishedIsNotUsableByTheOther(t *testing.T) {
	vm := platform(t, imageA)
	b := startOnVM(t, "b", platform(t, imageB), admitting(imageA), nil)
	peers := tunneld.PeerTable{"b": b.Addr().String()}
	admits := startOnVM(t, "sandbox-admits", vm, admitting(imageB), peers)
	refuses := startOnVM(t, "sandbox-refuses", vm, admitting(imageNone), peers)

	ch, err := admits.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("sandbox-admits.Peer(b): %v", err)
	}
	defer ch.Close()
	exchanges(t, ch, "b", "admitted")

	other, err := refuses.Peer(ctx(t), "b")
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("sandbox-refuses got %v, %v for a peer its own set refuses; want ErrNotEstablished — it was handed the other sandbox's tunnel", other, err)
	}
	// It was refused for the reason its set gives, and not because something
	// else went wrong on the way.
	if got, want := refuses.refusals.next(t).Reason(), attest.ReasonMeasurementNotInSet; got != want {
		t.Errorf("sandbox-refuses logged %v; want %v", got, want)
	}
	if logged := admits.refusals.none(); len(logged) != 0 {
		t.Errorf("the admitting sandbox logged %d refusals; its neighbour's refusal is not its own", len(logged))
	}

	// Control: the neighbour's refusal did not disturb the tunnel that was
	// already there, and no exchange of the refused sandbox's reached the peer.
	exchanges(t, ch, "b", "still admitted")
	if n := b.served.Load(); n != 2 {
		t.Errorf("the peer answered %d exchanges; want 2 — both are the admitting sandbox's", n)
	}
}

// TestATunnelToOneTunneldDoesNotReachTheOther is the second criterion from the
// listening side. Two tunnelds on one VM listen on two addresses; a third
// tunneld holds both in its peer table and reaches each by name.
//
// A tunnel established to one of them is answered by that one and by nothing
// else. Two identities in one process do not share an accept path or a handler,
// so a peer that has a tunnel to one sandbox has a tunnel to one sandbox — the
// co-located neighbour is not reachable over it, however identical their
// evidence looks from outside.
func TestATunnelToOneTunneldDoesNotReachTheOther(t *testing.T) {
	vm := platform(t, imageA)
	one := startOnVM(t, "sandbox-1", vm, admitting(imageB), nil)
	two := startOnVM(t, "sandbox-2", vm, admitting(imageB), nil)
	if one.Addr().String() == two.Addr().String() {
		t.Fatalf("both tunnelds bound %s; they must listen separately", one.Addr())
	}
	caller := startOnVM(t, "caller", platform(t, imageB), admitting(imageA), tunneld.PeerTable{
		"one": one.Addr().String(),
		"two": two.Addr().String(),
	})

	// Each name in turn: the tunnel to it is answered by that sandbox's
	// handler, and the neighbour's count does not move.
	for _, c := range []struct {
		name    string
		reached *vmNode
		other   *vmNode
	}{
		{"one", one, two},
		{"two", two, one},
	} {
		ch, err := caller.Peer(ctx(t), c.name)
		if err != nil {
			t.Fatalf("caller.Peer(%s): %v", c.name, err)
		}
		defer ch.Close()
		exchanges(t, ch, c.reached.name, "for-"+c.name)
		if n := c.reached.served.Load(); n != 1 {
			t.Errorf("%s answered %d exchanges; want 1", c.reached.name, n)
		}
		if n := c.reached.verifier.handshakes(); n != 1 {
			t.Errorf("%s judged %d peers; want 1", c.reached.name, n)
		}
	}
}

// TestBothTunneldsExchangeConcurrently is the fourth criterion, the control the
// other three need. Two tunnelds on one VM run their exchanges at the same time
// against one peer, starting together so that their first uses genuinely
// overlap, and each gets its own responses back.
//
// Two handshakes and no more: concurrency does not make them one tunnel, and it
// does not make them three either.
func TestBothTunneldsExchangeConcurrently(t *testing.T) {
	const each = 8
	vm := platform(t, imageA)
	b := startOnVM(t, "b", platform(t, imageB), admitting(imageA), nil)
	peers := tunneld.PeerTable{"b": b.Addr().String()}
	one := startOnVM(t, "sandbox-1", vm, admitting(imageB), peers)
	two := startOnVM(t, "sandbox-2", vm, admitting(imageB), peers)

	c := ctx(t)
	release := make(chan struct{})
	errs := make([][]error, 2)
	var wg sync.WaitGroup
	for i, td := range []*vmNode{one, two} {
		errs[i] = make([]error, each)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			ch, err := td.Peer(c, "b")
			if err != nil {
				errs[i][0] = fmt.Errorf("%s.Peer(b): %w", td.name, err)
				return
			}
			defer ch.Close()
			for j := range each {
				request := fmt.Sprintf("%s-%02d", td.name, j)
				got, err := ch.Exchange(c, []byte(request))
				if err != nil {
					errs[i][j] = fmt.Errorf("%s exchange %q: %w", td.name, request, err)
					continue
				}
				if want := "b:" + request; string(got) != want {
					errs[i][j] = fmt.Errorf("%s exchange %q returned %q; want %q", td.name, request, got, want)
				}
			}
		}()
	}
	close(release)
	wg.Wait()

	for _, side := range errs {
		for _, err := range side {
			if err != nil {
				t.Error(err)
			}
		}
	}
	if n := b.verifier.handshakes(); n != 2 {
		t.Errorf("two sandboxes exchanging concurrently took %d handshakes; want 2", n)
	}
	if n := b.served.Load(); n != 2*each {
		t.Errorf("the peer answered %d exchanges; want %d", n, 2*each)
	}
}
