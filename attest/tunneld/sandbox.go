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

package tunneld

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
)

// Tunneld's side of the sandbox contract (ticket 22, docs/sandbox-contract.md).
//
// A tunneld is the network boundary for whatever sandbox sits beside it, and
// this file is the whole of what crosses that boundary: a stream to a named
// peer, a stream a peer opened with the identity it was admitted under, and the
// check tunneld makes on a pushed policy before the sandbox sees it. No
// evidence, no key and no trust decision goes through any of it — the verdict
// is reached at the handshake, in package ratls, and what survives it here is
// four public strings.
//
// [Tunneld] implements [sandbox.Network] and nothing implements
// [sandbox.Sandbox] in this package: what the sandbox does is the sandbox's,
// and the first one is the null sandbox the command builds
// ([sandbox.NewNull]).

// ErrClosed is returned by [Tunneld.Accept] once the tunneld has been closed.
var ErrClosed = errors.New("tunneld: closed")

// ErrNoTunneld is returned by a [Channel] that no tunneld made. The zero
// Channel is constructible from outside this package — its type is exported and
// all its fields are not — so it is given an answer rather than a nil pointer
// dereference (spike E2, "A push before admission"). It reaches no peer either
// way; what changes is that it says so.
var ErrNoTunneld = errors.New("tunneld: channel was not made by a tunneld")

var _ sandbox.Network = (*Tunneld)(nil)

// Open gives the sandbox a stream to the named peer, establishing the tunnel
// under it if there is not one already. It is [Tunneld.Peer] followed by a
// stream on the channel it returns, which is to say the peer is attested before
// the stream exists.
func (t *Tunneld) Open(ctx context.Context, peer string) (sandbox.Stream, error) {
	channel, err := t.Peer(ctx, peer)
	if err != nil {
		return nil, err
	}
	// The channel is a handle and closing it ends nothing; the stream is what
	// the caller keeps, and the tunnel under it belongs to the cache.
	defer channel.Close()
	s, err := channel.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Accept gives the sandbox the next stream a peer opened to it, with that
// peer's attested identity.
//
// Streams are taken from every accepted tunnel and handed over in the order
// they arrive, which is why this is on the tunneld rather than on a channel: a
// channel is a handle on a peer this sandbox dialed, and an incoming stream
// belongs to a peer that dialed it.
func (t *Tunneld) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	select {
	case in := <-t.incoming:
		return in.stream, in.who, nil
	case <-t.done:
		return nil, sandbox.Attested{}, ErrClosed
	case <-ctx.Done():
		return nil, sandbox.Attested{}, ctx.Err()
	}
}

// OpenStream opens a raw stream to this channel's peer — dialing and attesting
// one first if the tunnel that was there has been lost or has reached its
// maximum age, exactly as [Channel.Exchange] does.
//
// The stream is the caller's and the tunnel under it is not: several streams
// share one tunnel, and closing a stream leaves it alone.
func (c *Channel) OpenStream(ctx context.Context) (*tunnel.Stream, error) {
	conn, err := c.tunnelTo(ctx)
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStream(ctx)
	return s, c.lost(conn, err)
}

// PolicyChecked wraps the sandbox beside this tunneld so that tunneld reads the
// envelope of every pushed policy — its format and its version, and nothing
// else — before the sandbox sees the bytes.
//
// Where the check runs is the point of it. A policy whose version this side
// does not push is refused here, by the boundary, and the sandbox is not woken
// for it: an acknowledgement then means a sandbox with that policy, on every
// implementation of the contract, rather than meaning whatever the sandbox
// beside a particular tunneld happened to make of a document it could not read.
// What tunneld does not do is read any further. `n`, `f` and `x` are the
// sandbox's or nobody's.
// What it does carry across is liveness. A sandbox that says which policy it is
// enforcing ([sandbox.Live]) is still one after it has been wrapped, because
// the thing tunneld watches after a push is the thing it pushed to; a sandbox
// that does not is not made to look as though it does. The two wrappers are
// what keeps that a fact about the sandbox rather than about the wrapper — an
// embedded interface promotes only its own methods, so a single wrapper would
// either hide liveness from every sandbox or claim it for every sandbox.
func PolicyChecked(s sandbox.Sandbox) sandbox.Sandbox {
	if live, ok := s.(sandbox.Live); ok {
		return checkedLive{checked{s}, live}
	}
	return checked{s}
}

type checked struct{ sandbox.Sandbox }

type checkedLive struct {
	checked
	sandbox.Live
}

// The two wrappers say what they are, at compile time. Nothing else does: what
// [PolicyChecked] returns is asserted back to [sandbox.Live] at run time, and a
// method promoted at the same depth from both embedded members would be
// ambiguous rather than an error — it would leave this silently not Live, and
// the watch that would not start is the one thing here nothing else notices.
var (
	_ sandbox.Sandbox = checked{}
	_ sandbox.Sandbox = checkedLive{}
	_ sandbox.Live    = checkedLive{}
)

func (c checked) Apply(ctx context.Context, policy []byte) error {
	if _, err := sandbox.ReadEnvelope(policy); err != nil {
		return fmt.Errorf("tunneld: refusing to push it at the sandbox: %w", err)
	}
	return c.Sandbox.Apply(ctx, policy)
}

// accepted is one incoming stream with the identity of the tunnel it arrived
// on, on its way to whoever is in [Tunneld.Accept].
type accepted struct {
	stream *tunnel.Stream
	who    sandbox.Attested
}

// acceptStreams hands every raw stream one accepted tunnel carries to the
// sandbox, with the identity of the peer that opened it. It runs beside that
// tunnel's Serve, which is what tells a raw stream from an exchange.
//
// The identity is read once, when the tunnel is accepted, rather than per
// stream: it is a fact about the handshake, and the handshake happened once. A
// tunnel that reaches its maximum age is torn down and the next one is a new
// handshake with a new reading.
func (t *Tunneld) acceptStreams(conn *tunnel.Conn) {
	who := t.identify(conn)
	for {
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		select {
		case t.incoming <- accepted{stream: s, who: who}:
		case <-t.done:
			s.Close()
			return
		}
	}
}

// identify is what a sandbox may know about the peer on the other end of an
// accepted tunnel, read off the certificate that peer presented and the verdict
// this side reached about it.
//
// Nothing here re-verifies anything, and nothing here decides anything. The
// connection exists, so the peer was admitted; this reads the public facts out
// of what it presented. A field it cannot fill is left empty rather than
// guessed at.
func (t *Tunneld) identify(conn *tunnel.Conn) sandbox.Attested {
	who := sandbox.Attested{Peer: t.nameOf(conn.RemoteAddr())}
	der := conn.PeerCertificate()
	if der == nil {
		return who
	}
	evidence, binding, err := ratls.Open(der)
	if err != nil {
		// Unreachable on an established tunnel: the same call had to succeed
		// at the handshake for this connection to exist.
		return who
	}
	who.Vendor = string(evidence.Vendor)
	who.PolicyDigest = binding.PolicyDigest.String()
	if a, ok := t.verdicts.lookup(binding.CallerSuppliedBytes()); ok {
		who.Measurement = hex.EncodeToString(a.Claims.LaunchMeasurement)
	}
	return who
}

// nameOf is the peer table read backwards, which is as much as naming is worth
// here.
//
// An accepted connection arrives from an ephemeral source port, so the table
// can only be matched on the address and never on the address and port
// together. One entry matching gives the name; none or several give nothing,
// because a name that might be either of two peers is worse than no name.
// Naming binds to nothing (spec, Reference values and naming): what identifies
// the peer is its measurement and the policy digest it presented, both of which
// are beside this in the same value.
func (t *Tunneld) nameOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	var found string
	for name, peer := range t.cfg.Peers {
		h, _, err := net.SplitHostPort(peer)
		if err != nil || h != host {
			continue
		}
		if found != "" {
			return ""
		}
		found = name
	}
	return found
}

// A verdictBook remembers what this tunneld's listening side concluded about
// each peer it admitted, so that an accepted tunnel can be named later.
//
// The verdict is reached inside the TLS handshake, in [ratls.PeerVerifier],
// which hands it to nothing: a refusal goes to the refusal log and an
// acceptance goes nowhere, because nothing above needed it until a sandbox had
// to be told who opened a stream. The listening side asks nothing further of a
// peer — whom this sandbox *dials* is its own policy's business and that check
// is on the dialing configuration — so its admission hook is free, and this
// uses it to keep the verdict rather than adding a second way for one to leave
// the handshake.
//
// It is keyed by the caller-supplied bytes the evidence was acquired over,
// which is the one value that identifies a peer's identity exactly: it is a
// hash over the binding context, the policy digest and the public key TLS
// proved possession of, and [attest.Verification.Verify] has already refused
// the peer unless the evidence carries precisely it. Looking a connection's
// certificate up under it therefore finds the verdict for that certificate or
// finds nothing. The map holds one entry per distinct peer identity admitted,
// and a peer that re-handshakes overwrites its own.
type verdictBook struct {
	mu sync.Mutex
	m  map[string]attest.Attested
}

func newVerdictBook() *verdictBook {
	return &verdictBook{m: map[string]attest.Attested{}}
}

// remember is the admission hook: it admits every peer verification admitted,
// and keeps what it was told.
func (b *verdictBook) remember(a attest.Attested) error {
	key := a.Claims.CallerSuppliedBytes
	b.mu.Lock()
	b.m[string(key[:])] = a
	b.mu.Unlock()
	return nil
}

func (b *verdictBook) lookup(key [attest.CallerSuppliedBytesSize]byte) (attest.Attested, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.m[string(key[:])]
	return a, ok
}
