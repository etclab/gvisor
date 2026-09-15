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

// Package tunneld is the composition root of the attested tunnel and the
// public API everything above package attest is tested through: given a peer
// name, a channel or an error.
//
// A tunneld holds one sandbox's identity for the life of the process. It
// generates its key at startup and never persists it; it takes the sandbox
// identifier as a parameter, synthetic until the sentry integration supplies
// a real one, so that the key lifecycle here is already the final one. It
// loads one signed document against the author public key it was started with
// — its reference value set, through [attest.LoadReferenceValueSetFile] — and
// there is no path that starts without it.
//
// # The set and the digest are different questions
//
// The set is whom this sandbox admits: measurement and policy_digest pairs,
// enforced on every peer in either role. The digest in [Config.PolicyDigest]
// is what this sandbox presents about itself, for a peer's set to check
// against; what it names is the caller's to say, and the measured guest's
// command names the egress ceiling compiled into its image.
//
// The two were one document until ticket 19. Splitting them is what makes
// mutual pinning expressible at all: while a sandbox's policy was its own
// allow-list, A's set would have had to name the digest of B's set and B's the
// digest of A's, and neither digest can be fixed before the other.
//
// A second signed document — this sandbox's own policy, with its `forward_to`
// list — was loaded here beside the set until ticket 22, off the config
// device, and its digest was the one presented. Both are gone from this
// package: the ceiling that document used to carry is compiled into the
// measured image, and what a sandbox may delegate to whom is a contract pushed
// over the tunnel after attestation, not a list read off a disk the host
// supplies (docs/policy-binding.md).
//
// The vendor is injected through [Config]: an [attest.Acquirer] for this
// platform's evidence and an [attest.Verifier] for its peers'. Tests inject
// the fake platform there; nothing in this package knows which one it has.
//
// # The life of a tunnel
//
// A [Channel] is a handle on a peer and not on a connection. The tunnel under
// it is dialed the first time somebody asks for that peer, kept warm for
// everyone who asks afterwards, and dialed again whenever the one that was
// there has been lost or has reached its maximum age — at which point both
// sides judge each other's evidence again, because that is what a handshake
// is. [Config.Limits] sets both bounds; [tunnel.DefaultMaxAge] records why the
// maximum age is the number it is and what it does and does not bound.
package tunneld

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
)

// PeerTable maps peer names to addresses. It is deliberately not
// security-critical: a wrong address yields a failed handshake, never a
// compromised one, because attestation authenticates and naming does not.
type PeerTable map[string]string

// Handler answers the exchanges peers send to this tunneld.
type Handler = tunnel.Handler

// Limits bound the life of every tunnel this tunneld holds: how long one may
// carry nothing before it closes, and how long one may carry anything before
// both sides have to attest to each other again. See [tunnel.Limits], and
// [tunnel.DefaultMaxAge] for why the maximum age is the number it is.
type Limits = tunnel.Limits

// RefusalLog is handed every peer this tunneld refuses, with the typed reason
// that refused it. See [Config.RefusalLog].
type RefusalLog = ratls.RefusalLog

// Config is everything a tunneld is started with.
type Config struct {
	// SandboxID names the sandbox this tunneld serves. Synthetic for now; the
	// sentry integration supplies the real one. It is the unit of identity: one
	// tunneld, one sandbox, one key.
	SandboxID string

	// Acquirer produces this platform's evidence; Verifier judges peers'.
	// These are the two halves of the vendor seam.
	Acquirer attest.Acquirer
	Verifier attest.Verifier

	// ReferenceValueSetPath and AuthorPublicKey locate and authorise the
	// reference value set. A set that fails to load refuses startup.
	ReferenceValueSetPath string
	AuthorPublicKey       ed25519.PublicKey

	// PolicyDigest is the digest this tunneld presents to every peer it meets,
	// bound into its evidence under ADR-0002's amendment and checked against
	// the peer's own allow-list.
	//
	// It is required, and it is the caller's to choose because the caller is
	// the one thing that knows what this sandbox is: the command that builds
	// the measured guest passes the name of the egress ceiling compiled into
	// its image ([ceiling.Digest], ticket 22). It was the digest of the policy
	// at PolicyPath until then, which made the number a statement about a
	// document on a device the host supplies rather than about the image.
	PolicyDigest attest.PolicyDigest

	// Peers is the peer table.
	Peers PeerTable

	// ListenAddr is the UDP address to accept peers on. ":0" takes an
	// ephemeral port; read it back with Addr.
	ListenAddr string

	// Handler answers exchanges from peers. Nil answers none: every incoming
	// stream is closed without a response.
	Handler Handler

	// Limits bound how long a tunnel lives. The zero value takes the defaults,
	// which are 60 seconds idle and 15 minutes of age.
	Limits Limits

	// PushPolicy is the policy this tunneld pushes to every peer it dials,
	// after that peer has been admitted and before any stream or exchange
	// reaches it (push.go, docs/policy-push.md). Empty pushes nothing, which is
	// what every scenario recorded before ticket 22 does.
	//
	// The bytes are opaque and are not checked here, deliberately: a document
	// this side's own reader would refuse is still one a peer may read, and the
	// version that decides a push is the peer's. What a badly built one costs
	// is that peer's refusal, on the console, naming it. One policy goes to
	// every peer — per-peer delegation is what this field becomes when
	// something needs it, and a table keyed by peer name today would be a
	// second peer table with no test behind it.
	PushPolicy []byte

	// PushTimeout bounds how long a push waits for its acknowledgement. Zero
	// takes [DefaultPushTimeout], which New resolves once at startup the way
	// [Limits] resolves its own.
	PushTimeout time.Duration

	// RefusalLog receives every peer this tunneld refuses at the handshake,
	// whichever role it was in, with the typed reason that refused it. It is
	// the only place the reason surfaces: the peer sees an aborted handshake
	// and the caller sees [ErrNotEstablished], and neither can tell one reason
	// from another.
	//
	// Nil writes the line to standard error, which on a guest is the serial
	// console the design already says these logs go to. A tunneld that dropped
	// them by default would leave an operator with no way to tell a stale
	// certificate chain from a rolled image.
	RefusalLog RefusalLog
}

// ErrUnknownPeer is returned by Peer for a name the peer table does not hold.
var ErrUnknownPeer = errors.New("tunneld: unknown peer")

// ErrNotEstablished is returned when a tunnel to a known peer could not be
// established — the address was unreachable, or either side's evidence was
// refused. The caller learns only that; the reason stays in the operator log.
var ErrNotEstablished = errors.New("tunneld: tunnel not established")

// ErrChannelClosed is returned by [Channel.Exchange] on a channel its holder
// has closed.
var ErrChannelClosed = errors.New("tunneld: channel closed")

// Tunneld is a running tunneld. Construct one with New.
type Tunneld struct {
	cfg      Config
	listener *tunnel.Listener

	// unconstrained is the values in this tunneld's set that list no policy of
	// their own. It is read off disk at startup and never changes: the set is
	// loaded once, and the identity bound to [Config.PolicyDigest] is held for
	// the life of the process.
	unconstrained []attest.UnconstrainedValue

	// dialed holds the tunnels this tunneld opened, one per peer, and is what
	// makes a peer's tunnel lazy, warm and re-attested on schedule. The client
	// configuration it dials with is built once, at startup, from the one
	// identity this tunneld has.
	dialed *tunnel.Cache

	// The sandbox contract's three fields (sandbox.go): what the listening side
	// concluded about each peer it admitted, the streams peers have opened and
	// nobody has accepted yet, and the channel that closes when this tunneld
	// does so that a sandbox waiting in Accept is told rather than left there.
	verdicts *verdictBook
	incoming chan accepted
	done     chan struct{}

	// pushes is the policy push made on each tunnel this tunneld dialed, so
	// that one tunnel carries one push however many callers raced for it
	// (push.go).
	pushes *pushBook

	// refusals is where every reason this tunneld reaches is written: the
	// handshake's, through ratls, and a pushed policy that was not applied
	// (push.go). One sink, because an operator reading a console has one place
	// to look.
	refusals RefusalLog

	mu       sync.Mutex
	closed   bool
	accepted []*tunnel.Conn
	// box is the sandbox a pushed policy is handed to, set by [Tunneld.Attach]
	// and nil until it is (push.go).
	box sandbox.Sandbox
	wg  sync.WaitGroup
}

// New starts a tunneld: loads and checks the reference value set, generates the
// key, acquires this platform's evidence, and begins listening. Any failure is
// a refusal to start; in particular a reference value set that does not load
// returns an error wrapping [attest.ErrSetRefused].
func New(ctx context.Context, cfg Config) (*Tunneld, error) {
	if cfg.SandboxID == "" {
		return nil, errors.New("tunneld: no sandbox identifier")
	}
	if cfg.Acquirer == nil || cfg.Verifier == nil {
		return nil, errors.New("tunneld: both halves of the vendor seam are required")
	}
	if cfg.PolicyDigest == (attest.PolicyDigest{}) {
		return nil, errors.New("tunneld: no policy digest; a tunneld that presented none would ask every peer to admit it on its measurement alone")
	}
	if cfg.PushTimeout <= 0 {
		cfg.PushTimeout = DefaultPushTimeout
	}
	set, err := attest.LoadReferenceValueSetFile(cfg.ReferenceValueSetPath, cfg.AuthorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	verification, err := attest.New(cfg.Verifier, set)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	// The digest the caller named is what the identity binds into the evidence
	// and what a peer checks against its own allow-list.
	identity, err := ratls.NewIdentity(ctx, cfg.Acquirer, cfg.PolicyDigest)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	addr := cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	logRefusal := refusalLog(cfg)
	refusals := ratls.WithRefusalLog(logRefusal)
	// The listening side asks nothing more of a peer than verification did, so
	// its admission hook keeps the verdict instead (sandbox.go, verdictBook):
	// it is what names the peer that opened a stream to the sandbox.
	verdicts := newVerdictBook()
	listener, err := tunnel.Listen(addr, identity.ServerConfig(verification, refusals, ratls.WithAdmission(verdicts.remember)), cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	// Both roles are built from the same set, and since ticket 22 there is
	// nothing else in either: the dialing side carried one extra check until
	// then, this sandbox's own `forward_to`, and the document it came from does
	// not reach this package any more. [ratls.WithAdmission] is where a check
	// of that kind goes when the pushed contract brings one back.
	client := identity.ClientConfig(verification, refusals)
	t := &Tunneld{
		cfg:           cfg,
		listener:      listener,
		unconstrained: set.Unconstrained(),
		dialed:        tunnel.NewCache(client, cfg.Limits),
		verdicts:      verdicts,
		incoming:      make(chan accepted),
		done:          make(chan struct{}),
		pushes:        newPushBook(),
		refusals:      logRefusal,
	}
	t.wg.Add(1)
	go t.accept()
	return t, nil
}

// refusalLog is the sink refusals go to: the one the caller supplied, or
// standard error prefixed with the sandbox, so that two tunnelds in one process
// are told apart.
func refusalLog(cfg Config) RefusalLog {
	if cfg.RefusalLog != nil {
		return cfg.RefusalLog
	}
	return func(r *attest.Refusal) {
		fmt.Fprintf(os.Stderr, "tunneld[%s]: %s\n", cfg.SandboxID, r.LogString())
	}
}

// SandboxID is the sandbox this tunneld serves.
func (t *Tunneld) SandboxID() string { return t.cfg.SandboxID }

// Addr is the address peers reach this tunneld at.
func (t *Tunneld) Addr() net.Addr { return t.listener.Addr() }

// PolicyDigest is the digest this tunneld presents to every peer it meets
// (ADR-0002's amendment), which is the one its caller gave it.
//
// It is here so that the process around a tunneld can print it: a peer admits
// this sandbox only if one of its own reference values lists this number, and
// the only way an operator gets it is off a start log. It names something a
// reader of the image can recompute for themselves, so nothing about
// publishing it is a disclosure.
func (t *Tunneld) PolicyDigest() attest.PolicyDigest { return t.cfg.PolicyDigest }

// Unconstrained is the values in this tunneld's own set that list no policy
// digest, and so admit a peer running the named image under any policy at all.
//
// It is exposed for the same reason as [Tunneld.PolicyDigest] and with more
// urgency: an unconstrained value is the weaker reading of an absent field,
// which this design takes exactly once, and a deployment that did not mean to
// take it should be able to see that it did.
func (t *Tunneld) Unconstrained() []attest.UnconstrainedValue { return t.unconstrained }

func (t *Tunneld) accept() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept(context.Background())
		if err != nil {
			return
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			conn.Close()
			return
		}
		// Tunnels that have already closed — idle, expired, or ended by their
		// peer — are dropped as new ones arrive, so this list is what is open
		// rather than everything that ever was. A tunnel past its maximum age
		// but not yet torn down stays: its own expiry closes it, and dropping
		// it here would mean nothing did.
		t.accepted = append(live(t.accepted), conn)
		t.mu.Unlock()
		// A policy push is one of the exchanges this tunnel carries, and the
		// handler is bound to the connection so that a push it refuses can end
		// it (push.go).
		go conn.Serve(t.handleFor(conn))
		// And beside the exchanges, the streams: Serve tells the two apart and
		// this carries the raw ones to the sandbox (sandbox.go).
		go t.acceptStreams(conn)
	}
}

func live(conns []*tunnel.Conn) []*tunnel.Conn {
	kept := conns[:0]
	for _, c := range conns {
		if c.Live() {
			kept = append(kept, c)
		}
	}
	return kept
}

func (t *Tunneld) handle(ctx context.Context, request []byte) ([]byte, error) {
	if t.cfg.Handler == nil {
		return nil, errors.New("tunneld: no handler")
	}
	return t.cfg.Handler(ctx, request)
}

// Peer resolves name through the peer table and gives back a channel to it.
// The channel exists only once both sides have accepted the other's evidence;
// anything less is an error and no channel.
//
// The tunnel underneath is dialed on first use and reused afterwards. Asking
// for a peer a second time is not a second handshake, and no tunnel is dialed
// for a peer nobody has asked for: the peer table is a table of addresses, not
// a list of connections to open.
//
// Establishing here rather than at the first exchange is what makes a refusal
// visible where the caller asked for the peer. A channel handed back before
// anything was verified would be a channel that fails later for a reason the
// caller cannot see, which is the shape this design refuses everywhere else.
//
// It establishes by asking the channel it is about to hand back for its tunnel,
// rather than by reaching for the cache itself, so that there is one path to a
// tunnel and everything on it — the dial, the attestation, the policy pushed
// and acknowledged — happens once and in one order.
func (t *Tunneld) Peer(ctx context.Context, name string) (*Channel, error) {
	addr, ok := t.cfg.Peers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not in the peer table", ErrUnknownPeer, name)
	}
	c := &Channel{name: name, addr: addr, t: t}
	if _, err := c.tunnelTo(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// admitted is the tunnel to a peer, established and under this tunneld's
// policy: the cache dials and attests one if there is none, and the policy this
// tunneld pushes goes out on it and is acknowledged before it is handed back
// (push.go).
//
// Everything that reaches a peer comes through here — [Tunneld.Peer] and both
// of a channel's verbs — which is what makes "nothing is sent before the
// acknowledgement" a property of the type rather than of remembering to ask.
// The push cannot precede admission for the same reason: there is no
// connection to make it on until the cache has returned one, and the cache
// returns what Dial established or the error it failed with.
func (t *Tunneld) admitted(ctx context.Context, name, addr string) (*tunnel.Conn, error) {
	conn, err := t.dialed.Get(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %q at %s: %v", ErrNotEstablished, name, addr, err)
	}
	if err := t.pushPolicy(ctx, conn, name, addr); err != nil {
		return nil, err
	}
	return conn, nil
}

// Close stops listening and ends every tunnel, dialed and accepted.
func (t *Tunneld) Close() error {
	t.mu.Lock()
	was := t.closed
	t.closed = true
	accepted := t.accepted
	t.accepted = nil
	t.mu.Unlock()
	if !was {
		// Once, so that closing twice is not a panic: a sandbox waiting in
		// Accept is released here.
		close(t.done)
	}
	err := t.listener.Close()
	t.dialed.Close()
	for _, c := range accepted {
		c.Close()
	}
	t.wg.Wait()
	return err
}

// Channel is what a caller gets for a named peer: a means to exchange
// messages, with no key and no trust decision attached.
//
// It is a handle on a peer, not on a connection. It holds the name it was
// asked for and nothing else, and every exchange takes the tunnel from the
// cache at the moment it runs — which is what lets a tunnel be lost, or reach
// its maximum age and be re-attested, underneath a channel its holder keeps
// using.
type Channel struct {
	name   string
	addr   string
	t      *Tunneld
	closed atomic.Bool
}

// Peer is the name the channel was asked for.
func (c *Channel) Peer() string { return c.name }

// Exchange sends one request and returns the peer's response, over the tunnel
// to this peer — dialing one first if the tunnel that was there has been lost
// or has reached its maximum age.
//
// A request that reached the wire is never sent a second time. Re-dialing is
// transparent; re-sending would not be, because an exchange this design calls
// privileged is exactly the thing replay must not be able to do, and a
// transport that retried on the caller's behalf would replay it for them. A
// caller whose exchange dies in flight sees the error, and its next exchange
// runs over a new tunnel.
func (c *Channel) Exchange(ctx context.Context, request []byte) ([]byte, error) {
	conn, err := c.tunnelTo(ctx)
	if err != nil {
		return nil, err
	}
	response, err := conn.Exchange(ctx, request)
	return response, c.lost(conn, err)
}

// lost is what a failure becomes when the tunnel under it has gone.
//
// The cache had not yet heard: Live is the last thing this side was told, not a
// promise about the next instant. To the caller it is the same event as a
// tunnel found gone before the call started, and both of a channel's verbs say
// so in the same sentence. Anything else is the caller's own error, returned
// unchanged.
func (c *Channel) lost(conn *tunnel.Conn, err error) error {
	if err != nil && !conn.Live() {
		return fmt.Errorf("%w: %q at %s: %v", ErrNotEstablished, c.name, c.addr, err)
	}
	return err
}

// tunnelTo is what both of a channel's verbs do before they do anything: refuse
// a channel no tunneld made, refuse one its holder has closed, and take the
// tunnel to this peer out of the cache at the moment it is asked for — which is
// where it is dialed if there is none, re-dialed and re-attested if the one
// that was there is gone or has reached its maximum age, and where this
// tunneld's policy is pushed to the peer and acknowledged ([Tunneld.admitted]).
//
// A Channel nobody's Peer returned is the first of those: the type is exported
// and its fields are not, so &Channel{} compiles and reaches no peer. It is
// refused the way a closed one is rather than dereferencing the tunneld it has
// not got (spike E2).
func (c *Channel) tunnelTo(ctx context.Context) (*tunnel.Conn, error) {
	if c.t == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoTunneld, c.name)
	}
	if c.closed.Load() {
		return nil, fmt.Errorf("%w: %q", ErrChannelClosed, c.name)
	}
	return c.t.admitted(ctx, c.name, c.addr)
}

// Close gives up this channel. It does not end the tunnel: the tunnel is
// cached per peer and may be carrying another caller's exchanges, and its life
// belongs to the idle timeout and the maximum age rather than to whoever
// happened to ask for the peer first. A closed channel refuses further
// exchanges with [ErrChannelClosed].
func (c *Channel) Close() error {
	c.closed.Store(true)
	return nil
}
