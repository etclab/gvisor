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
// loads its reference value set through [attest.LoadReferenceValueSetFile]
// against the author public key it was started with, and there is no path
// that starts without a set.
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

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
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

	// dialed holds the tunnels this tunneld opened, one per peer, and is what
	// makes a peer's tunnel lazy, warm and re-attested on schedule. The client
	// configuration it dials with is built once, at startup, from the one
	// identity this tunneld has.
	dialed *tunnel.Cache

	mu       sync.Mutex
	closed   bool
	accepted []*tunnel.Conn
	wg       sync.WaitGroup
}

// New starts a tunneld: loads and checks the reference value set, generates
// the key, acquires this platform's evidence, and begins listening. Any
// failure is a refusal to start; in particular a reference value set that
// does not load returns an error wrapping [attest.ErrSetRefused].
func New(ctx context.Context, cfg Config) (*Tunneld, error) {
	if cfg.SandboxID == "" {
		return nil, errors.New("tunneld: no sandbox identifier")
	}
	if cfg.Acquirer == nil || cfg.Verifier == nil {
		return nil, errors.New("tunneld: both halves of the vendor seam are required")
	}
	set, err := attest.LoadReferenceValueSetFile(cfg.ReferenceValueSetPath, cfg.AuthorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	verification, err := attest.New(cfg.Verifier, set)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	identity, err := ratls.NewIdentity(ctx, cfg.Acquirer)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	addr := cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	refusals := ratls.WithRefusalLog(refusalLog(cfg))
	listener, err := tunnel.Listen(addr, identity.ServerConfig(verification, refusals), cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	t := &Tunneld{
		cfg:      cfg,
		listener: listener,
		dialed:   tunnel.NewCache(identity.ClientConfig(verification, refusals), cfg.Limits),
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
		go conn.Serve(t.handle)
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
func (t *Tunneld) Peer(ctx context.Context, name string) (*Channel, error) {
	addr, ok := t.cfg.Peers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not in the peer table", ErrUnknownPeer, name)
	}
	if _, err := t.dialed.Get(ctx, addr); err != nil {
		return nil, fmt.Errorf("%w: %q at %s: %v", ErrNotEstablished, name, addr, err)
	}
	return &Channel{name: name, addr: addr, t: t}, nil
}

// Close stops listening and ends every tunnel, dialed and accepted.
func (t *Tunneld) Close() error {
	t.mu.Lock()
	t.closed = true
	accepted := t.accepted
	t.accepted = nil
	t.mu.Unlock()
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
	if c.closed.Load() {
		return nil, fmt.Errorf("%w: %q", ErrChannelClosed, c.name)
	}
	conn, err := c.t.dialed.Get(ctx, c.addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %q at %s: %v", ErrNotEstablished, c.name, c.addr, err)
	}
	return conn.Exchange(ctx, request)
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
