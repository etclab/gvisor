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
package tunneld

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

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

// Tunneld is a running tunneld. Construct one with New.
type Tunneld struct {
	cfg          Config
	identity     *ratls.Identity
	verification *attest.Verification
	listener     *tunnel.Listener
	refusals     ratls.Option

	mu     sync.Mutex
	closed bool
	conns  []*tunnel.Conn
	wg     sync.WaitGroup
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
	listener, err := tunnel.Listen(addr, identity.ServerConfig(verification, refusals))
	if err != nil {
		return nil, fmt.Errorf("tunneld: refusing to start: %w", err)
	}
	t := &Tunneld{cfg: cfg, identity: identity, verification: verification, listener: listener, refusals: refusals}
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
		t.conns = append(t.conns, conn)
		t.mu.Unlock()
		go conn.Serve(t.handle)
	}
}

func (t *Tunneld) handle(ctx context.Context, request []byte) ([]byte, error) {
	if t.cfg.Handler == nil {
		return nil, errors.New("tunneld: no handler")
	}
	return t.cfg.Handler(ctx, request)
}

// Peer resolves name through the peer table and establishes a tunnel to it.
// The channel exists only once both sides have accepted the other's
// evidence; anything less is an error and no channel.
func (t *Tunneld) Peer(ctx context.Context, name string) (*Channel, error) {
	addr, ok := t.cfg.Peers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not in the peer table", ErrUnknownPeer, name)
	}
	conn, err := tunnel.Dial(ctx, addr, t.identity.ClientConfig(t.verification, t.refusals))
	if err != nil {
		return nil, fmt.Errorf("%w: %q at %s: %v", ErrNotEstablished, name, addr, err)
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("%w: tunneld is closed", ErrNotEstablished)
	}
	t.conns = append(t.conns, conn)
	t.mu.Unlock()
	return &Channel{name: name, conn: conn}, nil
}

// Close stops listening and ends every tunnel.
func (t *Tunneld) Close() error {
	t.mu.Lock()
	t.closed = true
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()
	err := t.listener.Close()
	for _, c := range conns {
		c.Close()
	}
	t.wg.Wait()
	return err
}

// Channel is what a caller gets for a named peer: a means to exchange
// messages, with no key and no trust decision attached.
type Channel struct {
	name string
	conn *tunnel.Conn
}

// Peer is the name the channel was asked for.
func (c *Channel) Peer() string { return c.name }

// Exchange sends one request and returns the peer's response.
func (c *Channel) Exchange(ctx context.Context, request []byte) ([]byte, error) {
	return c.conn.Exchange(ctx, request)
}

// Close ends the tunnel behind the channel.
func (c *Channel) Close() error { return c.conn.Close() }
