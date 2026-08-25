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
// to refuse early data, carry an exchange, and nothing more. Connection
// caching, idle and age limits, and the framing checks arrive with tickets 11
// and 12 and belong here when they do.
package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go"
)

// Early data is refused on both ends. A listener's Allow0RTT stays false, and
// the dial path is quic.DialAddr rather than DialAddrEarly, so a replayed
// privileged exchange has no 0-RTT slot to ride in on.
func config() *quic.Config {
	return &quic.Config{Allow0RTT: false}
}

// Listener accepts tunnels.
type Listener struct {
	l *quic.Listener
}

// Listen binds a UDP address. Pass a port of 0 to take an ephemeral one and
// read it back through Addr.
func Listen(addr string, tlsConf *tls.Config) (*Listener, error) {
	l, err := quic.ListenAddr(addr, tlsConf, config())
	if err != nil {
		return nil, fmt.Errorf("tunnel: listening on %s: %w", addr, err)
	}
	return &Listener{l: l}, nil
}

// Addr is the bound address.
func (l *Listener) Addr() net.Addr { return l.l.Addr() }

// Accept waits for the next connection whose handshake completed — which,
// with ratls in the TLS configuration, means this side verified the peer —
// and then answers the peer's establishment round trip, which is what tells
// the peer that it happened.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	c, err := l.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	if err := answerEstablishment(ctx, c); err != nil {
		c.CloseWithError(errProtocol, "establishment")
		return nil, fmt.Errorf("tunnel: establishing: %w", err)
	}
	return &Conn{c: c}, nil
}

// Close stops accepting. Established connections are unaffected.
func (l *Listener) Close() error { return l.l.Close() }

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

// Conn is one established tunnel.
type Conn struct {
	c *quic.Conn
}

// Exchange sends one request on a fresh stream and returns the response. The
// request ends when its stream's write side closes; the response ends at
// end-of-stream.
func (c *Conn) Exchange(ctx context.Context, request []byte) ([]byte, error) {
	s, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: opening a stream: %w", err)
	}
	defer s.CancelRead(0)
	if _, err := s.Write(request); err != nil {
		return nil, fmt.Errorf("tunnel: sending the request: %w", err)
	}
	if err := s.Close(); err != nil {
		return nil, fmt.Errorf("tunnel: finishing the request: %w", err)
	}
	response, err := io.ReadAll(s)
	if err != nil {
		return nil, fmt.Errorf("tunnel: reading the response: %w", err)
	}
	return response, nil
}

// Handler answers one exchange.
type Handler func(ctx context.Context, request []byte) ([]byte, error)

// Serve answers exchanges on c until the connection ends. Each stream is one
// exchange; a handler error closes that stream without a response.
func (c *Conn) Serve(handler Handler) error {
	for {
		s, err := c.c.AcceptStream(c.c.Context())
		if err != nil {
			return err
		}
		go func() {
			request, err := io.ReadAll(s)
			if err != nil {
				s.CancelWrite(0)
				return
			}
			response, err := handler(c.c.Context(), request)
			if err != nil {
				s.CancelWrite(0)
				return
			}
			s.Write(response)
			s.Close()
		}()
	}
}

// Close ends the connection.
func (c *Conn) Close() error { return c.c.CloseWithError(0, "") }
