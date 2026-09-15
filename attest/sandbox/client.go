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

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// A Client is a sandbox's side of the contract when the sandbox is in another
// process: it dials tunneld's socket, asks for streams over it, and answers the
// policy tunneld pushes down it.
//
// It is a [Network], so a sandbox written against the in-process contract runs
// unchanged over the socket — which is the property the whole boundary exists
// for. A sandbox that wants the null behaviour composes the two:
//
//	var null *sandbox.Null
//	c, err := sandbox.Dial(path, func(ctx context.Context, p []byte) error {
//		return null.Apply(ctx, p)
//	})
//	null = sandbox.NewNull(c, logf)
//
// A stream arrives as a descriptor and is handed back as a *net.UnixConn, which
// satisfies [Stream] as it stands: read, write, CloseWrite, Close. What is on
// the other side of it is tunneld's pump, not the peer, so an end in either
// direction is carried but a reset is not (spike E1).
type Client struct {
	w     *wire
	p     pending
	apply func(context.Context, []byte) error

	ctx  context.Context
	stop context.CancelFunc
	once sync.Once
}

// ErrTunneldClosed is returned once the socket to tunneld has gone.
var ErrTunneldClosed = errors.New("sandbox: the tunneld socket closed")

var _ Network = (*Client)(nil)

// Dial connects to the socket tunneld listens on. apply answers a pushed
// policy: a nil error acknowledges it and any error refuses it. A nil apply
// refuses every push, which is the honest answer for a sandbox that takes no
// policy.
func Dial(path string, apply func(context.Context, []byte) error) (*Client, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("sandbox: dialing %s: %w", path, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	cl := &Client{w: &wire{c: c}, apply: apply, ctx: ctx, stop: stop}
	go cl.serve()
	return cl, nil
}

// Open asks tunneld for a stream to the named peer.
func (c *Client) Open(ctx context.Context, peer string) (Stream, error) {
	r, err := c.request(ctx, message{Type: msgOpen, Peer: peer})
	if err != nil {
		return nil, err
	}
	s, _, err := stream(r)
	return s, err
}

// Accept takes the next stream a peer opened to this sandbox, with the identity
// tunneld admitted it under.
func (c *Client) Accept(ctx context.Context) (Stream, Attested, error) {
	r, err := c.request(ctx, message{Type: msgAccept})
	if err != nil {
		return nil, Attested{}, err
	}
	return stream(r)
}

// Close gives up the socket. Streams already received are unaffected: each is
// its own descriptor, and closing this changes nothing about them.
func (c *Client) Close() error {
	c.once.Do(func() {
		c.stop()
		c.w.c.Close()
	})
	return nil
}

// request sends one message and waits for the reply that carries its id.
func (c *Client) request(ctx context.Context, m message) (reply, error) {
	id, ch := c.p.begin()
	defer c.p.end(id, ch)
	m.ID = id
	if err := c.w.send(m, -1); err != nil {
		return reply{}, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-ctx.Done():
		return reply{}, ctx.Err()
	case <-c.ctx.Done():
		return reply{}, ErrTunneldClosed
	}
}

// stream turns a reply into the stream it carries, or into tunneld's error.
//
// The error text is tunneld's own, unchanged. It says the stream did not
// happen — an unknown peer, an unreachable one, a handshake that did not
// complete — and it is the same text an in-process sandbox would have been
// handed. No refusal reason travels in it, because none reaches the contract in
// the first place.
func stream(r reply) (Stream, Attested, error) {
	if r.m.Type != msgStream {
		r.discard()
		if r.m.Error == "" {
			return nil, Attested{}, fmt.Errorf("%w: a %q message where a stream was expected", ErrProtocol, r.m.Type)
		}
		return nil, Attested{}, errors.New(r.m.Error)
	}
	if r.f == nil {
		return nil, Attested{}, fmt.Errorf("%w: a stream reply carried no descriptor", ErrProtocol)
	}
	defer r.f.Close()
	conn, err := net.FileConn(r.f)
	if err != nil {
		return nil, Attested{}, fmt.Errorf("sandbox: the descriptor tunneld sent: %w", err)
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, Attested{}, fmt.Errorf("%w: the descriptor tunneld sent is a %T", ErrProtocol, conn)
	}
	var who Attested
	if r.m.Attested != nil {
		who = *r.m.Attested
	}
	return u, who, nil
}

// serve reads tunneld's messages until the socket goes: replies to what this
// sandbox asked for, and the policy tunneld pushes.
func (c *Client) serve() {
	defer c.Close()
	for {
		m, f, err := c.w.receive()
		if err != nil {
			return
		}
		switch m.Type {
		case msgStream, msgError:
			c.p.deliver(reply{m: m, f: f})
		case msgApply:
			if f != nil {
				f.Close()
			}
			go c.applied(m)
		default:
			if f != nil {
				f.Close()
			}
			c.w.send(message{ID: m.ID, Type: msgRefusal, Error: "unknown message type " + m.Type}, -1)
		}
	}
}

// applied answers one push. It runs on its own goroutine so that a sandbox
// taking its time over a policy does not stop it receiving the streams it
// already asked for.
func (c *Client) applied(m message) {
	if c.apply == nil {
		c.w.send(message{ID: m.ID, Type: msgRefusal, Error: "this sandbox takes no policy"}, -1)
		return
	}
	if err := c.apply(c.ctx, m.Policy); err != nil {
		c.w.send(message{ID: m.ID, Type: msgRefusal, Error: err.Error()}, -1)
		return
	}
	c.w.send(message{ID: m.ID, Type: msgAck}, -1)
}
