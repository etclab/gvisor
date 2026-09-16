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

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// streamConn is the contract's Stream as a net.Conn, which is what net/http
// dials.
//
// E2 had to write this and could not finish it. net.Conn wants two addresses
// and three deadlines that sandbox.Stream had not got, and the shim answered
// nil to all three — which net/http and crypto/tls both believed, so an agent
// behind the contract had no I/O timeout and a cancelled request could not
// free the goroutine blocked on the stream (E2, break 3). Contract version 2
// gave Stream the three deadlines, so the methods here are delegations and no
// longer lies.
//
// The two addresses are still fabricated, and say so. There is nothing behind
// them to fabricate from: a stream to an attested peer has no local port and
// no remote one, and Attested carries four strings none of which is an
// address. A consumer that logs them will log "synthetic", which is the true
// answer.
type streamConn struct {
	s sandbox.Stream

	// r is whatever read the exit's answer line, because it may already hold
	// bytes that arrived behind it. Reads come from here and not from s.
	r io.Reader

	peer string
}

var _ net.Conn = (*streamConn)(nil)

// newStreamConn wraps one stream. A nil r reads from the stream directly,
// which is what a caller that has not read anything first wants.
func newStreamConn(s sandbox.Stream, r io.Reader, peer string) *streamConn {
	if r == nil {
		r = s
	}
	return &streamConn{s: s, r: r, peer: peer}
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.s.Write(p) }
func (c *streamConn) Close() error                { return c.s.Close() }

// CloseWrite is not part of net.Conn, and is here because it is part of
// Stream: a consumer that knows to look for it — net/http's own transport does
// — gets the half-close the contract carries.
func (c *streamConn) CloseWrite() error { return c.s.CloseWrite() }

func (c *streamConn) SetDeadline(t time.Time) error      { return c.s.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.s.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

func (c *streamConn) LocalAddr() net.Addr  { return contractAddr("synthetic:this-sandbox") }
func (c *streamConn) RemoteAddr() net.Addr { return contractAddr("synthetic:peer=" + c.peer) }

// contractAddr is an address that is not one. Network() names the contract so
// that anything printing it says where the shape came from.
type contractAddr string

func (a contractAddr) Network() string { return "sandbox-contract" }
func (a contractAddr) String() string  { return string(a) }

// dialThrough is the DialContext an agent behind the contract runs on: every
// dial is Open to the one peer this binary has, and the address net/http
// wanted travels as the first line of the stream.
//
// net/http resolves inside the dialer it is given, so a dialer that never
// resolves means this agent never resolves: addr arrives as a host and a port
// and the resolver's whole row in E1's table belongs to the exit from here on
// (E2, break 1).
func dialThrough(box sandbox.Network, peer string, logf func(string, ...any)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("agent-probe: the contract carries no %s", network)
		}
		began := time.Now()
		s, err := box.Open(ctx, peer)
		if err != nil {
			return nil, fmt.Errorf("agent-probe: Open(%q) for %s: %w", peer, addr, err)
		}
		conn, err := connect(ctx, s, addr, peer)
		if err != nil {
			s.Close()
			return nil, err
		}
		logf("DIAL %s over Open(%q) in %s", addr, peer, time.Since(began).Round(time.Microsecond))
		return conn, nil
	}
}

// connect says where the stream is going and reads the exit's one-line answer.
//
// The deadline is the dial context's, and it is contract version 2 earning its
// place on the first line of the first thing anybody put on a stream: before
// it there was no way to bound this read at all, and an exit that never
// answered would have hung the dial for as long as the agent ran.
func connect(ctx context.Context, s sandbox.Stream, addr, peer string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		s.SetDeadline(deadline)
	}
	if _, err := io.WriteString(s, "CONNECT "+addr+"\n"); err != nil {
		return nil, fmt.Errorf("agent-probe: %s: saying where the stream is going: %w", addr, err)
	}
	br := bufio.NewReader(s)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("agent-probe: %s: the exit said nothing: %w", addr, err)
	}
	if _, ok := strings.CutPrefix(strings.TrimSpace(line), "OK "); !ok {
		return nil, fmt.Errorf("agent-probe: %s: the exit would not dial it: %s", addr, strings.TrimSpace(line))
	}
	// From here the stream is the client's, and net/http sets its own
	// deadlines on it.
	s.SetDeadline(time.Time{})
	return newStreamConn(s, br, peer), nil
}
