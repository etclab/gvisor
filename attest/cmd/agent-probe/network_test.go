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
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// quiet is the log a test does not read. What the contract path did is
// asserted on what came back through it and on counted, below: a line saying
// the exit dialed is the exit's word for it, and the model's answer arriving
// is the path itself.
func quiet(string, ...any) {}

func TestTheNullNetworkCarriesTheWholeLoopThroughOpenAndTheExit(t *testing.T) {
	// The fake model is on loopback and is reached the way api.anthropic.com
	// is reached in a real run: the transport dials its host and port, the
	// address travels as the CONNECT line, and the exit resolves and dials it.
	// Plain HTTP is enough here — in the real run TLS is end to end from the
	// loop to the model and the exit sees ciphertext only (spike E2).
	doc, docHost := document(t, "RFC 8446 defines TLS 1.3.")
	work := t.TempDir()
	model := canned(t,
		turnUsing(100, 20, use("tu_1", "fetch_url", `{"url":"`+doc+`/rfc8446.txt"}`)),
		turnUsing(200, 30, use("tu_2", "write_file", `{"path":"summary.txt","content":"one sentence"}`)),
		endTurn(300, 40, "DONE"))

	// The exit's list names exactly the two destinations this run may reach.
	// A run that completes is therefore a run whose CONNECT lines said those
	// two names and were checked against them — which is a stronger statement
	// than counting streams, and it is the enforcement point the study is
	// about standing in the path rather than beside it.
	allow, err := parseAllow(model.host + "," + docHost)
	if err != nil {
		t.Fatalf("the allow list: %v", err)
	}
	box := sandbox.NewNull(&localExit{logf: quiet, allow: allow}, quiet)
	w := behindTheContract(box, "b", quiet)
	defer w.close()

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	res, err := Run(ctx, w.client, Summarize(), Tools{FetchURL: true, WriteDir: work}, io.Discard)
	if err != nil {
		t.Fatalf("the agent behind the contract: %v", err)
	}
	if res.Final != "DONE" {
		t.Errorf("the final text is %q; want DONE", res.Final)
	}
	if len(res.Calls) != 2 {
		t.Errorf("the run made %d tool calls; want the fetch and the write", len(res.Calls))
	}
	if res.ToolError {
		t.Error("a tool failed behind the contract; both destinations were in the exit's list")
	}
}

func TestTheExitRefusesADestinationTheAllowListDoesNotName(t *testing.T) {
	// Something to reach, so that the two halves of the list are the only
	// difference between the dial that works and the dial that does not.
	echo, addr := echoListener(t)
	defer echo.Close()

	allow, err := parseAllow(addr)
	if err != nil {
		t.Fatalf("-allow %s: %v", addr, err)
	}
	dial := dialThrough(&localExit{logf: quiet, allow: allow}, "b", quiet)

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	// The destination in the list: dialed, and the bytes go both ways with the
	// half-close carried.
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("the exit would not dial %s, which is in -allow: %v", addr, err)
	}
	io.WriteString(conn, "hello")
	conn.(*streamConn).CloseWrite()
	back, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("reading back through the exit: %v", err)
	}
	if string(back) != "hello" {
		t.Errorf("the echo came back as %q; want hello", back)
	}
	conn.Close()

	// A destination that is not: one line, and the agent has a dial error.
	// 127.0.0.1:9 is discard, which nothing here is listening on — the point
	// is that the exit never dials it at all.
	_, err = dial(ctx, "tcp", "127.0.0.1:9")
	if err == nil {
		t.Fatal("the exit dialed a destination -allow does not name")
	}
	if !strings.Contains(err.Error(), "REFUSED 127.0.0.1:9") {
		t.Errorf("the dial failed with %v; want the exit's REFUSED line", err)
	}
}

func TestAReadDeadlineOnTheAdapterReachesTheStream(t *testing.T) {
	// Spike E2's shim answered nil to all three deadlines and net/http
	// believed it, so an agent behind the contract had no I/O timeout at all.
	// Contract version 2 gave Stream the three methods; this is the test that
	// the adapter passes them on rather than answering nil again.
	fake := &deadlineStream{}
	conn := newStreamConn(fake, nil, "b")
	when := time.Now().Add(time.Minute)

	if err := conn.SetReadDeadline(when); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if !fake.read.Equal(when) {
		t.Errorf("the stream's read deadline is %v; want %v", fake.read, when)
	}
	if err := conn.SetWriteDeadline(when); err != nil || !fake.write.Equal(when) {
		t.Errorf("the stream's write deadline is %v (err %v); want %v", fake.write, err, when)
	}
	if err := conn.SetDeadline(when); err != nil || !fake.both.Equal(when) {
		t.Errorf("the stream's deadline is %v (err %v); want %v", fake.both, err, when)
	}

	// And the two addresses, which are the part that is still fabricated and
	// which says so to anything that prints it.
	if got := conn.RemoteAddr(); got.Network() != "sandbox-contract" || !strings.HasPrefix(got.String(), "synthetic:") {
		t.Errorf("RemoteAddr is %s/%s; a fabricated address has to say that it is one", got.Network(), got)
	}
	if got := conn.LocalAddr(); !strings.HasPrefix(got.String(), "synthetic:") {
		t.Errorf("LocalAddr is %s; a fabricated address has to say that it is one", got)
	}
}

// deadlineStream is a Stream that does nothing and remembers what it was told.
type deadlineStream struct {
	read, write, both time.Time
}

var _ sandbox.Stream = (*deadlineStream)(nil)

func (s *deadlineStream) Read([]byte) (int, error)          { return 0, io.EOF }
func (s *deadlineStream) Write(p []byte) (int, error)       { return len(p), nil }
func (s *deadlineStream) Close() error                      { return nil }
func (s *deadlineStream) CloseWrite() error                 { return nil }
func (s *deadlineStream) SetDeadline(t time.Time) error     { s.both = t; return nil }
func (s *deadlineStream) SetReadDeadline(t time.Time) error { s.read = t; return nil }
func (s *deadlineStream) SetWriteDeadline(t time.Time) error {
	s.write = t
	return nil
}

// echoListener is a destination for the exit to dial: it reads until the
// client has finished sending and writes the same bytes back.
func echoListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l, l.Addr().String()
}
