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
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The exercise, now that it is the null sandbox's first client.
//
// What is checked is the shape of what it prints, because that is what every
// recorded scenario under docs/snp reads. The exercise moved from
// Channel.Exchange to a stream per exchange over the contract; the three
// LATENCY lines and the summary they carry did not move, and a harness parsing
// a console from before ticket 22 parses one from after it.

func TestTheExercisePrintsTheSameThreeFiguresOverTheContract(t *testing.T) {
	box := &loopbackSandbox{answerer: "sandbox-b"}
	var lines linesf
	e := exercise{Dial: []string{"b"}, Exchanges: 3, Concurrency: 2, Rounds: 2, Payload: "the-marker"}
	if err := e.perform(context.Background(), box, newWatchedVerifier(nil, lines.logf), lines.logf); err != nil {
		t.Fatalf("the exercise failed: %v", err)
	}

	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`^LATENCY pass=1 peer=b kind=establish ms=[0-9.]+ attempts=1 verifier_calls=0$`),
		regexp.MustCompile(`^LATENCY pass=1 peer=b kind=warm_exchange n=3 min_ms=[0-9.]+ p50_ms=[0-9.]+ p90_ms=[0-9.]+ max_ms=[0-9.]+ mean_ms=[0-9.]+ answered_by="sandbox-b"$`),
		regexp.MustCompile(`^LATENCY pass=1 peer=b kind=concurrent streams=2 rounds=2 n=4 wall_ms=[0-9.]+ min_ms=[0-9.]+ p50_ms=[0-9.]+ p90_ms=[0-9.]+ max_ms=[0-9.]+ mean_ms=[0-9.]+$`),
	} {
		if !lines.matches(want) {
			t.Errorf("no line matched %v; the console said:\n%s", want, lines.String())
		}
	}
	// One establishment, three warm exchanges and two rounds of two: every one
	// of them its own stream, opened through the contract.
	if got := box.opened.Load(); got != 8 {
		t.Errorf("the exercise opened %d streams; want 8", got)
	}
	if got := strings.Count(lines.String(), "the-marker"); got == 0 {
		t.Error("the marker the relay capture is searched for never went out")
	}
}

// TestTheExerciseStopsAskingForAPeerTheTableDoesNotHold is the one error the
// retry loop must not retry: a name no peer table holds will not appear by
// waiting, and the run configuration is wrong.
func TestTheExerciseStopsAskingForAPeerTheTableDoesNotHold(t *testing.T) {
	box := &loopbackSandbox{answerer: "sandbox-b"}
	var lines linesf
	e := exercise{Dial: []string{"nobody"}, Exchanges: 1}
	err := e.perform(context.Background(), box, newWatchedVerifier(nil, lines.logf), lines.logf)
	if err == nil {
		t.Fatal("the exercise passed against a peer that is not in the table")
	}
	if !strings.Contains(err.Error(), "unknown peer") {
		t.Errorf("the exercise failed with %v; want the unknown peer", err)
	}
	if got := box.opened.Load(); got != 0 {
		t.Errorf("%d streams were opened to a peer that does not exist", got)
	}
}

// TestTheRoundTripCarriesTheEndOfTheRequest is the half-close the exercise's
// protocol is made of: a peer that reads to end-of-file gets the request only
// because CloseWrite said it was finished.
func TestTheRoundTripCarriesTheEndOfTheRequest(t *testing.T) {
	s := &loopbackStream{answerer: "sandbox-b"}
	response, err := roundTrip(s, []byte("hello"))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if want := "sandbox-b:hello"; string(response) != want {
		t.Errorf("round trip returned %q; want %q", response, want)
	}
	if !s.ended {
		t.Error("the request was never ended; the peer would still be waiting for it")
	}
}

// loopbackSandbox is the contract with nothing behind it: every stream it opens
// answers itself. The exercise cannot tell the difference, which is the point —
// it holds a [sandbox.Sandbox] and knows nothing about tunnels.
type loopbackSandbox struct {
	answerer string
	opened   atomic.Int32
}

func (b *loopbackSandbox) Open(_ context.Context, peer string) (sandbox.Stream, error) {
	if peer != "b" {
		return nil, fmt.Errorf("%w: %q is not in the peer table", tunneld.ErrUnknownPeer, peer)
	}
	b.opened.Add(1)
	return &loopbackStream{answerer: b.answerer}, nil
}

func (b *loopbackSandbox) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	<-ctx.Done()
	return nil, sandbox.Attested{}, ctx.Err()
}

func (b *loopbackSandbox) Apply(context.Context, []byte) error { return nil }

// loopbackStream answers the request it was given once the writer says the
// request is complete, which is exactly the protocol echoStream runs.
type loopbackStream struct {
	answerer string
	request  bytes.Buffer
	response *bytes.Reader
	ended    bool
}

func (s *loopbackStream) Write(p []byte) (int, error) { return s.request.Write(p) }

func (s *loopbackStream) CloseWrite() error {
	s.ended = true
	s.response = bytes.NewReader([]byte(s.answerer + ":" + s.request.String()))
	return nil
}

func (s *loopbackStream) Read(p []byte) (int, error) {
	if s.response == nil {
		return 0, io.EOF
	}
	return s.response.Read(p)
}

func (s *loopbackStream) Close() error { return nil }

// linesf is a logf that keeps what it was told.
type linesf struct {
	mu    sync.Mutex
	lines []string
}

func (l *linesf) logf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
}

func (l *linesf) matches(re *regexp.Regexp) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func (l *linesf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
