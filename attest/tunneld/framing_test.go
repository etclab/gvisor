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

package tunneld_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tunneld"
)

// An exchange occupies exactly one stream and ends at end-of-stream, and
// nothing may follow it there (CONTEXT.md, Exchange). These tests come at
// that from both sides: a peer whose evidence is admitted and whose
// establishment round trip is correct, but which lays bytes on a stream that
// package tunnel would never send; and legitimate callers running exchanges
// at the same time on one tunnel.
//
// The framing cases have to be written by hand at the QUIC layer, because the
// only way to present a misframed exchange is to be a peer that does not use
// the framing code. They reuse hostileDial, which is how ticket 09 built an
// attested peer that then misbehaves.

// framed is one exchange frame: a four-byte big-endian payload length, and
// the payload.
func framed(payload string) []byte {
	return append(lengthPrefix(uint32(len(payload))), payload...)
}

// lengthPrefix is a frame header on its own, for the cases where the payload
// that follows is not the one it declares.
func lengthPrefix(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// readFramed reads one frame back the way package tunnel does, so that a
// control case can assert what the listener answered — and so that a response
// with trailing bytes of its own would be caught here rather than ignored.
func readFramed(t *testing.T, s *quic.Stream) []byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		t.Fatalf("reading the response header: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(s, payload); err != nil {
		t.Fatalf("reading a %d byte response payload: %v", len(payload), err)
	}
	if n, err := io.ReadFull(s, make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the listener sent %d bytes after its response frame (%v)", n, err)
	}
	return payload
}

// establishedPeer completes a handshake and the establishment round trip with
// the tunneld at addr, then hands the raw connection to use. Everything after
// establishment is the test's to frame, or to misframe, by hand.
func establishedPeer(t *testing.T, addr string, admits attest.ReferenceValueSet, use func(*quic.Conn)) {
	t.Helper()
	hostileDial(t, addr, admits, func(c *quic.Conn) {
		s, err := c.OpenStreamSync(ctx(t))
		if err != nil {
			t.Fatalf("opening the establishment stream: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("closing the establishment stream: %v", err)
		}
		reply, err := io.ReadAll(s)
		if err != nil {
			t.Fatalf("reading the establishment reply: %v", err)
		}
		if len(reply) != 0 {
			t.Fatalf("the establishment reply carried %d bytes", len(reply))
		}
		use(c)
	})
}

// startWith runs a tunneld the way start does, but with a handler the test
// chooses. The exchange count is kept the same way, so served means the same
// thing here as it does there.
func startWith(t *testing.T, sandbox string, image []byte, admits attest.ReferenceValueSet, peers tunneld.PeerTable, handler tunneld.Handler) *node {
	t.Helper()
	p := platform(t, image)
	n := &node{}
	counted := handler
	if handler != nil {
		counted = func(ctx context.Context, request []byte) ([]byte, error) {
			n.served.Add(1)
			return handler(ctx, request)
		}
	}
	td, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             sandbox,
		Acquirer:              p,
		Verifier:              verifierFor(t, p),
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		AuthorPublicKey:       authorPub,
		Peers:                 peers,
		ListenAddr:            "127.0.0.1:0",
		Handler:               counted,
	})
	if err != nil {
		t.Fatalf("tunneld.New(%s): %v", sandbox, err)
	}
	n.Tunneld = td
	t.Cleanup(func() { td.Close() })
	return n
}

// TestOneStreamCarriesOneExchange is the security property in this ticket. A
// stream is a byte stream: a sender that puts a second frame behind the first
// is offering the receiver a second message inside one exchange's payload,
// and a receiver that reads on past the frame it was promised has accepted
// it. Each case here is refused outright — no handler runs, and the
// connection that carried it ends.
func TestOneStreamCarriesOneExchange(t *testing.T) {
	cases := map[string][]byte{
		"a second frame behind the first": append(framed("first"), framed("second")...),
		"trailing bytes after the frame":  append(framed("first"), []byte("junk")...),
		"a payload shorter than declared": append(lengthPrefix(64), []byte("short")...),
		"a length past the maximum":       lengthPrefix(math.MaxUint32),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			admits := admitting(imageA)
			listener := start(t, "listener", imageA, admits, nil)
			establishedPeer(t, listener.Addr().String(), admits, func(c *quic.Conn) {
				s, err := c.OpenStreamSync(ctx(t))
				if err != nil {
					t.Fatalf("opening an exchange stream: %v", err)
				}
				if _, err := s.Write(wire); err != nil {
					t.Fatalf("writing the misframed exchange: %v", err)
				}
				// Close may find the connection already gone: the listener
				// can refuse as soon as it has read enough to know. Either
				// ordering is a refusal, which is what is being asserted.
				s.Close()
				select {
				case <-c.Context().Done():
				case <-ctx(t).Done():
					t.Error("the listener left the connection up after a framing violation")
				}
			})
			if n := listener.served.Load(); n != 0 {
				t.Errorf("the listener answered %d exchanges from a peer that broke the framing; want 0", n)
			}
		})
	}
}

// TestTwoStreamsCarryTwoExchanges is the control for the case above: the same
// two frames, one per stream, are two exchanges and both are answered. What
// the listener refuses is the stream layout, not the bytes.
func TestTwoStreamsCarryTwoExchanges(t *testing.T) {
	admits := admitting(imageA)
	listener := start(t, "listener", imageA, admits, nil)
	establishedPeer(t, listener.Addr().String(), admits, func(c *quic.Conn) {
		for _, request := range []string{"first", "second"} {
			s, err := c.OpenStreamSync(ctx(t))
			if err != nil {
				t.Fatalf("opening an exchange stream: %v", err)
			}
			if _, err := s.Write(framed(request)); err != nil {
				t.Fatalf("writing the exchange: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("finishing the exchange: %v", err)
			}
			if got, want := string(readFramed(t, s)), "listener:"+request; got != want {
				t.Errorf("exchange %q returned %q; want %q", request, got, want)
			}
		}
	})
	if n := listener.served.Load(); n != 2 {
		t.Errorf("the listener answered %d exchanges on two streams; want 2", n)
	}
}

// TestAFrameArrivingInPiecesIsReadToEndOfStream sends one frame as four
// writes. A receiver that answered whatever the first read handed it would
// answer a truncated request, or none.
func TestAFrameArrivingInPiecesIsReadToEndOfStream(t *testing.T) {
	admits := admitting(imageA)
	listener := start(t, "listener", imageA, admits, nil)
	const request = "a request that arrives in pieces"
	establishedPeer(t, listener.Addr().String(), admits, func(c *quic.Conn) {
		s, err := c.OpenStreamSync(ctx(t))
		if err != nil {
			t.Fatalf("opening an exchange stream: %v", err)
		}
		wire := framed(request)
		// The first piece stops inside the header, the second straddles it.
		for _, piece := range [][]byte{wire[:2], wire[2:7], wire[7:20], wire[20:]} {
			if _, err := s.Write(piece); err != nil {
				t.Fatalf("writing a piece of the exchange: %v", err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("finishing the exchange: %v", err)
		}
		if got, want := string(readFramed(t, s)), "listener:"+request; got != want {
			t.Errorf("exchange returned %q; want %q", got, want)
		}
	})
	if n := listener.served.Load(); n != 1 {
		t.Errorf("the listener answered %d exchanges; want 1", n)
	}
}

// TestALargeExchangeRoundTripsWhole crosses enough packets that both ends
// have to reassemble, in both directions, and asserts the bytes rather than
// the length.
func TestALargeExchangeRoundTripsWhole(t *testing.T) {
	b := start(t, "sandbox-b", imageB, admitting(imageA), nil)
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})
	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()

	request := make([]byte, 512<<10)
	if _, err := rand.Read(request); err != nil {
		t.Fatal(err)
	}
	got, err := ch.Exchange(ctx(t), request)
	if err != nil {
		t.Fatalf("exchange of %d bytes: %v", len(request), err)
	}
	if want := append([]byte("sandbox-b:"), request...); !bytes.Equal(got, want) {
		t.Errorf("a %d byte exchange came back as %d bytes and did not match", len(want), len(got))
	}
}

// headOfLineGuard only has to be longer than a local round trip can plausibly
// take on a loaded machine; the failure it catches is a wait with no end.
const headOfLineGuard = 30 * time.Second

// TestASlowExchangeDoesNotBlockAnother pins the reason the transport is QUIC.
// One exchange is held inside its handler and cannot finish until this test
// says so; a second exchange on the same tunnel has to complete first. The
// ordering is what is asserted, not a duration: if the tunnel head-of-line
// blocked, the second exchange could only finish after the first was
// released, which never happens here.
func TestASlowExchangeDoesNotBlockAnother(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	responder := startWith(t, "responder", imageA, admitting(imageA), nil,
		func(_ context.Context, request []byte) ([]byte, error) {
			if string(request) == "slow" {
				close(entered)
				<-release
				return []byte("slow answered"), nil
			}
			return []byte("fast answered"), nil
		})
	dialer := startWith(t, "dialer", imageA, admitting(imageA),
		tunneld.PeerTable{"responder": responder.Addr().String()}, nil)

	ch, err := dialer.Peer(ctx(t), "responder")
	if err != nil {
		t.Fatalf("dialer.Peer(responder): %v", err)
	}
	defer ch.Close()

	type outcome struct {
		got []byte
		err error
	}
	slow := make(chan outcome, 1)
	go func() {
		got, err := ch.Exchange(context.Background(), []byte("slow"))
		slow <- outcome{got, err}
	}()
	<-entered // The slow handler is running and will not return until released.

	fast := make(chan outcome, 1)
	go func() {
		got, err := ch.Exchange(context.Background(), []byte("fast"))
		fast <- outcome{got, err}
	}()
	select {
	case r := <-fast:
		if r.err != nil {
			t.Fatalf("the second exchange failed: %v", r.err)
		}
		if got, want := string(r.got), "fast answered"; got != want {
			t.Errorf("the second exchange returned %q; want %q", got, want)
		}
	case <-time.After(headOfLineGuard):
		close(release)
		t.Fatal("a second exchange never completed while the first was held in its handler: the tunnel head-of-line blocks")
	}

	close(release)
	if r := <-slow; r.err != nil {
		t.Errorf("the held exchange failed: %v", r.err)
	} else if got, want := string(r.got), "slow answered"; got != want {
		t.Errorf("the held exchange returned %q; want %q", got, want)
	}
}

// TestConcurrentExchangesEachReturnTheirOwnResponse is the control the
// head-of-line test needs: exchanges running at once on one tunnel not only
// all succeed, they come back to the caller that asked. A concurrency test
// that checked only for errors would pass with every response swapped.
func TestConcurrentExchangesEachReturnTheirOwnResponse(t *testing.T) {
	const exchanges = 32
	b := start(t, "sandbox-b", imageB, admitting(imageA), nil)
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})
	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()

	c := ctx(t)
	got := make([][]byte, exchanges)
	errs := make([]error, exchanges)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := range exchanges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release // Start together, so the exchanges genuinely overlap.
			got[i], errs[i] = ch.Exchange(c, fmt.Appendf(nil, "request-%02d", i))
		}()
	}
	close(release)
	wg.Wait()

	for i := range exchanges {
		if errs[i] != nil {
			t.Errorf("exchange %d: %v", i, errs[i])
			continue
		}
		if want := fmt.Sprintf("sandbox-b:request-%02d", i); string(got[i]) != want {
			t.Errorf("exchange %d returned %q; want %q — a response reached the wrong caller", i, got[i], want)
		}
	}
	if n := b.served.Load(); n != exchanges {
		t.Errorf("the peer answered %d exchanges; want %d", n, exchanges)
	}
}
