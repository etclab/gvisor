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
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/tunneld"
)

// An attested peer is not a well-behaved one. These tests present a dialer
// whose evidence is admitted and whose handshake completes, and which then
// misbehaves on the establishment round trip — and assert that a legitimate
// peer arriving meanwhile is still served. Before the listener answered
// establishment off its accept path, the first held every later peer and the
// second killed the accept loop outright.

// hostileDial completes a handshake with the listener at addr, as a platform
// the listener's set admits, and hands the raw connection to misbehave.
func hostileDial(t *testing.T, addr string, admits attest.ReferenceValueSet, misbehave func(*quic.Conn)) {
	t.Helper()
	p := platform(t, imageA)
	identity, err := ratls.NewIdentity(ctx(t), p)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := attest.New(verifierFor(t, p), admits)
	if err != nil {
		t.Fatal(err)
	}
	c, err := quic.DialAddr(ctx(t), addr, identity.ClientConfig(verification), &quic.Config{})
	if err != nil {
		t.Fatalf("the hostile dialer's handshake should complete; it is attested: %v", err)
	}
	t.Cleanup(func() { c.CloseWithError(0, "") })
	misbehave(c)
}

func TestAPeerThatNeverEstablishesDoesNotHoldOthers(t *testing.T) {
	admits := admitting(imageA)
	listener := start(t, "listener", imageA, admits, nil)
	hostileDial(t, listener.Addr().String(), admits, func(*quic.Conn) {}) // handshake, then silence

	dialer := start(t, "dialer", imageA, admits, tunneld.PeerTable{"listener": listener.Addr().String()})
	ch, err := dialer.Peer(ctx(t), "listener")
	if err != nil {
		t.Fatalf("a legitimate peer was held behind a silent one: %v", err)
	}
	if _, err := ch.Exchange(ctx(t), []byte("hello")); err != nil {
		t.Fatal(err)
	}
}

func TestAPeerThatBreaksEstablishmentDoesNotStopAccepting(t *testing.T) {
	admits := admitting(imageA)
	listener := start(t, "listener", imageA, admits, nil)
	hostileDial(t, listener.Addr().String(), admits, func(c *quic.Conn) {
		s, err := c.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte("not empty")) // establishment must carry nothing
		s.Close()
		// Wait for the listener to reject the connection before the
		// legitimate peer dials, so the test exercises the accept loop
		// after the failure rather than concurrently with it.
		<-c.Context().Done()
	})

	dialer := start(t, "dialer", imageA, admits, tunneld.PeerTable{"listener": listener.Addr().String()})
	ch, err := dialer.Peer(ctx(t), "listener")
	if err != nil {
		t.Fatalf("the accept loop died on one bad peer: %v", err)
	}
	if _, err := ch.Exchange(ctx(t), []byte("hello")); err != nil {
		t.Fatal(err)
	}
}

// TestAnExchangeWaitsForTheEstablishmentRoundTrip: a dial does not report
// success, and no exchange reaches the wire, until the peer has answered the
// establishment round trip. The listener here is attested and completes the
// handshake, then never answers; if Dial skipped the round trip, the request
// frame would arrive at it. Removing establish() from Dial fails this test.
func TestAnExchangeWaitsForTheEstablishmentRoundTrip(t *testing.T) {
	admits := admitting(imageA)
	p := platform(t, imageA)
	identity, err := ratls.NewIdentity(ctx(t), p)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := attest.New(verifierFor(t, p), admits)
	if err != nil {
		t.Fatal(err)
	}
	silent, err := quic.ListenAddr("127.0.0.1:0", identity.ServerConfig(verification), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var dataFrames atomic.Int32
	go func() {
		for {
			c, err := silent.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					// Read what the dialer sent and never answer. The
					// establishment stream is empty; a request is not.
					if b, _ := io.ReadAll(s); len(b) > 0 {
						dataFrames.Add(1)
					}
				}
			}()
		}
	}()

	dialer := start(t, "dialer", imageA, admits, tunneld.PeerTable{"silent": silent.Addr().String()})
	short, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	began := time.Now()
	ch, err := dialer.Peer(short, "silent")
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		if ch != nil {
			ch.Close()
		}
		t.Fatalf("Peer(silent) = %v, %v; want ErrNotEstablished", ch, err)
	}
	// And it gave up at the caller's deadline, not at the idle timeout: the
	// establishment read must watch the context.
	if waited := time.Since(began); waited > 5*time.Second {
		t.Errorf("Peer(silent) took %v to give up on a 2s context", waited)
	}
	if n := dataFrames.Load(); n != 0 {
		t.Errorf("%d request frame(s) reached a peer that had not answered establishment", n)
	}
}
