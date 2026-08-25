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
	"testing"

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
