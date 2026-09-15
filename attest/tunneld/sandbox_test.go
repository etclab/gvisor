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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The sandbox contract over the loopback harness (ticket 22,
// docs/sandbox-contract.md).
//
// These are the same two tunnelds every test in this package runs, with the
// fake platform injected through Config, driven through the contract instead of
// through Exchange: one sandbox opens a stream to a peer it has attested, the
// other accepts it and is told who opened it.

const (
	policyV1 = `{"format":"policy","version":1,"n":["one"],"f":["two"],"x":["three"]}`
	policyV2 = `{"format":"policy","version":2,"n":[],"f":[],"x":[]}`
)

func TestSandboxOpensAStreamToAnAttestedPeerAndAcceptsItWithItsIdentity(t *testing.T) {
	// B's peer table names A at an address it never dials. An accepted
	// connection arrives from an ephemeral source port, so the table can only
	// be matched on the address, and this is the case where exactly one entry
	// does match.
	b := start(t, "sandbox-b", imageB, admitting(imageA), tunneld.PeerTable{"a": "127.0.0.1:65535"})
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})

	boxA := sandbox.NewNull(a.Tunneld, nil)
	boxB := sandbox.NewNull(b.Tunneld, nil)

	type accepted struct {
		request string
		who     sandbox.Attested
		err     error
	}
	answered := make(chan accepted, 1)
	go func() {
		stream, who, err := boxB.Accept(ctx(t))
		if err != nil {
			answered <- accepted{err: err}
			return
		}
		defer stream.Close()
		request, err := io.ReadAll(stream)
		if err != nil {
			answered <- accepted{err: err}
			return
		}
		if _, err := stream.Write([]byte("sandbox-b:" + string(request))); err != nil {
			answered <- accepted{err: err}
			return
		}
		answered <- accepted{request: string(request), who: who, err: stream.CloseWrite()}
	}()

	stream, err := boxA.Open(ctx(t), "b")
	if err != nil {
		t.Fatalf("opening a stream to b: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("ending the request: %v", err)
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if want := "sandbox-b:hello"; string(response) != want {
		t.Errorf("the peer answered %q; want %q", response, want)
	}

	got := <-answered
	if got.err != nil {
		t.Fatalf("the accepting sandbox: %v", got.err)
	}
	if got.request != "hello" {
		t.Errorf("the accepting sandbox read %q; want %q", got.request, "hello")
	}
	want := sandbox.Attested{
		Peer:         "a",
		Vendor:       string(attest.VendorAMDSEVSNP),
		Measurement:  hex.EncodeToString(imageA),
		PolicyDigest: policyDigestOf(t, everyImage()).String(),
	}
	if got.who != want {
		t.Errorf("the accepted stream carried\n %+v\nwant\n %+v", got.who, want)
	}

	// And the framing the contract did not replace: an exchange on the same
	// tunnel still reaches the handler, because a raw stream and an exchange
	// are told apart by the four bytes they open with and by nothing else.
	channel, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer channel.Close()
	echoed, err := channel.Exchange(ctx(t), []byte("still framed"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if want := "sandbox-b:still framed"; string(echoed) != want {
		t.Errorf("exchange returned %q; want %q", echoed, want)
	}
	if b.served.Load() != 1 {
		t.Errorf("b's handler answered %d exchanges; want 1 — a stream must not reach it", b.served.Load())
	}
}

func TestAnAmbiguousPeerTableNamesNobody(t *testing.T) {
	// Two entries on this address and no way to tell which peer opened the
	// stream: a name that might be either is worse than no name.
	c := start(t, "sandbox-c", imageB, admitting(imageA), tunneld.PeerTable{
		"x": "127.0.0.1:65534", "y": "127.0.0.1:65535",
	})
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"c": c.Addr().String()})

	who := make(chan sandbox.Attested, 1)
	go func() {
		stream, attested, err := sandbox.NewNull(c.Tunneld, nil).Accept(ctx(t))
		if err != nil {
			t.Errorf("accepting: %v", err)
			who <- sandbox.Attested{}
			return
		}
		stream.Close()
		who <- attested
	}()

	stream, err := sandbox.NewNull(a.Tunneld, nil).Open(ctx(t), "c")
	if err != nil {
		t.Fatalf("opening a stream to c: %v", err)
	}
	defer stream.Close()

	got := <-who
	if got.Peer != "" {
		t.Errorf("the accepted stream was named %q; want no name", got.Peer)
	}
	if got.Measurement != hex.EncodeToString(imageA) {
		t.Errorf("the accepted stream's measurement is %q; want a's image", got.Measurement)
	}
}

func TestAcceptIsReleasedWhenTheTunneldCloses(t *testing.T) {
	a := start(t, "sandbox-a", imageA, admitting(imageB), nil)
	released := make(chan error, 1)
	go func() {
		_, _, err := sandbox.NewNull(a.Tunneld, nil).Accept(ctx(t))
		released <- err
	}()
	a.Close()
	if err := <-released; !errors.Is(err, tunneld.ErrClosed) {
		t.Errorf("Accept returned %v after Close; want ErrClosed", err)
	}
	// And closing twice is not a panic, which is what the harness does next.
	a.Close()
}

// TestAChannelNoTunneldMadeRefusesRatherThanPanicking closes the gap spike E2
// recorded: Channel is exported and all its fields are not, so &Channel{}
// compiles, and calling Exchange on one used to dereference the tunneld it
// has not got.
func TestAChannelNoTunneldMadeRefusesRatherThanPanicking(t *testing.T) {
	manufactured := &tunneld.Channel{}
	if _, err := manufactured.Exchange(ctx(t), []byte("privileged")); !errors.Is(err, tunneld.ErrNoTunneld) {
		t.Errorf("Exchange on a manufactured channel returned %v; want ErrNoTunneld", err)
	}
	if _, err := manufactured.OpenStream(ctx(t)); !errors.Is(err, tunneld.ErrNoTunneld) {
		t.Errorf("OpenStream on a manufactured channel returned %v; want ErrNoTunneld", err)
	}
	if manufactured.Peer() != "" {
		t.Errorf("a manufactured channel is for peer %q; want none", manufactured.Peer())
	}
}

// TestTunneldChecksTheEnvelopeBeforeTheSandboxSeesThePolicy is where the
// version check lives: at the boundary, so that an acknowledgement means a
// sandbox with that policy on every implementation of the contract.
func TestTunneldChecksTheEnvelopeBeforeTheSandboxSeesThePolicy(t *testing.T) {
	null := sandbox.NewNull(nil, nil)
	box := tunneld.PolicyChecked(null)

	for _, refused := range []string{policyV2, `{"format":"not-a-policy","version":1}`, `not json at all`, ``} {
		if err := box.Apply(ctx(t), []byte(refused)); !errors.Is(err, sandbox.ErrPolicyRefused) {
			t.Errorf("pushing %q returned %v; want a refusal", refused, err)
		}
	}
	if applied := null.Applied(); len(applied) != 0 {
		t.Fatalf("the sandbox saw %d refused policies; want none", len(applied))
	}

	if err := box.Apply(ctx(t), []byte(policyV1)); err != nil {
		t.Fatalf("pushing a version 1 policy: %v", err)
	}
	applied := null.Applied()
	if len(applied) != 1 {
		t.Fatalf("the sandbox recorded %d policies; want 1", len(applied))
	}
	sum := sha256.Sum256([]byte(policyV1))
	want := sandbox.Record{
		Format:  sandbox.PolicyFormat,
		Version: sandbox.PolicyVersion,
		Bytes:   len(policyV1),
		SHA256:  hex.EncodeToString(sum[:]),
	}
	if applied[0] != want {
		t.Errorf("recorded %+v; want %+v", applied[0], want)
	}
}
