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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/internal/fixture"
	"gvisor.dev/gvisor/attest/internal/snpfake"
	"gvisor.dev/gvisor/attest/tunneld"
)

// Every test here drives tunneld's public API with the fake platform injected
// through Config. Verification and reference value handling are covered at
// the attest seam and are not re-tested; what is asserted is external
// behaviour: a channel or an error, an exchange completed or not.

var (
	imageA    = bytes.Repeat([]byte{0x11}, 48)
	imageB    = bytes.Repeat([]byte{0x22}, 48)
	imageNone = bytes.Repeat([]byte{0x33}, 48)
)

var (
	platformTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	launched    = attest.GuestPolicy{AllowSMT: true}
	permitted   = attest.GuestPolicy{AllowSMT: true}
)

// author is the reference value author for the whole test binary.
var authorPub, authorPriv, _ = ed25519.GenerateKey(rand.Reader)

// platform is a fake platform running one image at the TCB and under the guest
// policy these tests treat as the ordinary ones.
func platform(t *testing.T, measurement []byte) *snpfake.Platform {
	t.Helper()
	return platformUnder(t, measurement, platformTCB, launched)
}

// platformUnder is [platform] with all three stated, for a refusal that is
// about one of them.
func platformUnder(t *testing.T, measurement []byte, tcb attest.TCB, policy attest.GuestPolicy) *snpfake.Platform {
	t.Helper()
	return fixture.SNPPlatform(t, snpfake.Config{LaunchMeasurement: measurement, TCB: tcb, Policy: policy})
}

func admitting(measurements ...[]byte) attest.ReferenceValueSet {
	var set attest.ReferenceValueSet
	for _, m := range measurements {
		set.Values = append(set.Values, attest.ReferenceValue{
			LaunchMeasurement: m,
			MinimumTCB:        platformTCB,
			GuestPolicy:       permitted,
		})
	}
	return set
}

// somePolicyDigest is the digest a test peer presents, minted from its name.
//
// Since ticket 22 that is all a digest is to the code under test: a number its
// caller gives it, which the measured guest's command takes from the egress
// ceiling compiled into its image and a test takes from here. These tests wrote
// and hashed a policy document for it until then, because the tunneld loaded
// one off its config device and presented what it found.
//
// Every set these tests write lists no policy_digest on any value, so every
// entry admits any policy and the number here decides nothing. What matters is
// that the peer presents one at all, which every peer speaking binding context
// v2 must. The tests that are about the digest name their own.
func somePolicyDigest(who string) attest.PolicyDigest {
	return sha256.Sum256([]byte("a test peer's policy: " + who))
}

// writeSet writes a signed reference value set and returns the document path.
func writeSet(t *testing.T, set attest.ReferenceValueSet, key ed25519.PrivateKey) string {
	t.Helper()
	doc, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	sig, err := attest.SignReferenceValueSet(doc, key)
	if err != nil {
		t.Fatalf("sign set: %v", err)
	}
	path := filepath.Join(t.TempDir(), "reference-values.json")
	fixture.WriteSigned(t, path, doc, sig)
	return path
}

// node is one tunneld under test.
type node struct {
	*tunneld.Tunneld
	served atomic.Int32 // exchanges the handler answered
}

func echo(prefix string, n *node) tunneld.Handler {
	return func(_ context.Context, request []byte) ([]byte, error) {
		n.served.Add(1)
		return append([]byte(prefix), request...), nil
	}
}

// start runs a tunneld on an ephemeral port: its platform measures image,
// its set admits admits, and it knows peers.
func start(t *testing.T, sandbox string, image []byte, admits attest.ReferenceValueSet, peers tunneld.PeerTable) *node {
	t.Helper()
	p := platform(t, image)
	n := &node{}
	td, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             sandbox,
		Acquirer:              p,
		Verifier:              fixture.VerifierTrusting(t, p),
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		PolicyDigest:          somePolicyDigest(sandbox),
		AuthorPublicKey:       authorPub,
		Peers:                 peers,
		ListenAddr:            "127.0.0.1:0",
		Handler:               echo(sandbox+":", n),
	})
	if err != nil {
		t.Fatalf("tunneld.New(%s): %v", sandbox, err)
	}
	n.Tunneld = td
	t.Cleanup(func() { td.Close() })
	return n
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestExchangeCompletesOverMutuallyAttestedTunnel(t *testing.T) {
	b := start(t, "sandbox-b", imageB, admitting(imageA), nil)
	a := start(t, "sandbox-a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})

	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	if ch.Peer() != "b" {
		t.Errorf("channel is for %q; want b", ch.Peer())
	}
	got, err := ch.Exchange(ctx(t), []byte("hello"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if want := "sandbox-b:hello"; string(got) != want {
		t.Errorf("exchange returned %q; want %q", got, want)
	}
	if b.served.Load() != 1 {
		t.Errorf("b answered %d exchanges; want 1", b.served.Load())
	}
}

func TestSetAdmittingSeveralImagesAdmitsEach(t *testing.T) {
	// A rollout: a's set admits both the old and the new image, and peers on
	// each are reachable.
	old := start(t, "old", imageA, admitting(imageB), nil)
	new := start(t, "new", imageNone, admitting(imageB), nil)
	a := start(t, "a", imageB, admitting(imageA, imageNone), tunneld.PeerTable{
		"old": old.Addr().String(), "new": new.Addr().String(),
	})
	for _, name := range []string{"old", "new"} {
		ch, err := a.Peer(ctx(t), name)
		if err != nil {
			t.Fatalf("a.Peer(%s): %v", name, err)
		}
		if _, err := ch.Exchange(ctx(t), []byte("x")); err != nil {
			t.Errorf("exchange with %s: %v", name, err)
		}
		ch.Close()
	}
}

func TestUnknownPeerNameYieldsNoChannel(t *testing.T) {
	a := start(t, "a", imageA, admitting(imageB), tunneld.PeerTable{})
	ch, err := a.Peer(ctx(t), "nobody")
	if !errors.Is(err, tunneld.ErrUnknownPeer) {
		t.Fatalf("Peer(nobody) = %v, %v; want ErrUnknownPeer", ch, err)
	}
}

func TestListenerRefusesDialerItsSetDoesNotAdmit(t *testing.T) {
	// b admits only imageNone; a runs imageA. b must abort the handshake, and
	// a gets no channel even though a itself would accept b.
	b := start(t, "b", imageB, admitting(imageNone), nil)
	a := start(t, "a", imageA, admitting(imageB), tunneld.PeerTable{"b": b.Addr().String()})

	ch, err := a.Peer(ctx(t), "b")
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Fatalf("Peer(b) = %v, %v; want ErrNotEstablished", ch, err)
	}
	if b.served.Load() != 0 {
		t.Errorf("b answered %d exchanges over a refused tunnel", b.served.Load())
	}
}

func TestDialerRefusesListenerItsSetDoesNotAdmit(t *testing.T) {
	// The mirror image: b would accept a, but a's set does not admit b.
	b := start(t, "b", imageB, admitting(imageA), nil)
	a := start(t, "a", imageA, admitting(imageNone), tunneld.PeerTable{"b": b.Addr().String()})

	ch, err := a.Peer(ctx(t), "b")
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Fatalf("Peer(b) = %v, %v; want ErrNotEstablished", ch, err)
	}
	if b.served.Load() != 0 {
		t.Errorf("b answered %d exchanges over a refused tunnel", b.served.Load())
	}
}

// evidenceless is a platform that presents nothing.
type evidenceless struct{ attest.Acquirer }

func (evidenceless) Acquire(context.Context, [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	return attest.Evidence{}, nil
}

func TestPeerPresentingNoEvidenceIsRefused(t *testing.T) {
	b := start(t, "b", imageB, admitting(imageA), nil)
	p := platform(t, imageA)
	a, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             "a",
		Acquirer:              evidenceless{p},
		Verifier:              fixture.VerifierTrusting(t, p),
		ReferenceValueSetPath: writeSet(t, admitting(imageB), authorPriv),
		PolicyDigest:          somePolicyDigest("a"),
		AuthorPublicKey:       authorPub,
		Peers:                 tunneld.PeerTable{"b": b.Addr().String()},
		ListenAddr:            "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("tunneld.New: %v", err)
	}
	defer a.Close()
	ch, err := a.Peer(ctx(t), "b")
	if !errors.Is(err, tunneld.ErrNotEstablished) {
		t.Fatalf("Peer(b) = %v, %v; want ErrNotEstablished", ch, err)
	}
	if b.served.Load() != 0 {
		t.Errorf("b answered %d exchanges from a peer without evidence", b.served.Load())
	}
}

// TestRefusesToStartWithoutAnAcceptedSet: a tunneld loads one signed document
// and there is no path that starts without it.
//
// It loaded two until ticket 22 — its set and its own policy — and the two
// failures kept separate sentinels so that a caller asking why a guest will not
// boot did not have to read the text to learn which file to fix. The policy is
// not on the config device any more and there is one document left, so
// [attest.ErrSetRefused] is the whole of the answer.
func TestRefusesToStartWithoutAnAcceptedSet(t *testing.T) {
	p := platform(t, imageA)
	base := tunneld.Config{
		SandboxID:             "a",
		Acquirer:              p,
		Verifier:              fixture.VerifierTrusting(t, p),
		AuthorPublicKey:       authorPub,
		ListenAddr:            "127.0.0.1:0",
		ReferenceValueSetPath: writeSet(t, admitting(imageB), authorPriv),
		PolicyDigest:          somePolicyDigest("a"),
	}
	_, otherAuthor, _ := ed25519.GenerateKey(rand.Reader)

	for name, path := range map[string]string{
		"missing":           filepath.Join(t.TempDir(), "absent.json"),
		"signed by another": writeSet(t, admitting(imageB), otherAuthor),
	} {
		cfg := base
		cfg.ReferenceValueSetPath = path
		td, err := tunneld.New(context.Background(), cfg)
		if !errors.Is(err, attest.ErrSetRefused) {
			if td != nil {
				td.Close()
			}
			t.Errorf("%s set: New = %v, %v; want ErrSetRefused", name, td, err)
		}
	}

	// Control: the same configuration with the set accepted starts, and
	// presents the digest it was given.
	td, err := tunneld.New(context.Background(), base)
	if err != nil {
		t.Fatalf("control: New with an accepted set: %v", err)
	}
	defer td.Close()
	if got, want := td.PolicyDigest(), somePolicyDigest("a"); got != want {
		t.Errorf("the tunneld presents policy %s; it was given %s", got, want)
	}
}
