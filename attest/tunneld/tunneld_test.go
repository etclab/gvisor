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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/tunneld"
	"gvisor.dev/gvisor/attest/verify"
)

// Every test here drives tunneld's public API with the fake platform injected
// through Config. Verification and reference value handling are covered at
// the attest seam and are not re-tested; what is asserted is external
// behaviour: a channel or an error, an exchange completed or not.

var (
	chainCreatedAt     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	whenChainsAreValid = chainCreatedAt.Add(30 * 24 * time.Hour)
)

var (
	imageA    = bytes.Repeat([]byte{0x11}, 48)
	imageB    = bytes.Repeat([]byte{0x22}, 48)
	imageNone = bytes.Repeat([]byte{0x33}, 48)
)

var (
	platformTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	launched    = snpfake.Policy{SMT: true}
	permitted   = attest.GuestPolicy{AllowSMT: true}
)

// author is the reference value author for the whole test binary.
var authorPub, authorPriv, _ = ed25519.GenerateKey(rand.Reader)

func platform(t *testing.T, measurement []byte) *snpfake.Platform {
	t.Helper()
	p, err := snpfake.New(snpfake.Config{
		LaunchMeasurement: measurement,
		TCB:               platformTCB,
		Policy:            launched,
		Now:               chainCreatedAt,
	})
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	return p
}

// verifierFor trusts the fake vendor root. Every fake platform is signed
// under the same test root, so one verifier judges all of them.
func verifierFor(t *testing.T, p *snpfake.Platform) attest.Verifier {
	t.Helper()
	v, err := verify.New(verify.Options{
		VendorRootPEM: p.VendorRootPEM(),
		ProductLine:   p.ProductLine(),
		Now:           whenChainsAreValid,
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
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

// somePolicyDigest stands in for the digest of a peer's own signed policy, where
// a test builds a peer out of ratls directly instead of starting a tunneld to
// build one.
//
// Every set these tests write lists no policy_digest on any value, so every
// entry admits any policy and the number here decides nothing. What matters is
// that the peer presents one at all, which every peer speaking binding context
// v2 must. The tests that are about the digest name their own.
func somePolicyDigest(who string) attest.PolicyDigest {
	return sha256.Sum256([]byte("a test peer's policy: " + who))
}

// everyImage is what a test tunneld's own policy forwards to: all three images
// this package's fixtures use.
//
// forward_to is the dialing side's check and it is not what most of these tests
// are about, so the default policy says yes to every peer they can build and the
// verdicts stay the reference value set's. The tests that *are* about forward_to
// write their own policy.
func everyImage() [][]byte { return [][]byte{imageA, imageB, imageNone} }

// writePolicy writes a signed policy forwarding to the given images and returns
// the document path. It is the second document a tunneld loads, beside the set,
// and its digest is the identity that tunneld presents.
func writePolicy(t *testing.T, forwardTo [][]byte, key ed25519.PrivateKey) string {
	t.Helper()
	doc, err := attest.MarshalPolicy(attest.Policy{ForwardTo: forwardTo})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	sig, err := attest.SignPolicy(doc, key)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+attest.SignatureFileSuffix, sig, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// policyDigestOf is the digest a tunneld loading a policy forwarding to these
// images will present. It renders the document exactly as writePolicy does, so
// the two agree by construction.
func policyDigestOf(t *testing.T, forwardTo [][]byte) attest.PolicyDigest {
	t.Helper()
	doc, err := attest.MarshalPolicy(attest.Policy{ForwardTo: forwardTo})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return attest.PolicyDigestOf(doc)
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
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+attest.SignatureFileSuffix, sig, 0o644); err != nil {
		t.Fatal(err)
	}
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
		Verifier:              verifierFor(t, p),
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		PolicyPath:            writePolicy(t, everyImage(), authorPriv),
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
		Verifier:              verifierFor(t, p),
		ReferenceValueSetPath: writeSet(t, admitting(imageB), authorPriv),
		PolicyPath:            writePolicy(t, everyImage(), authorPriv),
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

// TestRefusesToStartWithoutAnAcceptedSetOrPolicy: a tunneld loads two signed
// documents and there is no path that starts without either.
//
// The two failures keep separate sentinels. A caller that asked why a guest will
// not boot should not have to read the text to learn which of the two files on
// the config device is the one to fix.
func TestRefusesToStartWithoutAnAcceptedSetOrPolicy(t *testing.T) {
	p := platform(t, imageA)
	base := tunneld.Config{
		SandboxID:             "a",
		Acquirer:              p,
		Verifier:              verifierFor(t, p),
		AuthorPublicKey:       authorPub,
		ListenAddr:            "127.0.0.1:0",
		ReferenceValueSetPath: writeSet(t, admitting(imageB), authorPriv),
		PolicyPath:            writePolicy(t, everyImage(), authorPriv),
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
	for name, path := range map[string]string{
		"missing":               filepath.Join(t.TempDir(), "absent.json"),
		"signed by another":     writePolicy(t, everyImage(), otherAuthor),
		"a reference value set": writeSet(t, admitting(imageB), authorPriv),
	} {
		cfg := base
		cfg.PolicyPath = path
		td, err := tunneld.New(context.Background(), cfg)
		if !errors.Is(err, attest.ErrPolicyRefused) {
			if td != nil {
				td.Close()
			}
			t.Errorf("%s policy: New = %v, %v; want ErrPolicyRefused", name, td, err)
		}
	}

	// Control: the same configuration with both documents accepted starts, and
	// presents the digest of the policy it loaded.
	td, err := tunneld.New(context.Background(), base)
	if err != nil {
		t.Fatalf("control: New with an accepted set and policy: %v", err)
	}
	defer td.Close()
	if got, want := td.PolicyDigest(), policyDigestOf(t, everyImage()); got != want {
		t.Errorf("the tunneld presents policy %s; its own document is %s", got, want)
	}
}
