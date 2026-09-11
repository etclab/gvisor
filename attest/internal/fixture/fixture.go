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

// Package fixture is what this module's tests are built out of: a fake
// platform, a verifier that trusts it, a reference value author, and the
// control every refusal test is paired with.
//
// Four test packages need these — gvisor.dev/gvisor/attest and its provision,
// tsm and tunneld packages — and a helper declared in one package's _test.go
// files is not reachable from another's, so this is a normal package rather
// than a test file. It sits under internal/ beside the two fake platforms for
// the reason they do: nothing outside this module may build on it, and only a
// test binary has any use for it. cmd/tunneld's import-graph and
// packaged-binary tests name it alongside the fakes, so the measured binary
// cannot acquire it by accident.
//
// What is here is builders: things that either produce what a test starts from
// or stop the test saying why they could not. What a test asserts stays in the
// test. The one judgement here is [MustAccept], and it is the control rather
// than the assertion — that legitimate evidence is still accepted on this
// wiring, which every refusal test in every package was already writing for
// itself.
//
// A test whose subject is one of these things does not use the builder for it.
// The recorded-run loaders, the stand-in that judges a binding this verifier no
// longer admits, and the in-memory loaders that reach names only the root
// package's own tests can see all stay where they are used.
package fixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/internal/snpfake"
	"gvisor.dev/gvisor/attest/verify"
)

// ChainCreatedAt is when a fake platform's certificate chain is created, and
// WhenChainsAreValid an instant at which it is valid. Both are fixed so that a
// test's outcome does not depend on the day it runs.
var (
	ChainCreatedAt     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	WhenChainsAreValid = ChainCreatedAt.Add(30 * 24 * time.Hour)
)

// ChipID identifies the chip a fake platform reports where the test is about
// the chain provisioned for a chip rather than about an image.
var ChipID = bytes.Repeat([]byte{0x5A}, 64)

// SNPPlatform builds a fake SEV-SNP platform, with the chain creation time
// fixed at [ChainCreatedAt] unless the caller named one of its own.
func SNPPlatform(t *testing.T, cfg snpfake.Config) *snpfake.Platform {
	t.Helper()
	if cfg.Now.IsZero() {
		cfg.Now = ChainCreatedAt
	}
	p, err := snpfake.New(cfg)
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	return p
}

// SNPPlatformAtTCB is a fake platform a test knows by its chip rather than by
// its image: [ChipID], at the TCB the caller names. The acquisition and
// provisioning tests are about the chain a chip is entitled to, so the launch
// measurement is left to the fake and the guest policy is one that exists.
func SNPPlatformAtTCB(t *testing.T, tcb attest.TCB) *snpfake.Platform {
	t.Helper()
	return SNPPlatform(t, snpfake.Config{TCB: tcb, ChipID: ChipID, Policy: attest.GuestPolicy{AllowSMT: true}})
}

// VerifierTrusting returns a verifier configured with a fake platform's vendor
// root, as a tunneld is configured with the root provisioned onto its config
// device, judging certificate validity at [WhenChainsAreValid].
func VerifierTrusting(t *testing.T, p *snpfake.Platform) attest.Verifier {
	t.Helper()
	v, err := verify.New(verify.Options{
		VendorRootPEM: p.VendorRootPEM(),
		ProductLine:   p.ProductLine(),
		Now:           WhenChainsAreValid,
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
}

// TDXVerifier builds a TDX verifier from opts.
//
// Whose collateral and whose root those name is the caller's to say, and is the
// only thing that differs between a verifier over the recorded Intel collateral
// and one over a fake platform's generated collateral: an empty VendorRootPEM
// means the Intel root embedded in go-tdx-guest, which is what makes an
// acceptance over the recordings say they chain to Intel's own root.
func TDXVerifier(t *testing.T, opts verify.TDXOptions) *verify.TDX {
	t.Helper()
	v, err := verify.NewTDX(opts)
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	return v
}

// Verification wires a verifier to a reference value set, which is where a set
// that could not mean what its author intended is refused.
func Verification(t *testing.T, v attest.Verifier, set attest.ReferenceValueSet) *attest.Verification {
	t.Helper()
	wired, err := attest.New(v, set)
	if err != nil {
		t.Fatalf("attest.New: %v", err)
	}
	return wired
}

// AcquireZero asks a platform for evidence over caller-supplied bytes nothing
// else in the test depends on. A test that is about the binding builds its own.
func AcquireZero(t *testing.T, a attest.Acquirer) attest.Evidence {
	t.Helper()
	ev, err := a.Acquire(context.Background(), [attest.CallerSuppliedBytesSize]byte{})
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	return ev
}

// A judge is what [MustAccept] drives, in the two spellings this module has for
// it: an [attest.Verifier], which holds evidence against a reference value set,
// and an [attest.Verification] — or a test's own stand-in for one — which holds
// it against a binding. Nothing else differs between them, so the control is
// written once, over what the evidence is held against.
type judge[Against any] interface {
	Verify(ctx context.Context, ev attest.Evidence, against Against) (attest.Attested, error)
}

// MustAccept is the control every refusal test is paired with: on this wiring,
// legitimate evidence is still accepted. It returns the verdict, so that a test
// can go on to assert on what was attested.
func MustAccept[Against any](t *testing.T, v judge[Against], ev attest.Evidence, against Against) attest.Attested {
	t.Helper()
	attested, err := v.Verify(context.Background(), ev, against)
	if err != nil {
		t.Fatalf("evidence that should have been accepted was refused: %s", Detail(err))
	}
	return attested
}

// Detail returns the operator-facing text behind a refusal, for test output
// only. A caller in production reads this from the log, never from an error.
func Detail(err error) string {
	var r *attest.Refusal
	if errors.As(err, &r) {
		return r.LogString()
	}
	return err.Error()
}

// An Author is a reference value author: the key pair whose public half a
// measured image carries and whose private half authorises the two documents
// that image loads.
type Author struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// NewAuthor generates an author's key pair.
func NewAuthor(t *testing.T) Author {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a reference value author key: %v", err)
	}
	return Author{Public: pub, Private: priv}
}

// Sign authorises a reference value set, returning the contents of the
// signature file that belongs beside it.
func (a Author) Sign(t *testing.T, document string) []byte {
	t.Helper()
	return a.authorise(t, document, attest.SignReferenceValueSet)
}

// SignPolicy authorises a policy, returning the same.
func (a Author) SignPolicy(t *testing.T, document string) []byte {
	t.Helper()
	return a.authorise(t, document, attest.SignPolicy)
}

// authorise is what both of those are: this author's key over the document's
// bytes, through whichever of the module's two signers the document is for.
func (a Author) authorise(t *testing.T, document string, sign func([]byte, ed25519.PrivateKey) ([]byte, error)) []byte {
	t.Helper()
	signature, err := sign([]byte(document), a.Private)
	if err != nil {
		t.Fatalf("signing a document: %v", err)
	}
	return signature
}

// WriteFile writes one of the files a config device carries, read-only,
// because what a guest finds there is not the guest's to change.
func WriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o444); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// WriteSigned writes a document and the signature file that belongs beside it,
// which is the pair every loader in this module reads.
func WriteSigned(t *testing.T, path string, document, signature []byte) {
	t.Helper()
	WriteFile(t, path, document)
	WriteFile(t, path+attest.SignatureFileSuffix, signature)
}
