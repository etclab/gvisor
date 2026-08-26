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

// The offline half of milestone 1 (ticket 05).
//
// Everything else in this package verifies evidence this package's own test
// signer minted. These tests verify a report that a physical AMD processor
// produced, against the AMD root certificates embedded in the verification
// library, using the reference value set that was authored and signed for that
// guest — and they do it with no confidential VM, no network and no hardware,
// because the artifacts of the run are in docs/snp/evidence/ticket05.
//
// They are not the proof. The proof is the recorded run in
// docs/snp/evidence/ticket05/verify-run.txt, because what milestone 1 asserts —
// that a live guest's evidence verifies outside it — needs a live guest, and a
// test replaying captured bytes cannot re-establish that. What these tests do
// is keep the conclusion from silently rotting: if a change to the verifier,
// the loader or the binding stopped accepting real silicon's evidence, or
// stopped refusing a substituted measurement, that would be found on the next
// `go test` rather than on the next time somebody books a machine.
//
// The whole procedure is docs/verification-on-hardware.md.
package attest_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/verify"
)

// hardwareDir holds one run of docs/snp/verify-on-hardware.sh: the evidence a
// live confidential guest produced, the key it is bound to, and the signed
// reference value set authored for that guest from a measurement predicted
// offline. The certificate chain is not copied here — it is the provisioned
// one beside it, which is the point of ADR-0005.
const (
	hardwareDir     = "../docs/snp/evidence/ticket05"
	provisionedDir  = "../docs/snp/evidence"
	provisionedName = "certificate-chain.bin"
)

// liveGuest is one captured run, loaded.
type liveGuest struct {
	evidence attest.Evidence
	binding  attest.Binding
	author   ed25519.PublicKey
}

// loadLiveGuest reads the captured run, or skips. It skips rather than fails
// because the artifacts are the record of a run on a particular machine, and a
// checkout without them is not a broken checkout.
func loadLiveGuest(t *testing.T) liveGuest {
	t.Helper()
	report, err := os.ReadFile(filepath.Join(hardwareDir, "evidence.bin"))
	if err != nil {
		t.Skipf("no evidence captured from a live guest: %v", err)
	}
	chain, err := os.ReadFile(filepath.Join(provisionedDir, provisionedName))
	if err != nil {
		t.Fatalf("evidence was captured without the chain provisioned for it: %v", err)
	}
	publicKey, err := os.ReadFile(filepath.Join(hardwareDir, "public-key.der"))
	if err != nil {
		t.Fatalf("evidence was captured without the key it is bound to: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(hardwareDir, "author.pub"))
	if err != nil {
		t.Fatalf("the reference value set was captured without its author's public key: %v", err)
	}
	author, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(author) != ed25519.PublicKeySize {
		t.Fatalf("author.pub is not a hexadecimal Ed25519 public key")
	}
	return liveGuest{
		evidence: attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: report, Chain: chain},
		binding:  attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1},
		author:   author,
	}
}

// against builds the verification a peer would run: the real SEV-SNP verifier
// with no root of its own — which means the AMD root certificates embedded in
// the library, the production path — and the named set loaded through the
// loader, signature first.
//
// verify.Options is left empty deliberately. Every other test in this package
// hands the verifier a test root, because test-signed evidence must not chain
// to AMD; here the whole point is that it does.
func (g liveGuest) against(t *testing.T, setName string) *attest.Verification {
	t.Helper()
	set, err := attest.LoadReferenceValueSetFile(filepath.Join(hardwareDir, setName), g.author)
	if err != nil {
		t.Fatalf("the captured reference value set was refused: %v", err)
	}
	verifier, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.New(verifier, set)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// accept is the control, and the milestone: this evidence, this set, accepted.
func (g liveGuest) accept(t *testing.T, v *attest.Verification) attest.Attested {
	t.Helper()
	attested, err := v.Verify(context.Background(), g.evidence, g.binding)
	if err != nil {
		t.Fatalf("a live confidential guest's evidence was refused: %s", detail(err))
	}
	return attested
}

// TestARealPlatformsEvidenceVerifiesAgainstAMDsRoot is milestone 1, replayed.
//
// The report came out of a physical AMD processor. Its signature is checked
// against AMD's own root, through the certificate chain provisioned for this
// chip ahead of use. The launch measurement it attests is the one a reference
// value author predicted offline from the firmware image, before this guest
// was asked for anything — so the acceptance is not the tautology of comparing
// a platform's report against what that platform last reported.
//
// Nothing here reaches the network, and the recorded run proves that is a
// property of the code rather than of the machine: the same verification runs
// in a namespace where the vendor cannot be resolved or reached at all.
func TestARealPlatformsEvidenceVerifiesAgainstAMDsRoot(t *testing.T) {
	g := loadLiveGuest(t)
	attested := g.accept(t, g.against(t, "reference-values.json"))

	// The measurement in the accepted verdict is the one the set named, which
	// is what says the set decided the outcome rather than merely accompanying
	// it.
	predicted := g.reference(t, "reference-values.json")
	if got := hex.EncodeToString(attested.Claims.LaunchMeasurement); got != predicted {
		t.Errorf("the platform attests measurement %s; the set names %s", got, predicted)
	}
	if attested.Vendor != attest.VendorAMDSEVSNP {
		t.Errorf("accepted as vendor %q", attested.Vendor)
	}

	// And the binding held: the caller-supplied bytes in a report signed by
	// AMD are the digest of the key the guest generated for it (ADR-0002).
	// This is the same arithmetic attest/tsm checks against the captured
	// bytes; what is new here is that the signature over them was checked.
	want := g.binding.CallerSuppliedBytes()
	if attested.Claims.CallerSuppliedBytes != want {
		t.Errorf("evidence carries %x; the presented key produces %x", attested.Claims.CallerSuppliedBytes, want)
	}
}

// TestSubstitutingALaunchMeasurementRefusesARealPlatformsEvidence is the
// refusal the milestone turns on, and its control.
//
// reference-values-mutated.json differs from the set beside it in one byte of
// one launch measurement and in nothing else — same floor, same policy, same
// author, and signed by that same author, so the loader accepts it and the
// only thing that can account for a different verdict is the measurement.
func TestSubstitutingALaunchMeasurementRefusesARealPlatformsEvidence(t *testing.T) {
	g := loadLiveGuest(t)

	// The control first: with the unmodified set this same evidence is
	// accepted, so the refusal below is evidence of a working check rather
	// than of a broken path.
	g.accept(t, g.against(t, "reference-values.json"))

	refuses(t, g.against(t, "reference-values-mutated.json"), g.evidence, g.binding, attest.ReasonMeasurementNotInSet)

	authored, mutated := g.reference(t, "reference-values.json"), g.reference(t, "reference-values-mutated.json")
	if authored == mutated {
		t.Fatal("the mutated set names the same launch measurement as the authored one")
	}
	if len(authored) != len(mutated) {
		t.Errorf("the mutated measurement is a different length (%d) from the authored one (%d); "+
			"the substitution is supposed to be of a value, not of a shape", len(mutated), len(authored))
	}
}

// TestARealPlatformsEvidenceWithoutItsProvisionedChainIsRefused: the chain is
// provisioned ahead of use and travels with the evidence (ADR-0005). Evidence
// arriving without one is refused, and — the part that matters — is not
// rescued by fetching the chain from the vendor.
//
// The assertion on the detail is the regression guard: were certificate
// fetching ever re-enabled, the refusal would come from the getter that
// refuses network access rather than from the absent chain, and the reason
// alone would not tell the two apart.
func TestARealPlatformsEvidenceWithoutItsProvisionedChainIsRefused(t *testing.T) {
	g := loadLiveGuest(t)
	v := g.against(t, "reference-values.json")
	g.accept(t, v)

	unprovisioned := g.evidence
	unprovisioned.Chain = nil
	refuses(t, v, unprovisioned, g.binding, attest.ReasonChainNotRooted)

	_, err := v.Verify(context.Background(), unprovisioned, g.binding)
	if strings.Contains(detail(err), "refusing to fetch") {
		t.Errorf("verification tried to fetch a certificate: %s", detail(err))
	}
}

// TestARealPlatformsEvidenceWithAStaleProvisionedChainIsRefused records what a
// stale chain actually does on real silicon, which is not what this design's
// documents say it does.
//
// certificate-chain-stale.bin is genuine: AMD's key distribution service issued
// it, for this same chip, at a TCB one microcode level below the one the
// platform now reports. That is exactly the artifact a host has after a
// firmware update it did not re-provision for.
//
// ADR-0005 and docs/provisioning-certificate-chain.md say such a chain surfaces
// at the peer as malformed evidence, because the library compares the reported
// TCB against the one the chain was issued for. It does not. The VCEK is
// derived from the chip secret *and* the TCB, so a chain for another TCB
// endorses a different key; the report's own signature fails under it, and the
// verdict is [attest.ReasonChainNotRooted] — decided before the coherence check
// that would have called it malformed ever runs. The refusal is still closed
// and still fetches nothing, but an operator told to look for "malformed
// evidence" will not see it. The place a stale chain is named as such is the
// local check in attest/provision, which is where it should be caught anyway.
func TestARealPlatformsEvidenceWithAStaleProvisionedChainIsRefused(t *testing.T) {
	g := loadLiveGuest(t)
	stale, err := os.ReadFile(filepath.Join(hardwareDir, "certificate-chain-stale.bin"))
	if err != nil {
		t.Skipf("no stale chain captured: %v", err)
	}
	v := g.against(t, "reference-values.json")
	g.accept(t, v)

	staled := g.evidence
	staled.Chain = stale
	refuses(t, v, staled, g.binding, attest.ReasonChainNotRooted)

	_, err = v.Verify(context.Background(), staled, g.binding)
	if strings.Contains(detail(err), "refusing to fetch") {
		t.Errorf("verification tried to fetch a certificate: %s", detail(err))
	}
}

// reference returns the one launch measurement the named captured set holds,
// as hexadecimal. Each captured set holds exactly one; a set that grew a
// second value would make the tests above ambiguous rather than wrong, so it
// is refused here.
func (g liveGuest) reference(t *testing.T, setName string) string {
	t.Helper()
	set, err := attest.LoadReferenceValueSetFile(filepath.Join(hardwareDir, setName), g.author)
	if err != nil {
		t.Fatalf("%s was refused: %v", setName, err)
	}
	if len(set.Values) != 1 {
		t.Fatalf("%s holds %d reference values; these tests are written for one", setName, len(set.Values))
	}
	return hex.EncodeToString(set.Values[0].LaunchMeasurement)
}
