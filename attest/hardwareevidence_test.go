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
	"encoding/hex"
	"encoding/json"
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
	// The recorded author.pub is not read. The recorded set is re-authored in
	// this process rather than loaded as delivered, for the reason reauthoredSet
	// gives, so the key that signed it has nothing left to verify.
	return liveGuest{
		evidence: attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: report, Chain: chain},
		binding:  attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1},
	}
}

// reauthoredSet reads a reference value set recorded beside captured evidence
// and re-authors it here: same values, tagged with the vendor the run was on,
// rendered by this package's own writer, signed with a key generated in the
// test, and put back through the loader.
//
// The recorded documents are version 1. They were authored and signed before
// the format carried a vendor on every value, and this loader now refuses that
// version rather than reading it as SEV-SNP. Re-signing them as they stand is
// not possible either: each run's reference value author key was generated for
// that run and is not in git. The recorded artifacts themselves are not
// touched — they are the record of a run on real hardware (tickets 05, 07, 08)
// and cannot be regenerated without booking the machine again.
//
// What survives is what these tests are about. The launch measurement, the TCB
// floor and the guest policy are the recorded ones — predicted and written down
// before the guest booted — and the set still reaches the verifier through the
// loader rather than being handed to it. What does not survive is the original
// author's signature over those bytes; that it held is recorded in the run
// itself, and no test replaying captured bytes could re-establish it.
func reauthoredSet(t *testing.T, path string) attest.ReferenceValueSet {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the recorded reference value set: %v", err)
	}
	var recorded struct {
		ReferenceValues []struct {
			LaunchMeasurement string `json:"launch_measurement"`
			MinimumTCB        struct {
				Bootloader uint8 `json:"bootloader"`
				TEE        uint8 `json:"tee"`
				SNP        uint8 `json:"snp"`
				Microcode  uint8 `json:"microcode"`
			} `json:"minimum_tcb"`
			GuestPolicy struct {
				ABIMajor            uint8 `json:"abi_major"`
				ABIMinor            uint8 `json:"abi_minor"`
				AllowSMT            bool  `json:"allow_smt"`
				AllowMigrationAgent bool  `json:"allow_migration_agent"`
				AllowDebug          bool  `json:"allow_debug"`
				RequireSingleSocket bool  `json:"require_single_socket"`
			} `json:"guest_policy"`
		} `json:"reference_values"`
	}
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatalf("%s is not a reference value set document: %v", path, err)
	}
	set := attest.ReferenceValueSet{}
	for _, v := range recorded.ReferenceValues {
		measurement, err := hex.DecodeString(v.LaunchMeasurement)
		if err != nil {
			t.Fatalf("%s names a launch measurement that is not hexadecimal: %v", path, err)
		}
		set.Values = append(set.Values, attest.ReferenceValue{
			Vendor:            attest.VendorAMDSEVSNP,
			LaunchMeasurement: measurement,
			MinimumTCB: attest.TCB{
				Bootloader: v.MinimumTCB.Bootloader,
				TEE:        v.MinimumTCB.TEE,
				SNP:        v.MinimumTCB.SNP,
				Microcode:  v.MinimumTCB.Microcode,
			},
			GuestPolicy: attest.GuestPolicy{
				ABIMajor:            v.GuestPolicy.ABIMajor,
				ABIMinor:            v.GuestPolicy.ABIMinor,
				AllowSMT:            v.GuestPolicy.AllowSMT,
				AllowMigrationAgent: v.GuestPolicy.AllowMigrationAgent,
				AllowDebug:          v.GuestPolicy.AllowDebug,
				RequireSingleSocket: v.GuestPolicy.RequireSingleSocket,
			},
		})
	}
	document, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("rendering the recorded set from %s: %v", path, err)
	}
	a := newAuthor(t)
	loaded, err := attest.LoadReferenceValueSet(document, a.sign(t, string(document)), a.public)
	if err != nil {
		t.Fatalf("the re-authored set from %s was refused: %v", path, err)
	}
	return loaded
}

// against builds the verification a peer would run: the real SEV-SNP verifier
// with no root of its own — which means the AMD root certificates embedded in
// the library, the production path — and the named set loaded through the
// loader, signature first.
//
// verify.Options is left empty deliberately. Every other test in this package
// hands the verifier a test root, because test-signed evidence must not chain
// to AMD; here the whole point is that it does.
//
// What comes back is a [preV2] rather than an [attest.Verification], because
// this evidence was recorded before binding context v2 existed: see that type.
func (g liveGuest) against(t *testing.T, setName string) *preV2 {
	t.Helper()
	return &preV2{verifier: snpAgainstAMDsRoot(t), set: reauthoredSet(t, filepath.Join(hardwareDir, setName))}
}

// snpAgainstAMDsRoot is the production SEV-SNP verifier: no root of its own, so
// the AMD roots embedded in the library.
func snpAgainstAMDsRoot(t *testing.T) attest.Verifier {
	t.Helper()
	verifier, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// preV2 answers the questions [attest.Verification] answers, for evidence
// recorded before ADR-0002's binding version 2 existed.
//
// Every bundle under docs/snp was acquired over SHA-512(public key ‖ v1
// context): the guests that produced them ran a tunneld that predates the
// policy digest, and the machines are not booked again to redo it. Ticket 18
// made v2 the only context [attest.Verification.Verify] admits, so these
// bundles are now refused there on the version alone, before anything AMD
// signed is looked at — which is correct, and is asserted as its own test in
// TestARecordingMadeBeforeBindingVersionTwoIsRefusedAsAnUnknownContext.
//
// It is not what these tests are about. They are about what real silicon
// reported and what a signed set decided about it, so they keep asking those
// two questions in the order Verify asks them: the vendor's verifier against
// the set, and then the binding recomputed from the recording's own v1 context
// with [attest.Binding.CallerSuppliedBytes] — the same arithmetic, on the same
// exported surface, as the guest used when it asked for the report.
type preV2 struct {
	verifier attest.Verifier
	set      attest.ReferenceValueSet
}

// Verify is [attest.Verification.Verify] with the binding context check left
// out and the binding check kept.
func (p *preV2) Verify(ctx context.Context, ev attest.Evidence, binding attest.Binding) (attest.Attested, error) {
	if !ev.Present() {
		return attest.Attested{}, attest.Refuse(attest.ReasonNoEvidence, "peer presented no evidence")
	}
	if binding.Context != attest.BindingContextV1 {
		return attest.Attested{}, attest.Refuse(attest.ReasonUnknownBindingContext,
			"this stand-in judges v1 recordings only; %x is not v1", binding.Context[:])
	}
	attested, err := p.verifier.Verify(ctx, ev, p.set)
	if err != nil {
		return attest.Attested{}, err
	}
	if want := binding.CallerSuppliedBytes(); want != attested.Claims.CallerSuppliedBytes {
		return attest.Attested{}, attest.Refuse(attest.ReasonBindingMismatch,
			"evidence is bound to different caller-supplied bytes than the presented public key produces under v1")
	}
	return attested, nil
}

// accept is the control, and the milestone: this evidence, this set, accepted.
func (g liveGuest) accept(t *testing.T, v *preV2) attest.Attested {
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
	//
	// It is the v1 formula — SHA-512(public key ‖ context), no policy digest —
	// because that is what the guest that produced this report computed. That
	// the formula still reproduces these recorded bytes is the property ticket
	// 18 had to keep while making v2 the only context a peer may speak.
	want := g.binding.CallerSuppliedBytes()
	if attested.Claims.CallerSuppliedBytes != want {
		t.Errorf("evidence carries %x; the presented key produces %x", attested.Claims.CallerSuppliedBytes, want)
	}
}

// TestARecordingMadeBeforeBindingVersionTwoIsRefusedAsAnUnknownContext is the
// other half of the test above, and the reason it needs a stand-in at all.
//
// This bundle is genuine AMD-signed evidence over a genuine v1 binding. A
// tunneld built today refuses it without reading any of that, because a v1 peer
// commits to no policy digest and admitting one would let any peer skip the
// policy check by claiming the older context. The recording is kept, the
// refusal is asserted, and the two together say exactly what changed: not that
// the evidence went bad, but that this verifier stopped speaking its version.
func TestARecordingMadeBeforeBindingVersionTwoIsRefusedAsAnUnknownContext(t *testing.T) {
	g := loadLiveGuest(t)

	// Control: through the stand-in that does speak v1, the same evidence and
	// the same set are accepted.
	g.accept(t, g.against(t, "reference-values.json"))

	v, err := attest.New(snpAgainstAMDsRoot(t), reauthoredSet(t, filepath.Join(hardwareDir, "reference-values.json")))
	if err != nil {
		t.Fatal(err)
	}
	refuses(t, v, g.evidence, g.binding, attest.ReasonUnknownBindingContext)
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
	set := reauthoredSet(t, filepath.Join(hardwareDir, setName))
	if len(set.Values) != 1 {
		t.Fatalf("%s holds %d reference values; these tests are written for one", setName, len(set.Values))
	}
	return hex.EncodeToString(set.Values[0].LaunchMeasurement)
}
