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

// Tests for the Intel TDX half of the vendor seam, in the style of ticket 02's:
// every refusal reason reached by a change to one thing, each paired with a
// control on the same wiring showing that legitimate evidence is still
// accepted.
//
// # Where the expected values in this file come from
//
// No test here copies a register out of a quote and puts it in a reference
// value. A check built that way cannot fail: it asks the machine what it
// measured and then requires the machine to have measured that.
//
// There are exactly two permitted sources, and every expected value below cites
// one of them.
//
//   - RTMR2, the image's register, is *read out of the prediction files*
//     under docs/snp/evidence/tdx/predict at test time, by
//     [tdxPredictedRTMR2]. Those files are ticket 16's output: RTMR2 computed
//     from the disk image before anything booted. Reading them mechanically
//     rather than transcribing them is deliberate — a hex constant in this
//     file could have been pasted from a quote and nobody would see it.
//
//   - MRTD, RTMR0 and RTMR1, the provider's registers, are the observed
//     constants below. They cannot be predicted from anything a reference
//     value author holds (docs/tdx-rtmr2-prediction.md, "What this does not
//     establish"), so they are pinned as facts about Google's current boot
//     stack, observed on real hardware and recorded as such.
//
// # What is real here and what is fake
//
// The recorded quotes are real: eight boots of a real Google TDX VM, verified
// against the real Intel collateral fetched once in ticket 17 and committed
// under docs/snp/evidence/tdx/collateral. Nothing in this file reaches the
// network, and the verifier is handed a getter that refuses every address the
// provisioned directory does not answer, so an accepted verdict is also
// evidence that nothing was fetched.
//
// The mutations that a recording cannot express — a register moved, a debug
// TD, a TCB level Intel calls out of date — come from
// gvisor.dev/gvisor/attest/tdxfake, which re-signs a recording under a
// generated chain and mints the Intel collateral to match.
package attest_test

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tdxfake"
	"gvisor.dev/gvisor/attest/verify"
)

// tdxEvidenceDir is where ticket 14's and ticket 16's recordings live,
// relative to this module.
const tdxEvidenceDir = "../docs/snp/evidence/tdx"

// tdxCollateralDir is the Intel collateral fetched once from Intel's
// provisioning service and committed on this branch, with its transcript in
// FETCH.txt. It is the only collateral these tests use.
var tdxCollateralDir = filepath.Join(tdxEvidenceDir, "collateral")

// tdxNow is a fixed instant inside the recorded collateral's validity: it was
// issued on 2026-09-08 and expires a month later. Every test judges expiry
// against this rather than against the day it runs, because collateral that
// expires on a calendar would otherwise turn a passing suite into a failing one
// with no change to any code.
var tdxNow = time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)

// The provider's registers, observed on real Google TDX VMs and pinned as
// constants. See the file comment for why these are observed rather than
// predicted, and docs/tdx-rtmr2-prediction.md for what that costs.
//
// RTMR1 takes two values and both are listed: it covers the GPT, and a Google
// VM produces one value on its first boot — before the root partition is
// grown — and another on every boot after. A reference value naming one would
// refuse a healthy peer after its first reboot.
const (
	tdxObservedMRTD       = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"
	tdxObservedRTMR0      = "c0b8b19ca6f51dc37435da45a61ab417e59253cd31cc2eeb3e833e8b8979679fe5a65387e0014831fe7b3ec4be51896d"
	tdxObservedRTMR1First = "02c7f19c862b3dae1592c737358d9bb13f8f0a34d3b3eca67c39bf7941a12c347635b8a291d68d9cace45b16ec25913b"
	tdxObservedRTMR1Later = "3a446943925fef7f1682fd54e1b6697df864692e28592ec373860d1868582ac14ca3029c48282eb964868a785bafd691"
)

// tdxFloor is the TCB floor every reference value in this file carries: Intel's
// current status, and collateral no older than the evaluation data number the
// recorded collateral carries.
var tdxFloor = attest.TDXTCBFloor{Status: attest.TDXTCBUpToDate, EvaluationDataNumber: 20}

// A tdxBoot is one recorded boot of the measured image: the quote it produced,
// and the file holding the RTMR2 that was predicted for it before it booted.
type tdxBoot struct {
	// name is what the boot is called in the record.
	name string

	// quote is the recorded quote, relative to [tdxEvidenceDir].
	quote string

	// prediction is the file under predict/ whose "RTMR2 predicted" line is
	// this boot's expected RTMR2. Several boots share one: a boot that changed
	// nothing about the image is predicted by the image's own prediction.
	prediction string
}

// tdxBoots is every quote recorded on this branch. The four distinct predicted
// RTMR2 values among them are the four image states ticket 16 produced: the
// pristine image, and the three the upgrade study created.
var tdxBoots = []tdxBoot{
	{"eventlog", "eventlog/quote.bin", "predict-v20260826.txt"},
	{"eventlog-wrongmap", "eventlog-wrongmap/quote.bin", "predict-vs-run1.txt"},
	{"control-reboot", "mutate/control-reboot/quote.bin", "predict-vs-control-reboot.txt"},
	{"upgrade-baseline", "predict/upgrade/baseline/quote.bin", "predict-v20260826.txt"},
	{"update-grub", "predict/upgrade/update-grub/quote.bin", "predict-vs-update-grub.txt"},
	{"recordfail", "predict/upgrade/recordfail/quote.bin", "predict-vs-recordfail.txt"},
	{"upgrade-kernel-baseline", "predict/upgrade-kernel/baseline/quote.bin", "predict-v20260826.txt"},
	{"kernel-upgrade", "predict/upgrade-kernel/kernel-upgrade/quote.bin", "predict-vs-kernel-upgrade.txt"},
}

// TestEveryRecordedBootIsAcceptedByTheValuePredictedForIt is the acceptance
// case, and the control every refusal below is measured against.
//
// Eight boots of a real Google TDX VM, each verified against the real Intel
// collateral, each admitted by a reference value whose RTMR2 was predicted from
// the image before that boot happened and whose other registers are the
// provider's observed constants. Nothing is fetched and no confidential VM is
// involved.
func TestEveryRecordedBootIsAcceptedByTheValuePredictedForIt(t *testing.T) {
	for _, boot := range tdxBoots {
		t.Run(boot.name, func(t *testing.T) {
			attested := tdxMustAccept(t, tdxRecordedVerifier(t), tdxRecordedEvidence(t, boot), tdxSetFor(t, boot))
			if got := attested.Vendor; got != attest.VendorIntelTDX {
				t.Errorf("accepted as vendor %q, want %q", got, attest.VendorIntelTDX)
			}
			// The launch measurement a TDX peer is admitted on is RTMR2, and
			// the claims must say so: everything above the seam reads that
			// field without knowing which vendor filled it.
			if got, want := attested.Claims.LaunchMeasurement, attested.Claims.TDX.RTMR2; !bytesEqualTDX(got, want) {
				t.Errorf("launch measurement %x is not RTMR2 %x", got, want)
			}
			if got := attested.Claims.TDX.TCBStatus; got != attest.TDXTCBUpToDate {
				t.Errorf("Intel's status for this platform read as %q, want %q", got, attest.TDXTCBUpToDate)
			}
			if got := attested.Claims.TDX.TCBEvaluationDataNumber; got != tdxFloor.EvaluationDataNumber {
				t.Errorf("evaluation data number %d, want the recorded collateral's %d", got, tdxFloor.EvaluationDataNumber)
			}
		})
	}
}

// TestARecordedBootIsRefusedByAnotherBootsPrediction is the refusal that keeps
// a modified image out, on real evidence.
//
// update-grub and kernel-upgrade are the natural cases: both are the same VM,
// the same firmware and the same provider registers, differing only in what
// grub and the kernel became after an upgrade. A verifier that admitted them
// under the pristine image's reference value would be admitting an image nobody
// signed for.
func TestARecordedBootIsRefusedByAnotherBootsPrediction(t *testing.T) {
	verifier := tdxRecordedVerifier(t)
	for _, boot := range tdxBoots {
		own := tdxPredictedRTMR2(t, boot.prediction)
		for _, other := range tdxBoots {
			elsewhere := tdxPredictedRTMR2(t, other.prediction)
			if bytesEqualTDX(own, elsewhere) {
				// The same image state: nothing to tell apart.
				continue
			}
			t.Run(boot.name+"/vs/"+other.name, func(t *testing.T) {
				// Control: this boot is accepted by its own prediction on this
				// same wiring.
				tdxMustAccept(t, verifier, tdxRecordedEvidence(t, boot), tdxSetFor(t, boot))

				tdxMustRefuse(t, verifier, tdxRecordedEvidence(t, boot), tdxSetFor(t, other), attest.ReasonMeasurementNotInSet)
			})
		}
	}
}

// TestEvidenceFromAnotherVendorIsRefusedByTheTDXVerifier: a verifier that
// guessed at the format of evidence whose vendor it does not implement would
// have turned itself into an attack surface for no benefit.
func TestEvidenceFromAnotherVendorIsRefusedByTheTDXVerifier(t *testing.T) {
	boot := tdxBoots[0]
	verifier := tdxRecordedVerifier(t)
	set := tdxSetFor(t, boot)
	tdxMustAccept(t, verifier, tdxRecordedEvidence(t, boot), set)

	// The same bytes, claiming AMD. The vendor tag is checked before anything
	// looks at the bytes, which is the whole point of routing on a tag.
	elsewhere := tdxRecordedEvidence(t, boot)
	elsewhere.Vendor = attest.VendorAMDSEVSNP
	tdxMustRefuse(t, verifier, elsewhere, set, attest.ReasonUnsupportedVendor)
}

// TestTDXEvidenceReachingADispatcherThatOnlyKnowsAMDIsRefused is the same
// property one level up: a dispatcher does not offer evidence to a verifier
// that did not claim its vendor, on the chance that it might parse.
func TestTDXEvidenceReachingADispatcherThatOnlyKnowsAMDIsRefused(t *testing.T) {
	snp, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatalf("building the SEV-SNP verifier: %v", err)
	}
	amdOnly, err := attest.Dispatch(snp)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	boot := tdxBoots[0]
	tdxMustRefuse(t, amdOnly, tdxRecordedEvidence(t, boot), tdxSetFor(t, boot), attest.ReasonUnsupportedVendor)
}

// TestADispatcherWithBothVendorsAdmitsTDXEvidenceFromAMixedSet is the shape
// ticket 17 exists to produce: one signed reference value set naming peers on
// either vendor, one verifier above the seam, and no change to
// [attest.Verification].
func TestADispatcherWithBothVendorsAdmitsTDXEvidenceFromAMixedSet(t *testing.T) {
	snp, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatalf("building the SEV-SNP verifier: %v", err)
	}
	both, err := attest.Dispatch(snp, tdxRecordedVerifier(t))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if got := both.Vendor(); got != "amd-sev-snp+intel-tdx" {
		t.Errorf("the dispatcher names itself %q; a composite that does not name both is a lie in a log", got)
	}

	boot := tdxBoots[0]
	mixed := tdxSetFor(t, boot)
	// An SEV-SNP value about some other image, in the same set. It is a
	// reference value and not a register read off any quote; a TDX peer has
	// nothing to say about it and it must not refuse one.
	mixed.Values = append([]attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: tdxHex(t, strings.Repeat("a5", 48)),
		MinimumTCB:        attest.TCB{Bootloader: 9, SNP: 23, Microcode: 72},
	}}, mixed.Values...)

	tdxMustAccept(t, both, tdxRecordedEvidence(t, boot), mixed)
}

// TestATruncatedQuoteIsRefusedAsMalformed: attacker-supplied bytes reach the
// parser before anything else does, and the parser is not a place to be
// optimistic.
func TestATruncatedQuoteIsRefusedAsMalformed(t *testing.T) {
	boot := tdxBoots[0]
	verifier := tdxRecordedVerifier(t)
	set := tdxSetFor(t, boot)
	evidence := tdxRecordedEvidence(t, boot)
	tdxMustAccept(t, verifier, evidence, set)

	truncated := evidence
	truncated.Bytes = evidence.Bytes[:600]
	tdxMustRefuse(t, verifier, truncated, set, attest.ReasonMalformedEvidence)
}

// TestAFlippedByteInARecordedQuoteIsRefused is authenticity checked on real
// evidence: one byte of a real quote's TD report changed, everything else
// untouched, including the real PCK chain and the real Intel collateral.
//
// The verdict is [attest.ReasonChainNotRooted] and not something about the
// register that moved, because the signature over the report no longer holds
// and nothing after that point is believed.
func TestAFlippedByteInARecordedQuoteIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	verifier := tdxRecordedVerifier(t)
	set := tdxSetFor(t, boot)
	evidence := tdxRecordedEvidence(t, boot)
	tdxMustAccept(t, verifier, evidence, set)

	flipped := evidence
	flipped.Bytes = append([]byte(nil), evidence.Bytes...)
	// 0x100 is inside the TD report, which the attestation key signs over.
	flipped.Bytes[0x100] ^= 0x01
	tdxMustRefuse(t, verifier, flipped, set, attest.ReasonChainNotRooted)
}

// TestCollateralPastItsDateRefusesAsAChainThatDoesNotRootNow is why expired
// collateral gets no reason of its own: it shares [attest.ReasonChainNotRooted]
// with a forged chain, because both answer the same question — is this
// evidence rooted now — and a chain judged against collateral that is not
// valid now cannot be.
//
// The peer is the same real VM, the quote is the same real quote and the
// collateral is the same real Intel documents. The only difference is the
// date, and on the later date the verifier can say nothing about any peer at
// all. What tells an operator this is not a forged peer is the refusal's
// detail, which names the verifier's own provisioning and ADR-0007 rather than
// anything the peer did.
func TestCollateralPastItsDateRefusesAsAChainThatDoesNotRootNow(t *testing.T) {
	boot := tdxBoots[0]
	set := tdxSetFor(t, boot)
	evidence := tdxRecordedEvidence(t, boot)

	// Control: inside the collateral's validity, accepted.
	tdxMustAccept(t, tdxRecordedVerifier(t), evidence, set)

	// The recorded collateral was issued on 2026-09-08 and says nextUpdate a
	// month later. Three months on, it is stale.
	later, err := verify.NewTDX(verify.TDXOptions{CollateralDir: tdxCollateralDir, Now: tdxNow.AddDate(0, 3, 0)})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	refusal := tdxMustRefuse(t, later, evidence, set, attest.ReasonChainNotRooted)
	if got := detail(refusal); !strings.Contains(got, "ADR-0007") {
		t.Errorf("refusal detail = %q; want it to name ADR-0007, the remedy for the verifier's own stale collateral, not the peer", got)
	}
}

// TestARecordedQuoteDoesNotChainToAFakePlatformsRoot, and its converse, are
// the two halves of the same statement: these quotes are Intel's and the fake's
// are not.
func TestARecordedQuoteDoesNotChainToAFakePlatformsRoot(t *testing.T) {
	boot := tdxBoots[0]
	fake := tdxNewFake(t, boot, tdxfake.Config{})

	// The real quote, judged against the fake platform's root.
	wrongRoot, err := verify.NewTDX(verify.TDXOptions{
		CollateralDir: tdxCollateralDir,
		VendorRootPEM: fake.VendorRootPEM(),
		Now:           tdxNow,
	})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	tdxMustRefuse(t, wrongRoot, tdxRecordedEvidence(t, boot), tdxSetFor(t, boot), attest.ReasonChainNotRooted)

	// And the fake's quote against Intel's real root, which is the default.
	tdxMustRefuse(t, tdxRecordedVerifier(t), tdxAcquire(t, fake), tdxSetFor(t, boot), attest.ReasonChainNotRooted)
}

// TestAFakeSignedUnderAnotherFakesRootIsRefused: two generated chains, and
// evidence from one judged against the other's root. The evidence is complete,
// parses, and carries a full chain — it simply descends from a root this
// verifier was not told to trust.
func TestAFakeSignedUnderAnotherFakesRootIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	platform := tdxNewFake(t, boot, tdxfake.Config{})
	impostor := tdxNewFake(t, boot, tdxfake.Config{})

	// Control: the platform's own root admits it.
	tdxMustAccept(t, tdxFakeVerifier(t, platform), tdxAcquire(t, platform), tdxSetFor(t, boot))

	elsewhere, err := verify.NewTDX(verify.TDXOptions{
		CollateralDir: platform.CollateralDir(),
		VendorRootPEM: impostor.VendorRootPEM(),
		Now:           tdxNow,
	})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	tdxMustRefuse(t, elsewhere, tdxAcquire(t, platform), tdxSetFor(t, boot), attest.ReasonChainNotRooted)
}

// TestCollateralSignedByAStrangerIsRefused: the TCB info and quoting-enclave
// identity signed by a key nothing vouches for, while the issuer chain in the
// response headers still names the legitimate signing certificate.
//
// This is what a host that edited its own provisioned collateral looks like —
// raising a platform's status, say — and it must be refused for the same reason
// a forged quote is. The collateral is as much a signed document as the quote.
func TestCollateralSignedByAStrangerIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	honest := tdxNewFake(t, boot, tdxfake.Config{})
	tdxMustAccept(t, tdxFakeVerifier(t, honest), tdxAcquire(t, honest), tdxSetFor(t, boot))

	forged := tdxNewFake(t, boot, tdxfake.Config{CollateralSignedByStranger: true})
	tdxMustRefuse(t, tdxFakeVerifier(t, forged), tdxAcquire(t, forged), tdxSetFor(t, boot), attest.ReasonChainNotRooted)
}

// TestAPlatformIntelCallsOutOfDateIsRefusedAtIntelsGate records a behaviour of
// the pinned library rather than a design decision, and the assertion is here
// so that the behaviour cannot change without a test noticing.
//
// go-tdx-guest at this commit requires the platform's TCB status to be exactly
// UpToDate, inside the same call that checks the quote's signature and the
// collateral's. So a platform whose level Intel calls out of date never reaches
// the reference value's floor: it is refused as [attest.ReasonChainNotRooted],
// with the floor untouched. See the verify.TDX type comment for what that means
// for a floor of SWHardeningNeeded, which is the case that cannot currently be
// admitted at all.
func TestAPlatformIntelCallsOutOfDateIsRefusedAtIntelsGate(t *testing.T) {
	boot := tdxBoots[0]
	current := tdxNewFake(t, boot, tdxfake.Config{})
	tdxMustAccept(t, tdxFakeVerifier(t, current), tdxAcquire(t, current), tdxSetFor(t, boot))

	stale := tdxNewFake(t, boot, tdxfake.Config{TCBStatus: "OutOfDate"})
	// A floor of UpToDate would refuse this platform too, so the set is given
	// the weakest floor a reference value may name. It still lands on
	// ChainNotRooted, which is the point: Intel's gate ran first.
	set := tdxSetFor(t, boot)
	set.Values[0].TDX.MinimumTCB = attest.TDXTCBFloor{Status: attest.TDXTCBSWHardeningNeeded}
	tdxMustRefuse(t, tdxFakeVerifier(t, stale), tdxAcquire(t, stale), set, attest.ReasonChainNotRooted)
}

// TestCollateralFromBeforeATCBRecoveryIsBelowTheFloor is the TCB refusal a
// reference value can still make at this library commit, and the one that
// matters most in a design where the *host* provisions the collateral.
//
// Intel raises tcbEvaluationDataNumber at every TCB recovery. Collateral from
// before a recovery verifies perfectly and still calls a since-vulnerable
// platform UpToDate, so a host that never re-provisions is a host whose peers
// are judged against last year's opinion. The floor is what catches that, and
// nothing else does.
func TestCollateralFromBeforeATCBRecoveryIsBelowTheFloor(t *testing.T) {
	boot := tdxBoots[0]
	current := tdxNewFake(t, boot, tdxfake.Config{})
	tdxMustAccept(t, tdxFakeVerifier(t, current), tdxAcquire(t, current), tdxSetFor(t, boot))

	old := tdxNewFake(t, boot, tdxfake.Config{EvaluationDataNumber: tdxFloor.EvaluationDataNumber - 1})
	tdxMustRefuse(t, tdxFakeVerifier(t, old), tdxAcquire(t, old), tdxSetFor(t, boot), attest.ReasonTCBBelowFloor)
}

// TestADebugEnabledTDIsRefused is the refusal that keeps a TD the host can read
// out of the tunnel. TD_ATTRIBUTES.DEBUG lets the host inspect the TD's memory,
// which makes every confidentiality claim the tunnel rests on false.
func TestADebugEnabledTDIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	ordinary := tdxNewFake(t, boot, tdxfake.Config{})
	tdxMustAccept(t, tdxFakeVerifier(t, ordinary), tdxAcquire(t, ordinary), tdxSetFor(t, boot))

	// The same attributes the recording carries, with bit 0 of the first byte
	// set. Nothing else about the platform changes.
	attributes := append([]byte(nil), tdxRecordedTDAttributes...)
	attributes[0] |= 0x01
	debugging := tdxNewFake(t, boot, tdxfake.Config{TDAttributes: attributes})
	tdxMustRefuse(t, tdxFakeVerifier(t, debugging), tdxAcquire(t, debugging), tdxSetFor(t, boot), attest.ReasonPolicyMismatch)

	// And a reference value that does permit it admits it, so the refusal above
	// is the policy and not an accident of the fake.
	permissive := tdxSetFor(t, boot)
	permissive.Values[0].TDX.TDPolicy.AllowDebug = true
	tdxMustAccept(t, tdxFakeVerifier(t, debugging), tdxAcquire(t, debugging), permissive)
}

// TestAProviderRegisterOutsideTheObservedListIsRefused: MRTD, RTMR0 and RTMR1
// are the provider's, listed as observed constants, and a peer whose firmware
// or boot chain is not one of the listed values is refused even though its
// image is exactly right.
//
// This is the check that would fire the day Google changes its firmware, and
// the reason the reference value calls those fields Observed: nobody predicted
// them, so nobody can predict the next ones either.
func TestAProviderRegisterOutsideTheObservedListIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	elsewhere := make([]byte, 48)
	for i := range elsewhere {
		elsewhere[i] = 0x5a
	}
	for _, tc := range []struct {
		name string
		cfg  tdxfake.Config
	}{
		{"MRTD", tdxfake.Config{MRTD: elsewhere}},
		{"RTMR0", tdxfake.Config{RTMR0: elsewhere}},
		{"RTMR1", tdxfake.Config{RTMR1: elsewhere}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := tdxNewFake(t, boot, tdxfake.Config{})
			tdxMustAccept(t, tdxFakeVerifier(t, control), tdxAcquire(t, control), tdxSetFor(t, boot))

			moved := tdxNewFake(t, boot, tc.cfg)
			refusal := tdxMustRefuse(t, tdxFakeVerifier(t, moved), tdxAcquire(t, moved), tdxSetFor(t, boot), attest.ReasonMeasurementNotInSet)
			if !strings.Contains(refusal.Detail(), tc.name) {
				t.Errorf("the operator log does not say which register moved: %s", refusal.LogString())
			}
		})
	}
}

// TestARecordedQuoteIsRefusedWhenItsBindingIsWrong is the ADR-0002 check, run
// through [attest.Verification] so that it is the same code path both vendors
// take.
//
// The recorded quotes were taken over fixed caller-supplied bytes — 0x00
// through 0x3f, an operator's counting pattern — rather than over the digest of
// any key, so any key at all is the wrong one for them. That is exactly the
// shape of a replayed report: genuine evidence, genuine chain, presented
// alongside a key it was never bound to.
//
// The binding claims v2, which is what a peer today speaks, and the reference
// value lists no policy digest, so the policy check admits any policy and the
// refusal below is the binding and nothing before it.
func TestARecordedQuoteIsRefusedWhenItsBindingIsWrong(t *testing.T) {
	boot := tdxBoots[0]
	verification, err := attest.New(tdxRecordedVerifier(t), tdxSetFor(t, boot))
	if err != nil {
		t.Fatalf("attest.New: %v", err)
	}
	binding := attest.Binding{PublicKey: []byte("a public key this evidence was never bound to"), Context: attest.BindingContextV2, PolicyDigest: tdxPolicy}
	_, err = verification.Verify(context.Background(), tdxRecordedEvidence(t, boot), binding)
	if got := attest.ReasonOf(err); got != attest.ReasonBindingMismatch {
		t.Fatalf("refused with %v, want %v", got, attest.ReasonBindingMismatch)
	}
}

// TestAFakeTDXPlatformIsAcceptedThroughVerification closes the loop the test
// above leaves open: with evidence acquired over the binding's own bytes, the
// whole path — dispatcher, vendor verifier, reference value, ADR-0002 binding —
// accepts.
func TestAFakeTDXPlatformIsAcceptedThroughVerification(t *testing.T) {
	boot := tdxBoots[0]
	platform := tdxNewFake(t, boot, tdxfake.Config{})
	snp, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatalf("building the SEV-SNP verifier: %v", err)
	}
	both, err := attest.Dispatch(snp, tdxFakeVerifier(t, platform))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	verification, err := attest.New(both, tdxSetFor(t, boot))
	if err != nil {
		t.Fatalf("attest.New: %v", err)
	}

	binding := attest.Binding{PublicKey: []byte("the peer's presented public key"), Context: attest.BindingContextV2, PolicyDigest: tdxPolicy}
	evidence, err := platform.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	attested, err := verification.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("accepted evidence was refused: %v", tdxLog(err))
	}
	if attested.Claims.TDX == nil {
		t.Fatal("an accepted TDX platform carries no TDX claims")
	}

	// And the same evidence against another key is refused, so the acceptance
	// above was not the binding being ignored.
	other := attest.Binding{PublicKey: []byte("somebody else's public key"), Context: attest.BindingContextV2, PolicyDigest: tdxPolicy}
	if _, err := verification.Verify(context.Background(), evidence, other); attest.ReasonOf(err) != attest.ReasonBindingMismatch {
		t.Fatalf("refused with %v, want %v", attest.ReasonOf(err), attest.ReasonBindingMismatch)
	}
}

// TestATDXPeerIsAdmittedOnlyByASetListingItsPolicy is ticket 18's allow-list at
// the second vendor, which is the point of putting the check above the seam:
// the entries are measurement and policy pairs for Intel exactly as they are
// for AMD, and nothing in verify/tdx.go knows a policy exists.
//
// The platform is the fake one rather than a recorded quote, and it has to be.
// The recordings were taken over fixed caller-supplied bytes, so their binding
// cannot be chosen and a peer presenting a policy of its own cannot be built
// out of one. What a recorded quote can show about this is the refusal, and
// TestARecordedQuoteIsRefusedWhenItsBindingIsWrong shows it.
func TestATDXPeerIsAdmittedOnlyByASetListingItsPolicy(t *testing.T) {
	boot := tdxBoots[0]
	platform := tdxNewFake(t, boot, tdxfake.Config{})
	binding := attest.Binding{
		PublicKey:    []byte("the TDX peer's presented public key"),
		Context:      attest.BindingContextV2,
		PolicyDigest: tdxPolicy,
	}
	evidence, err := platform.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	verify := func(t *testing.T, set attest.ReferenceValueSet, b attest.Binding) (attest.Attested, error) {
		t.Helper()
		v, err := attest.New(tdxFakeVerifier(t, platform), set)
		if err != nil {
			t.Fatalf("attest.New: %v", err)
		}
		return v.Verify(context.Background(), evidence, b)
	}

	// Listed: admitted, by the value that lists it.
	attested, err := verify(t, tdxSetListing(t, boot, tdxPolicy), binding)
	if err != nil {
		t.Fatalf("a TDX peer presenting a listed policy was refused: %v", tdxLog(err))
	}
	if attested.Satisfied.PolicyDigest == nil || *attested.Satisfied.PolicyDigest != tdxPolicy {
		t.Errorf("admitted by a value listing %v; want the one listing %s", attested.Satisfied.PolicyDigest, tdxPolicy)
	}

	// Unlisted: refused as a policy mismatch, with the presented digest named.
	_, err = verify(t, tdxSetListing(t, boot, tdxOtherPolicy), binding)
	if got := attest.ReasonOf(err); got != attest.ReasonPolicyMismatch {
		t.Fatalf("refused with %v, want %v (%s)", got, attest.ReasonPolicyMismatch, tdxLog(err))
	}
	var refusal *attest.Refusal
	if errors.As(err, &refusal) && !strings.Contains(refusal.Detail(), tdxPolicy.String()) {
		t.Errorf("the operator log does not name the policy the peer presented: %s", refusal.LogString())
	}

	// Unconstrained: the set every TDX value on this branch was authored as,
	// which lists no policy and admits any.
	if _, err := verify(t, tdxSetFor(t, boot), binding); err != nil {
		t.Errorf("an unconstrained TDX value refused a peer's policy: %v", tdxLog(err))
	}

	// And a digest swapped in flight is refused at the binding rather than
	// admitted: both policies are listed, so the peer reaches the binding check
	// instead of being turned away a step earlier as a policy mismatch.
	claimed := binding
	claimed.PolicyDigest = tdxOtherPolicy
	both := tdxSetListing(t, boot, tdxPolicy)
	both.Values = append(both.Values, tdxSetListing(t, boot, tdxOtherPolicy).Values...)
	if _, err := verify(t, both, claimed); attest.ReasonOf(err) != attest.ReasonBindingMismatch {
		t.Fatalf("refused with %v, want %v (%s)", attest.ReasonOf(err), attest.ReasonBindingMismatch, tdxLog(err))
	}
}

// tdxSetListing is tdxSetFor with a policy digest on its one value.
func tdxSetListing(t *testing.T, boot tdxBoot, policy attest.PolicyDigest) attest.ReferenceValueSet {
	t.Helper()
	set := tdxSetFor(t, boot)
	set.Values[0].PolicyDigest = &policy
	return set
}

// TestNoTDXEvidenceIsRefused: a peer that presents none must be refused, not
// treated as unknown.
func TestNoTDXEvidenceIsRefused(t *testing.T) {
	boot := tdxBoots[0]
	verifier := tdxRecordedVerifier(t)
	tdxMustAccept(t, verifier, tdxRecordedEvidence(t, boot), tdxSetFor(t, boot))
	tdxMustRefuse(t, verifier, attest.Evidence{Vendor: attest.VendorIntelTDX}, tdxSetFor(t, boot), attest.ReasonNoEvidence)
}

// TestAVerifierWhoseCollateralIsMissingRefusesRatherThanFetching is ADR-0005's
// consequence for the second vendor, and the assertion on the detail is the
// regression guard: if a fetch were ever introduced, the refusal would come
// from the getter rather than from the absent file, and the reason alone would
// not tell the difference.
func TestAVerifierWhoseCollateralIsMissingRefusesRatherThanFetching(t *testing.T) {
	boot := tdxBoots[0]
	tdxMustAccept(t, tdxRecordedVerifier(t), tdxRecordedEvidence(t, boot), tdxSetFor(t, boot))

	empty, err := verify.NewTDX(verify.TDXOptions{CollateralDir: t.TempDir(), Now: tdxNow})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	refusal := tdxMustRefuse(t, empty, tdxRecordedEvidence(t, boot), tdxSetFor(t, boot), attest.ReasonChainNotRooted)
	if strings.Contains(refusal.Detail(), "refusing to fetch") {
		t.Errorf("verification tried to fetch collateral: %s", refusal.LogString())
	}
	if !strings.Contains(refusal.Detail(), "ADR-0005") {
		t.Errorf("the operator log does not point at the provisioning decision: %s", refusal.LogString())
	}
}

// tdxPolicy is the policy digest a TDX peer presents in these tests, standing
// in for the digest of its own signed reference value set. Whose document it is
// the digest of is settled in refvalsfile_test.go; here it only has to be
// something a peer can bind and a set can list.
var tdxPolicy = attest.PolicyDigest{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8}

// tdxOtherPolicy is a second sandbox's policy: a digest this peer does not
// present, and therefore one an allow-list holding only it must refuse.
var tdxOtherPolicy = attest.PolicyDigest{0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8}

// tdxRecordedTDAttributes is TD_ATTRIBUTES as every recorded boot carries it:
// DEBUG clear. It is a fact about the recordings, used to build a debugging
// platform that differs from them in exactly one bit; it is never a reference
// value.
var tdxRecordedTDAttributes = []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}

// tdxRecordedVerifier is a verifier over the real Intel collateral, judging
// certificate validity at [tdxNow].
//
// It is deliberately given no VendorRootPEM: the root of trust is the Intel
// root embedded in go-tdx-guest, so an acceptance here says these quotes chain
// to Intel's own root and not to anything in this tree. The library says so on
// stdout each time, which is noise in a test log and evidence in a transcript.
func tdxRecordedVerifier(t *testing.T) *verify.TDX {
	t.Helper()
	v, err := verify.NewTDX(verify.TDXOptions{CollateralDir: tdxCollateralDir, Now: tdxNow})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	return v
}

// tdxFakeVerifier is a verifier over one fake platform's generated collateral
// and root.
func tdxFakeVerifier(t *testing.T, p *tdxfake.Platform) *verify.TDX {
	t.Helper()
	v, err := verify.NewTDX(verify.TDXOptions{
		CollateralDir: p.CollateralDir(),
		VendorRootPEM: p.VendorRootPEM(),
		Now:           tdxNow,
	})
	if err != nil {
		t.Fatalf("building the TDX verifier: %v", err)
	}
	return v
}

// tdxNewFake builds a fake platform from one recorded boot, with its collateral
// in a directory of its own.
func tdxNewFake(t *testing.T, boot tdxBoot, cfg tdxfake.Config) *tdxfake.Platform {
	t.Helper()
	cfg.RecordedQuote = tdxReadQuote(t, boot)
	cfg.CollateralDir = t.TempDir()
	cfg.Now = tdxNow
	p, err := tdxfake.New(cfg)
	if err != nil {
		t.Fatalf("building the fake TDX platform: %v", err)
	}
	return p
}

// tdxAcquire asks a fake platform for evidence over bytes nothing else in the
// test depends on. Tests that care about the binding build it themselves.
func tdxAcquire(t *testing.T, p *tdxfake.Platform) attest.Evidence {
	t.Helper()
	ev, err := p.Acquire(context.Background(), [attest.CallerSuppliedBytesSize]byte{})
	if err != nil {
		t.Fatalf("acquiring evidence from the fake platform: %v", err)
	}
	return ev
}

// tdxReadQuote reads one recorded quote.
func tdxReadQuote(t *testing.T, boot tdxBoot) []byte {
	t.Helper()
	path := filepath.Join(tdxEvidenceDir, boot.quote)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the recorded quote %s: %v", path, err)
	}
	return raw
}

// tdxRecordedEvidence is one recorded quote as evidence. A TDX quote carries
// its own certificate chain, so Chain stays empty.
func tdxRecordedEvidence(t *testing.T, boot tdxBoot) attest.Evidence {
	t.Helper()
	return attest.Evidence{Vendor: attest.VendorIntelTDX, Bytes: tdxReadQuote(t, boot)}
}

// tdxSetFor is the reference value set that should admit one boot: that boot's
// predicted RTMR2, the provider's observed registers, and the floor.
func tdxSetFor(t *testing.T, boot tdxBoot) attest.ReferenceValueSet {
	t.Helper()
	return attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor: attest.VendorIntelTDX,
		TDX: &attest.TDXReferenceValue{
			ObservedMRTD:   [][]byte{tdxHex(t, tdxObservedMRTD)},
			ObservedRTMR0:  [][]byte{tdxHex(t, tdxObservedRTMR0)},
			ObservedRTMR1:  [][]byte{tdxHex(t, tdxObservedRTMR1First), tdxHex(t, tdxObservedRTMR1Later)},
			PredictedRTMR2: tdxPredictedRTMR2(t, boot.prediction),
			MinimumTCB:     tdxFloor,
		},
	}}}
}

// tdxPredictedRTMR2 reads the "RTMR2 predicted" line out of one of ticket 16's
// prediction files.
//
// It reads the file rather than restating its contents on purpose. A hex
// constant in a test could have come from anywhere, including from the quote it
// is about to be compared against, and a reference value derived from the thing
// it checks checks nothing. Reading the prediction makes the provenance
// mechanical: if the file changes, this changes with it, and if the file is not
// a prediction the test cannot be repaired by editing a constant here.
func tdxPredictedRTMR2(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(tdxEvidenceDir, "predict", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reading the prediction %s: %v", path, err)
	}
	defer f.Close()

	const marker = "RTMR2 predicted"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), marker) {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("%s: %q has no value after the colon", path, line)
		}
		return tdxHex(t, strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	t.Fatalf("%s holds no %q line; the prediction this test needs is not there", path, marker)
	return nil
}

func tdxHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%q is not hexadecimal: %v", s, err)
	}
	return b
}

// tdxMustAccept requires a verdict of accepted and returns it.
func tdxMustAccept(t *testing.T, v attest.Verifier, ev attest.Evidence, set attest.ReferenceValueSet) attest.Attested {
	t.Helper()
	attested, err := v.Verify(context.Background(), ev, set)
	if err != nil {
		t.Fatalf("evidence that should be accepted was refused: %v", tdxLog(err))
	}
	return attested
}

// tdxMustRefuse requires a refusal with a particular reason and returns it, so
// that a test can go on to assert on what the operator reads.
func tdxMustRefuse(t *testing.T, v attest.Verifier, ev attest.Evidence, set attest.ReferenceValueSet, want attest.Reason) *attest.Refusal {
	t.Helper()
	attested, err := v.Verify(context.Background(), ev, set)
	if err == nil {
		t.Fatalf("evidence that should be refused was accepted as %+v", attested.Vendor)
	}
	refusal, ok := err.(*attest.Refusal)
	if !ok {
		t.Fatalf("refused with an untyped error, which a caller cannot report or log: %v", err)
	}
	if got := refusal.Reason(); got != want {
		t.Fatalf("refused with %v, want %v (log: %s)", got, want, refusal.LogString())
	}
	return refusal
}

// tdxLog renders a refusal the way an operator would read it, for a failure
// message that says what actually happened.
func tdxLog(err error) string {
	if r, ok := err.(*attest.Refusal); ok {
		return r.LogString()
	}
	return err.Error()
}

func bytesEqualTDX(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
