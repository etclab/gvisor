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

package attest_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/verify"
)

// TestEvidenceSatisfyingAReferenceValueIsAccepted is the control the whole file
// rests on. If this fails, no refusal below is evidence of anything.
func TestEvidenceSatisfyingAReferenceValueIsAccepted(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	attested := accepts(t, v, f)

	if attested.Vendor != attest.VendorAMDSEVSNP {
		t.Errorf("attested vendor = %q; want %q", attested.Vendor, attest.VendorAMDSEVSNP)
	}
	if !bytes.Equal(attested.Claims.LaunchMeasurement, theMeasurement) {
		t.Errorf("attested launch measurement = %x; want %x", attested.Claims.LaunchMeasurement, theMeasurement)
	}
	if attested.Claims.TCB != platformTCB {
		t.Errorf("attested TCB = %+v; want %+v", attested.Claims.TCB, platformTCB)
	}
	if !bytes.Equal(attested.Satisfied.LaunchMeasurement, theMeasurement) {
		t.Errorf("satisfied reference value = %+v; want the one for %x", attested.Satisfied, theMeasurement)
	}
}

// TestASetAdmitsEvidenceMatchingAnyOneOfItsValues is what lets a new image roll
// out while the old one is still running: a set holds more than one reference
// value and a peer matching any of them is admitted.
func TestASetAdmitsEvidenceMatchingAnyOneOfItsValues(t *testing.T) {
	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{
		{Vendor: attest.VendorAMDSEVSNP, LaunchMeasurement: otherMeasurement, MinimumTCB: floorTCB, GuestPolicy: permittedPolicy},
		{Vendor: attest.VendorAMDSEVSNP, LaunchMeasurement: theMeasurement, MinimumTCB: floorTCB, GuestPolicy: permittedPolicy},
	}}

	// A platform running the first image is admitted.
	first := newFixture(t, withMeasurement(defaultConfig(), otherMeasurement))
	accepts(t, verification(t, first, set), first)

	// So is a platform running the second, without either being redeployed.
	second := newFixture(t, defaultConfig())
	attested := accepts(t, verification(t, second, set), second)
	if !bytes.Equal(attested.Satisfied.LaunchMeasurement, theMeasurement) {
		t.Errorf("admitted by the reference value for %x; want the one for %x",
			attested.Satisfied.LaunchMeasurement, theMeasurement)
	}
}

// TestEvidenceNotChainingToTheVendorRootIsRefused points a verifier that trusts
// AMD's real root at a platform that signed its own chain. This is the shape an
// impostor takes: a well-formed report, a complete chain, and a root nobody
// should trust.
func TestEvidenceNotChainingToTheVendorRootIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())

	// Control: the same evidence, verified against the root that did sign it.
	accepts(t, verification(t, f, defaultSet()), f)

	// An empty VendorRootPEM means the AMD root certificates embedded in
	// go-sev-guest — the production configuration, which no fake platform can
	// chain to.
	amdRooted, err := verify.New(verify.Options{Now: whenChainsAreValid})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	v, err := attest.New(amdRooted, defaultSet())
	if err != nil {
		t.Fatalf("attest.New: %v", err)
	}
	refuses(t, v, f.evidence, f.binding, attest.ReasonChainNotRooted)
}

// TestEvidenceWithAForgedMeasurementIsRefused presents a genuine signature on a
// report whose launch measurement has been rewritten. The signature no longer
// covers the bytes presented, so the evidence is not authentic — the same
// question, and therefore the same reason, as a chain that does not root.
func TestEvidenceWithAForgedMeasurementIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())

	// Control: unforged evidence from the same platform is accepted.
	accepts(t, verification(t, f, defaultSet()), f)

	// A platform running an unauthorised image, forging the authorised
	// measurement onto its genuine report. The measurement it now claims is the
	// one the reference value set names, so a refusal here cannot be a
	// measurement mismatch in disguise.
	impostor := newFixture(t, withMeasurement(defaultConfig(), otherMeasurement))
	forged, err := impostor.platform.AcquireForged(context.Background(),
		impostor.binding.CallerSuppliedBytes(), theMeasurement)
	if err != nil {
		t.Fatalf("forging evidence: %v", err)
	}

	refuses(t, verification(t, impostor, defaultSet()), forged, impostor.binding, attest.ReasonChainNotRooted)
}

// TestLaunchMeasurementAbsentFromTheSetIsRefused is what keeps a modified image
// out. The platform is genuine and its evidence is authentic; it is simply
// running something the reference value author did not authorise.
func TestLaunchMeasurementAbsentFromTheSetIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())

	// Control: the set that names this image admits it.
	accepts(t, verification(t, f, defaultSet()), f)

	other := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: otherMeasurement,
		MinimumTCB:        floorTCB,
		GuestPolicy:       permittedPolicy,
	}}}
	refuses(t, verification(t, f, other), f.evidence, f.binding, attest.ReasonMeasurementNotInSet)
}

// TestPlatformBelowTheTCBFloorIsRefused is what keeps a known-vulnerable
// firmware level out. The image is the authorised one and the policy is
// permitted; only the platform's patch level is short.
func TestPlatformBelowTheTCBFloorIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())

	// Control: the floor this platform meets.
	accepts(t, verification(t, f, defaultSet()), f)

	raised := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: theMeasurement,
		MinimumTCB:        aboveTCB,
		GuestPolicy:       permittedPolicy,
	}}}
	refuses(t, verification(t, f, raised), f.evidence, f.binding, attest.ReasonTCBBelowFloor)
}

// TestGuestPolicyNotPermittedIsRefused is what stops a debug-enabled guest
// attesting. A guest the host may decrypt has nothing to prove, and a reference
// value that does not permit debugging must say so.
func TestGuestPolicyNotPermittedIsRefused(t *testing.T) {
	// Control: a guest launched without debugging, against a reference value
	// that does not permit it, is admitted.
	ok := newFixture(t, defaultConfig())
	accepts(t, verification(t, ok, defaultSet()), ok)

	debugging := defaultConfig()
	debugging.Policy = snpfake.Policy{SMT: true, Debug: true}
	f := newFixture(t, debugging)
	refuses(t, verification(t, f, defaultSet()), f.evidence, f.binding, attest.ReasonPolicyMismatch)
}

// TestAPeerPresentingAListedPolicyIsAccepted is the first half of ticket 18's
// allow-list: entries are measurement and policy pairs, and a peer running the
// named image under a listed policy is admitted.
//
// The verdict names the entry that admitted it, which is what an operator reads
// when two entries name one image during a policy rollout.
func TestAPeerPresentingAListedPolicyIsAccepted(t *testing.T) {
	f := newFixture(t, defaultConfig())

	attested := accepts(t, verification(t, f, setListingPolicies(thePolicy)), f)
	if attested.Satisfied.PolicyDigest == nil || *attested.Satisfied.PolicyDigest != thePolicy {
		t.Errorf("admitted by a value listing %v; want the one listing %s", attested.Satisfied.PolicyDigest, thePolicy)
	}

	// A set naming this image twice, under two policies, admits it by the entry
	// that lists the one it presents. That is the rollout case: an operator
	// adds the new policy beside the old and neither peer stops working.
	rollout := setListingPolicies(otherPolicy, thePolicy)
	attested = accepts(t, verification(t, f, rollout), f)
	if attested.Satisfied.PolicyDigest == nil || *attested.Satisfied.PolicyDigest != thePolicy {
		t.Errorf("admitted by a value listing %v; want the one listing the presented %s",
			attested.Satisfied.PolicyDigest, thePolicy)
	}
}

// TestAPeerPresentingAnUnlistedPolicyIsRefused is the refusal the allow-list
// exists for: the right image, running behaviour this verifier did not
// authorise.
//
// Everything else about the peer is in order — genuine platform, authentic
// evidence, measurement in the set, TCB met, guest policy permitted, binding
// sound — so a refusal here is the policy digest and nothing else. The detail
// names the digest the peer presented, because the operator's next move is to
// decide whether to add it to the set or to ask the peer what it is running.
func TestAPeerPresentingAnUnlistedPolicyIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())

	// Control: the same peer against a set that lists its policy.
	accepts(t, verification(t, f, setListingPolicies(thePolicy)), f)

	v := verification(t, f, setListingPolicies(otherPolicy))
	refuses(t, v, f.evidence, f.binding, attest.ReasonPolicyMismatch)

	_, err := v.Verify(context.Background(), f.evidence, f.binding)
	var r *attest.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if !strings.Contains(r.Detail(), thePolicy.String()) {
		t.Errorf("the operator log does not name the policy the peer presented: %s", r.LogString())
	}
	if strings.Contains(r.Detail(), otherPolicy.String()) {
		t.Errorf("the operator log names a policy the set holds; a refused peer's log line is not the place "+
			"to print the allow-list back: %s", r.LogString())
	}
}

// TestAnEntryWithNoPolicyDigestAdmitsAnyPolicy is the compatibility direction,
// stated as a test so that it is a decision rather than an oversight.
//
// A reference value that lists no policy_digest admits the image under any
// policy at all. Every set authored before ticket 18 is of that shape, and
// refusing them would have made this change a flag day for every deployment.
// The weakening is real, which is why a loaded set reports its unconstrained
// entries and a tunneld prints one line for each at startup.
func TestAnEntryWithNoPolicyDigestAdmitsAnyPolicy(t *testing.T) {
	unconstrained := defaultSet()
	if unconstrained.Values[0].PolicyDigest != nil {
		t.Fatal("the default set constrains a policy; this test is about one that does not")
	}
	for _, policy := range []attest.PolicyDigest{thePolicy, otherPolicy, {}} {
		f := newFixturePresenting(t, defaultConfig(), policy)
		accepts(t, verification(t, f, unconstrained), f)
	}

	// And the set says which entries those were, so nothing has to notice by
	// reading the file.
	if got := unconstrained.Unconstrained(); len(got) != 1 || got[0].Index != 0 || got[0].Vendor != attest.VendorAMDSEVSNP {
		t.Errorf("the set reports %+v as unconstrained; want its one value", got)
	}
	if got := setListingPolicies(thePolicy).Unconstrained(); len(got) != 0 {
		t.Errorf("a set whose every value lists a policy reports %+v as unconstrained", got)
	}
}

// TestAPolicyDigestSwappedInFlightIsRefusedAsABindingMismatch is what stops the
// allow-list being a formality.
//
// The peer's evidence was acquired over thePolicy; it is presented claiming
// otherPolicy, which is what an attacker holding a genuine report from a
// sandbox with a permissive policy would do to be admitted as a strict one.
// Both digests are in the set on purpose: without that the peer would be
// refused a step earlier as a policy mismatch, and this test would pass while
// proving nothing about the binding.
func TestAPolicyDigestSwappedInFlightIsRefusedAsABindingMismatch(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, setListingPolicies(thePolicy, otherPolicy))

	// Control: presented honestly, against that same set, it is admitted.
	accepts(t, v, f)

	claimed := f.binding
	claimed.PolicyDigest = otherPolicy
	refuses(t, v, f.evidence, claimed, attest.ReasonBindingMismatch)
}

// setListingPolicies is defaultSet with one value per named policy digest, each
// naming theMeasurement. A set holding two is the policy rollout: one image,
// two policies, both admitted while a deployment moves between them.
func setListingPolicies(digests ...attest.PolicyDigest) attest.ReferenceValueSet {
	var set attest.ReferenceValueSet
	for _, d := range digests {
		digest := d
		set.Values = append(set.Values, attest.ReferenceValue{
			Vendor:            attest.VendorAMDSEVSNP,
			LaunchMeasurement: theMeasurement,
			MinimumTCB:        floorTCB,
			GuestPolicy:       permittedPolicy,
			PolicyDigest:      &digest,
		})
	}
	return set
}

// TestNoEvidenceIsRefused is a non-confidential VM: it has nothing to say, and
// it must be refused rather than treated as unknown.
func TestNoEvidenceIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	refuses(t, v, attest.Evidence{}, f.binding, attest.ReasonNoEvidence)
}

// TestCallerSuppliedBytesNotMatchingThePresentedKeyIsRefused is a replay: a
// genuine, authentic, in-policy report from a real measured platform, presented
// alongside a different public key. Without this check an attacker who
// intercepts one peer's evidence could bind it to a key it holds.
func TestCallerSuppliedBytesNotMatchingThePresentedKeyIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	// The same evidence, presented with someone else's key.
	other := newFixture(t, defaultConfig())
	refuses(t, v, f.evidence, other.binding, attest.ReasonBindingMismatch)
}

// TestUnrecognisedBindingContextIsRefused is ADR-0002's reservation doing its
// job. A peer claiming a context this verifier does not understand may be
// binding something into its evidence that this verifier cannot see, and
// admitting it would make the reserved field worth nothing.
func TestUnrecognisedBindingContextIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	// Control: v2 is understood and admitted.
	accepts(t, v, f)

	future := attest.BindingContext{}
	future[0] = 3
	binding := attest.Binding{PublicKey: f.binding.PublicKey, Context: future, PolicyDigest: thePolicy}
	evidence, err := f.platform.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}

	// The evidence is authentic and correctly bound to that key under that
	// context. It is refused anyway, on the version alone.
	refuses(t, v, evidence, binding, attest.ReasonUnknownBindingContext)
}

// TestAVersionOneBindingContextIsNoLongerAdmitted is the same reservation being
// spent, which is a refusal in the other direction.
//
// A v1 peer is not speaking a version from the future; it is speaking the one
// this verifier used to speak, and its evidence commits to no policy at all.
// Admitting it would let any peer skip the policy check by claiming the older
// context — the reserved field would have bought a version bump and nothing
// else. So a v1 peer is refused on the version, before the vendor's verifier
// is asked anything.
//
// The evidence here is genuine and genuinely bound under v1, which is what a
// peer running yesterday's tunneld actually presents.
func TestAVersionOneBindingContextIsNoLongerAdmitted(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	// Control: the same platform speaking v2 is admitted.
	accepts(t, v, f)

	old := attest.Binding{PublicKey: f.binding.PublicKey, Context: attest.BindingContextV1}
	evidence, err := f.platform.Acquire(context.Background(), old.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	refuses(t, v, evidence, old, attest.ReasonUnknownBindingContext)

	// And the detail says what a v1 peer is missing, because the operator on
	// the other end of it has a tunneld to rebuild.
	_, err = v.Verify(context.Background(), evidence, old)
	var r *attest.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if !strings.Contains(r.Detail(), "policy digest") {
		t.Errorf("the operator log does not say what v1 lacks: %s", r.LogString())
	}
}

// TestReservedBytesOfTheBindingContextAreNotIgnored covers the case a version
// byte alone would miss: a context claiming v2 but with a reserved byte set. If
// only the version byte were checked, a peer could smuggle a value past a
// verifier that never looked at it.
func TestReservedBytesOfTheBindingContextAreNotIgnored(t *testing.T) {
	f := newFixture(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	sneaky := attest.BindingContextV2
	sneaky[attest.BindingContextSize-1] = 1
	binding := attest.Binding{PublicKey: f.binding.PublicKey, Context: sneaky, PolicyDigest: thePolicy}
	evidence, err := f.platform.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	refuses(t, v, evidence, binding, attest.ReasonUnknownBindingContext)
}

// TestEveryRefusalLooksTheSameToACaller is the property a security reviewer
// asked for: an attacker who can provoke refusals cannot walk the reference
// value set one field at a time, because every refusal says the same thing.
func TestEveryRefusalLooksTheSameToACaller(t *testing.T) {
	f := newFixture(t, defaultConfig())
	debugging := defaultConfig()
	debugging.Policy = snpfake.Policy{SMT: true, Debug: true}
	debugger := newFixture(t, debugging)
	other := newFixture(t, defaultConfig())

	unknownContext := attest.BindingContext{}
	unknownContext[0] = 9

	cases := []struct {
		name     string
		set      attest.ReferenceValueSet
		fixture  *fixture
		evidence attest.Evidence
		binding  attest.Binding
		want     attest.Reason
	}{
		{"no evidence", defaultSet(), f, attest.Evidence{}, f.binding, attest.ReasonNoEvidence},
		{"measurement absent", setFor(otherMeasurement, floorTCB, permittedPolicy), f, f.evidence, f.binding, attest.ReasonMeasurementNotInSet},
		{"below TCB floor", setFor(theMeasurement, aboveTCB, permittedPolicy), f, f.evidence, f.binding, attest.ReasonTCBBelowFloor},
		{"policy mismatch", defaultSet(), debugger, debugger.evidence, debugger.binding, attest.ReasonPolicyMismatch},
		{"binding mismatch", defaultSet(), f, f.evidence, other.binding, attest.ReasonBindingMismatch},
		{"unknown binding context", defaultSet(), f, f.evidence, attest.Binding{PublicKey: f.binding.PublicKey, Context: unknownContext}, attest.ReasonUnknownBindingContext},
	}

	seen := map[attest.Reason]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := verification(t, tc.fixture, tc.set)
			refuses(t, v, tc.evidence, tc.binding, tc.want)
			seen[tc.want] = true
		})
	}
	if len(seen) != len(cases) {
		t.Errorf("the cases produced %d distinct reasons across %d cases; each must have its own", len(seen), len(cases))
	}
}

// TestASetThatCannotMeanWhatItsAuthorIntendedIsRejectedAtConstruction covers
// the two ways a set is wrong before any peer arrives.
//
// The empty set admits nobody, which is merely a mistake. The reference value
// with no launch measurement admits *everybody* — it names no image, so every
// authentic platform matches it — and that one does not announce itself: every
// handshake succeeds and nothing looks wrong. Both are refused at startup.
func TestASetThatCannotMeanWhatItsAuthorIntendedIsRejectedAtConstruction(t *testing.T) {
	f := newFixture(t, defaultConfig())
	verifier := verifierTrusting(t, f.platform)

	if _, err := attest.New(verifier, attest.ReferenceValueSet{}); err == nil {
		t.Error("an empty reference value set was accepted; want an error at construction")
	}

	wildcard := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:      attest.VendorAMDSEVSNP,
		MinimumTCB:  floorTCB,
		GuestPolicy: permittedPolicy,
	}}}
	if _, err := attest.New(verifier, wildcard); err == nil {
		t.Error("a reference value with no launch measurement was accepted; it would admit every authentic platform")
	}

	// Control: a set naming an image is accepted, and admits that image.
	v, err := attest.New(verifier, defaultSet())
	if err != nil {
		t.Fatalf("a well-formed set was rejected: %v", err)
	}
	accepts(t, v, f)
}

func setFor(measurement []byte, floor attest.TCB, policy attest.GuestPolicy) attest.ReferenceValueSet {
	return attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: measurement,
		MinimumTCB:        floor,
		GuestPolicy:       policy,
	}}}
}

func withMeasurement(cfg snpfake.Config, measurement []byte) snpfake.Config {
	cfg.LaunchMeasurement = measurement
	return cfg
}
