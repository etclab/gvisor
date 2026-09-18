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
	"context"
	"errors"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
)

// The taxonomy holds three reasons beyond the seven the design enumerates. They
// exist because a verifier must do something definite when evidence does not
// parse, when it comes from hardware nobody here implements, and when its chain
// is simply absent — and "something definite" must not be an acceptance, and
// must not be a reason that claims more than is known.
//
// A tenth was added by ticket 22, and it is the one reason here that is not a
// verdict on evidence at all: a peer that was admitted and then did not apply
// the policy pushed at it (docs/policy-push.md). The two tests at the foot of
// this file are what keeps that distinction from blurring — it has a sentence
// of its own, and nothing at this seam can produce it.

// TestEvidenceThatDoesNotParseIsRefused: attacker-supplied bytes reach the
// parser before anything else does, and the parser is not a place to be
// optimistic.
func TestEvidenceThatDoesNotParseIsRefused(t *testing.T) {
	f := newGuest(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	garbage := attest.Evidence{
		Vendor: attest.VendorAMDSEVSNP,
		Bytes:  []byte{0x01, 0x02, 0x03},
		Chain:  f.evidence.Chain,
	}
	refuses(t, v, garbage, f.binding, attest.ReasonMalformedEvidence)
}

// TestEvidenceFromAnUnimplementedVendorIsRefused: a verifier that guesses at
// the format of evidence whose vendor it does not know has turned itself into
// an attack surface for no benefit.
func TestEvidenceFromAnUnimplementedVendorIsRefused(t *testing.T) {
	f := newGuest(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	elsewhere := f.evidence
	elsewhere.Vendor = "intel-tdx"
	refuses(t, v, elsewhere, f.binding, attest.ReasonUnsupportedVendor)
}

// TestEvidenceBoundToNoPublicKeyIsRefused closes the case where a peer presents
// evidence but no identity. The binding of an absent key is still a definite
// value, so an attacker can acquire genuine evidence over it; without this
// check that attacker would be admitted as attested while presenting nothing to
// be attested about.
func TestEvidenceBoundToNoPublicKeyIsRefused(t *testing.T) {
	f := newGuest(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	keyless := attest.Binding{Context: attest.BindingContextV2, PolicyDigest: thePolicy}
	evidence, err := f.platform.Acquire(context.Background(), keyless.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	// The evidence really is bound to those bytes, so this is not a mismatch
	// the arithmetic catches — it is refused for having no key at all.
	refuses(t, v, evidence, keyless, attest.ReasonBindingMismatch)
}

// TestAMissingCertificateChainFailsClosedRatherThanFetching is ADR-0005's
// consequence made a test.
//
// The chain is provisioned onto the config device ahead of use, and a tunneld
// that finds it missing or stale must fail closed. The tempting alternative —
// fall back to fetching it from the vendor — would silently restore the
// availability dependency and the privacy leak that ADR-0005 removes, and would
// do it on the critical path of every handshake, where it is least visible.
//
// The assertion on the detail is the regression guard: if certificate fetching
// were ever re-enabled, the refusal would come from the getter that refuses
// network access rather than from the absent chain, and the reason alone would
// not tell the difference.
func TestAMissingCertificateChainFailsClosedRatherThanFetching(t *testing.T) {
	f := newGuest(t, defaultConfig())
	v := verification(t, f, defaultSet())

	// Control: the same evidence with its provisioned chain is accepted, which
	// is also the evidence that nothing was fetched to accept it.
	accepts(t, v, f)

	unprovisioned := attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: f.evidence.Bytes}
	refuses(t, v, unprovisioned, f.binding, attest.ReasonChainNotRooted)

	_, err := v.Verify(context.Background(), unprovisioned, f.binding)
	var r *attest.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if strings.Contains(r.Detail(), "refusing to fetch") {
		t.Errorf("verification tried to fetch a certificate: %s", r.LogString())
	}
}

// TestEveryReasonInTheTaxonomyHasASentenceOfItsOwn: reasons are typed so that
// an operator can read which check refused a peer, and two reasons that print
// the same sentence are one reason wearing two names.
//
// The end of the taxonomy is found by asking for the first reason that prints
// Reason(n), so that adding one here is adding one line in attest/refusal.go
// and nothing else — and so that a reason added with no sentence at all is
// found by the test rather than by an operator.
func TestEveryReasonInTheTaxonomyHasASentenceOfItsOwn(t *testing.T) {
	named := map[string]attest.Reason{}
	for r := attest.Reason(0); !strings.HasPrefix(r.String(), "Reason("); r++ {
		if other, taken := named[r.String()]; taken {
			t.Errorf("%v and %v both print %q", other, r, r.String())
		}
		named[r.String()] = r
	}
	// And it reaches the last of them. A reason declared after the first one
	// with no sentence would be invisible to the loop above, and invisible in
	// an operator's log for the same reason.
	for _, want := range []attest.Reason{attest.ReasonNone, attest.ReasonUnknownBindingContext, attest.ReasonPolicyNotApplied, attest.ReasonPolicyNotLive} {
		if _, ok := named[want.String()]; !ok {
			t.Errorf("the taxonomy stops before %v, which prints %q", want, want.String())
		}
	}
}

// TestNoVerdictOnEvidenceIsAReasonReachedAfterAdmission is the boundary the
// last two reasons share.
//
// Both are reached after a peer has been admitted — one when the policy pushed
// over the established tunnel was not applied, the other when the sandbox that
// applied it stopped enforcing it — and no [attest.Verifier] can return either:
// there is no policy at this seam, no peer to push one to, and nothing at all
// that goes on being true after the verdict. A verifier that started returning
// one of them would be claiming a peer had done something with a document it
// was never sent.
func TestNoVerdictOnEvidenceIsAReasonReachedAfterAdmission(t *testing.T) {
	f := newGuest(t, defaultConfig())
	v := verification(t, f, defaultSet())

	accepts(t, v, f)

	garbage := attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: []byte{0x01, 0x02, 0x03}, Chain: f.evidence.Chain}
	elsewhere := f.evidence
	elsewhere.Vendor = "intel-tdx"
	unprovisioned := attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: f.evidence.Bytes}
	for name, ev := range map[string]attest.Evidence{
		"no evidence at all":           {},
		"evidence that does not parse": garbage,
		"another vendor":               elsewhere,
		"no provisioned chain":         unprovisioned,
	} {
		_, err := v.Verify(context.Background(), ev, f.binding)
		got := attest.ReasonOf(err)
		for _, after := range []attest.Reason{attest.ReasonPolicyNotApplied, attest.ReasonPolicyNotLive} {
			if got == after {
				t.Errorf("%s was refused as %v; that reason is reached after admission and never here", name, got)
			}
		}
	}
}
