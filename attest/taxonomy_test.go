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

// TestEvidenceThatDoesNotParseIsRefused: attacker-supplied bytes reach the
// parser before anything else does, and the parser is not a place to be
// optimistic.
func TestEvidenceThatDoesNotParseIsRefused(t *testing.T) {
	f := newFixture(t, defaultConfig())
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
	f := newFixture(t, defaultConfig())
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
	f := newFixture(t, defaultConfig())
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
	f := newFixture(t, defaultConfig())
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
