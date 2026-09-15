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

// Tests for the dispatcher: the piece that lets a second vendor exist without
// anything above the seam learning that there is one.
//
// The verifiers here are stubs. Whether a vendor's evidence is authentic is
// tested against real evidence elsewhere; what is tested here is routing, and a
// stub is the only thing that can show a dispatcher handed evidence to the
// wrong verifier, because a real one would refuse it for its own reasons.
package attest_test

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/attest"
)

// stubVerifier accepts everything and writes down that it was asked.
type stubVerifier struct {
	vendor attest.Vendor
	asked  int
}

func (s *stubVerifier) Vendor() attest.Vendor { return s.vendor }

func (s *stubVerifier) Verify(_ context.Context, ev attest.Evidence, _ attest.ReferenceValueSet) (attest.Attested, error) {
	s.asked++
	return attest.Attested{Vendor: ev.Vendor}, nil
}

// TestADispatcherRoutesOnTheEvidencesVendor, and on nothing else. In
// particular it does not offer evidence to a verifier that did not claim its
// vendor: a parser reached only by evidence claiming its own vendor is a parser
// an attacker cannot pick.
func TestADispatcherRoutesOnTheEvidencesVendor(t *testing.T) {
	amd := &stubVerifier{vendor: attest.VendorAMDSEVSNP}
	intel := &stubVerifier{vendor: attest.VendorIntelTDX}
	d, err := attest.Dispatch(amd, intel)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	set := attest.ReferenceValueSet{}
	for _, vendor := range []attest.Vendor{attest.VendorAMDSEVSNP, attest.VendorIntelTDX} {
		attested, err := d.Verify(context.Background(), attest.Evidence{Vendor: vendor, Bytes: []byte{1}}, set)
		if err != nil {
			t.Fatalf("%s evidence was refused: %v", vendor, err)
		}
		if attested.Vendor != vendor {
			t.Errorf("%s evidence came back as %s", vendor, attested.Vendor)
		}
	}
	if amd.asked != 1 || intel.asked != 1 {
		t.Errorf("the AMD verifier was asked %d times and the Intel one %d; each should have been asked exactly once about its own vendor", amd.asked, intel.asked)
	}

	_, err = d.Verify(context.Background(), attest.Evidence{Vendor: "some-other-vendor", Bytes: []byte{1}}, set)
	if got := attest.ReasonOf(err); got != attest.ReasonUnsupportedVendor {
		t.Errorf("evidence from an unimplemented vendor was refused with %v, want %v", got, attest.ReasonUnsupportedVendor)
	}
	if amd.asked != 1 || intel.asked != 1 {
		t.Errorf("evidence from an unimplemented vendor was offered to a verifier anyway (AMD asked %d, Intel asked %d)", amd.asked, intel.asked)
	}
}

// TestADispatcherNamesEveryVendorItSpeaksFor. Returning one member's vendor
// would be a lie an operator reads in a log; the composite is not an
// [attest.Evidence] vendor anything will ever match, and is not meant to be.
func TestADispatcherNamesEveryVendorItSpeaksFor(t *testing.T) {
	// Given out of order, to show the name does not depend on the order the
	// verifiers were handed over.
	d, err := attest.Dispatch(&stubVerifier{vendor: attest.VendorIntelTDX}, &stubVerifier{vendor: attest.VendorAMDSEVSNP})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if got, want := d.Vendor(), attest.Vendor("amd-sev-snp+intel-tdx"); got != want {
		t.Errorf("Vendor() is %q, want %q", got, want)
	}
}

// TestADispatcherThatCouldNotDecideIsRefusedAtConstruction. Each of these is a
// configuration mistake whose only symptom at run time would be a peer refused
// for a reason that sounds like the peer's fault.
func TestADispatcherThatCouldNotDecideIsRefusedAtConstruction(t *testing.T) {
	for _, tc := range []struct {
		name      string
		verifiers []attest.Verifier
	}{
		{"no verifiers at all", nil},
		{"two verifiers for one vendor", []attest.Verifier{
			&stubVerifier{vendor: attest.VendorAMDSEVSNP},
			&stubVerifier{vendor: attest.VendorAMDSEVSNP},
		}},
		{"a verifier that names no vendor", []attest.Verifier{&stubVerifier{}}},
		{"a nil verifier", []attest.Verifier{&stubVerifier{vendor: attest.VendorAMDSEVSNP}, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := attest.Dispatch(tc.verifiers...); err == nil {
				t.Fatal("Dispatch was allowed")
			}
		})
	}
}
