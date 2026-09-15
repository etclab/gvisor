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

// Unit-level tests for the pieces of the TDX verifier that a verdict cannot
// reach: the collateral directory format, its expiry arithmetic, and the two
// ways a verifier can be constructed wrong.
//
// The verdicts themselves are tested where verdicts belong, against the
// recorded quotes and through the module's public entry point, in
// gvisor.dev/gvisor/attest's tdxevidence_test.go.
package verify_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/verify"
)

// recordedCollateral is the Intel collateral fetched once in ticket 17 and
// committed on this branch, with its transcript in FETCH.txt. It is also the
// worked example of the directory format the config device must carry.
const recordedCollateral = "../../docs/snp/evidence/tdx/collateral"

// recordedFMSPC and recordedCA are the platform every quote on this branch was
// produced by, as its PCK certificate names it.
const (
	recordedFMSPC = "00806f050000"
	recordedCA    = "platform"
)

// TestTheRecordedDirectoryIsTheFormatTheLoaderReads is the statement that the
// committed evidence and the code agree about what a config device carries. If
// the format ever changes, this is what says so before a guest finds out.
func TestTheRecordedDirectoryIsTheFormatTheLoaderReads(t *testing.T) {
	c, err := verify.LoadTDXCollateral(recordedCollateral, recordedFMSPC, recordedCA)
	if err != nil {
		t.Fatalf("loading the recorded collateral: %v", err)
	}
	if c.FMSPC != recordedFMSPC || c.CA != recordedCA {
		t.Errorf("loaded collateral for %s/%s, want %s/%s", c.FMSPC, c.CA, recordedFMSPC, recordedCA)
	}
	if got := c.EvaluationDataNumber(); got != 20 {
		t.Errorf("evaluation data number %d, want the 20 Intel served on 2026-09-08", got)
	}

	// The issuer chain arrives in a response header rather than in the body,
	// and go-tdx-guest looks it up by an exact key. A load that succeeded but
	// found no chain would fail much later, inside the library, as an
	// authenticity failure.
	for _, tc := range []struct {
		what string
		doc  verify.CollateralDocument
		key  string
	}{
		{"TCB info", c.TCBInfo, "Tcb-Info-Issuer-Chain"},
		{"quoting-enclave identity", c.QEIdentity, "Sgx-Enclave-Identity-Issuer-Chain"},
		{"PCK CRL", c.PCKCRL, "Sgx-Pck-Crl-Issuer-Chain"},
	} {
		if v := tc.doc.Header[tc.key]; len(v) != 1 || v[0] == "" {
			t.Errorf("the %s headers carry no %s; Intel sends that key in a different case, and it has to be canonicalised on the way in", tc.what, tc.key)
		}
	}
}

// TestTheEarliestExpiryIsWhatAnOperatorHasToActOn: the collateral is only as
// good as its soonest-expiring part, and an operator warned about anything else
// would re-provision too late.
func TestTheEarliestExpiryIsWhatAnOperatorHasToActOn(t *testing.T) {
	c, err := verify.LoadTDXCollateral(recordedCollateral, recordedFMSPC, recordedCA)
	if err != nil {
		t.Fatalf("loading the recorded collateral: %v", err)
	}
	earliest := c.EarliestExpiry()
	if earliest.What == "" || earliest.At.IsZero() {
		t.Fatalf("EarliestExpiry returned %+v; an operator warning with no name and no date is not a warning", earliest)
	}

	// Fresh a moment before, stale a moment after, and the message names the
	// part that went first.
	if err := c.CheckFresh(earliest.At.Add(-time.Second)); err != nil {
		t.Errorf("collateral one second before its earliest expiry is not fresh: %v", err)
	}
	err = c.CheckFresh(earliest.At.Add(time.Second))
	if err == nil {
		t.Fatal("collateral one second after its earliest expiry is still fresh")
	}
	if !strings.Contains(err.Error(), earliest.What) {
		t.Errorf("the staleness message %q does not name %q", err, earliest.What)
	}
}

// TestAnAbsentDocumentIsRefusedAndNamesTheDecision: every consumer-side failure
// has one remedy, and an operator reading any of them should be pointed at
// provisioning rather than at the peer.
func TestAnAbsentDocumentIsRefusedAndNamesTheDecision(t *testing.T) {
	entries, err := os.ReadDir(recordedCollateral)
	if err != nil {
		t.Fatalf("reading the recorded collateral: %v", err)
	}
	// One directory per document, each a complete copy with that one document
	// removed, so the only difference from a working directory is the absence.
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".body") && !strings.HasSuffix(name, ".headers") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, e := range entries {
				if e.IsDir() || e.Name() == name {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(recordedCollateral, e.Name()))
				if err != nil {
					t.Fatalf("copying %s: %v", e.Name(), err)
				}
				if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o644); err != nil {
					t.Fatalf("writing %s: %v", e.Name(), err)
				}
			}
			_, err := verify.LoadTDXCollateral(dir, recordedFMSPC, recordedCA)
			if err == nil {
				t.Fatalf("a directory missing %s loaded anyway", name)
			}
			if !errors.Is(err, verify.ErrCollateralRefused) {
				t.Errorf("the failure does not match ErrCollateralRefused: %v", err)
			}
			if !strings.Contains(err.Error(), "ADR-0005") {
				t.Errorf("the failure does not point at the provisioning decision: %v", err)
			}
		})
	}
}

// TestAnFMSPCFromAPeerCannotEscapeTheDirectory: the FMSPC and the CA are read
// out of a peer's own certificate and then put in a file name. A loader that
// took them on trust would let a peer choose which file the verifier reads.
func TestAnFMSPCFromAPeerCannotEscapeTheDirectory(t *testing.T) {
	for _, tc := range []struct{ name, fmspc, ca string }{
		{"traversal in the FMSPC", "../../../etc", recordedCA},
		{"a separator in the FMSPC", "00806f05/000", recordedCA},
		{"uppercase, which is not what the extension yields", "00806F050000", recordedCA},
		{"too short", "00806f0500", recordedCA},
		{"not hexadecimal", "00806f05zzzz", recordedCA},
		{"traversal in the CA", recordedFMSPC, "../platform"},
		{"a CA Intel does not operate", recordedFMSPC, "whatever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verify.LoadTDXCollateral(recordedCollateral, tc.fmspc, tc.ca); err == nil {
				t.Fatalf("LoadTDXCollateral(%q, %q) was allowed", tc.fmspc, tc.ca)
			} else if !errors.Is(err, verify.ErrCollateralRefused) {
				t.Errorf("the failure does not match ErrCollateralRefused: %v", err)
			}
		})
	}
}

// TestAVerifierWithNoCollateralDirectoryCannotBeBuilt: there is no useful
// default. A TDX verifier without collateral could only either refuse every
// peer or fetch, and the second is the one ADR-0005 exists to prevent.
func TestAVerifierWithNoCollateralDirectoryCannotBeBuilt(t *testing.T) {
	if _, err := verify.NewTDX(verify.TDXOptions{}); err == nil {
		t.Fatal("NewTDX with no CollateralDir was allowed")
	}
	if _, err := verify.NewTDX(verify.TDXOptions{CollateralDir: t.TempDir(), VendorRootPEM: []byte("not a certificate")}); err == nil {
		t.Fatal("NewTDX with a VendorRootPEM holding no certificate was allowed")
	}
}

// TestTheTDXVerifierSpeaksForIntel is the tag a dispatcher routes on.
func TestTheTDXVerifierSpeaksForIntel(t *testing.T) {
	v, err := verify.NewTDX(verify.TDXOptions{CollateralDir: recordedCollateral})
	if err != nil {
		t.Fatalf("NewTDX: %v", err)
	}
	if got := string(v.Vendor()); got != "intel-tdx" {
		t.Errorf("Vendor() is %q, want %q", got, "intel-tdx")
	}
}
