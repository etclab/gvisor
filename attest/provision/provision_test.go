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

package provision_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/provision"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/verify"
)

// Every test here is offline. The vendor's key distribution service is the
// fake platform's own, and the one real report is ticket 01's captured one,
// used to show what would be asked for without asking.

var (
	chainCreatedAt     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	whenChainsAreValid = chainCreatedAt.Add(30 * 24 * time.Hour)

	platformTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	updatedTCB  = attest.TCB{Bootloader: 9, TEE: 0, SNP: 24, Microcode: 72}
	chipID      = bytes.Repeat([]byte{0x5A}, 64)
)

// capturedReport is the report ticket 01 read out of a real confidential guest
// on this host, whose chip and TCB are recorded in docs/snp/evidence.
const capturedReport = "../../docs/snp/evidence/report.bin"

func platform(t *testing.T, tcb attest.TCB) *snpfake.Platform {
	t.Helper()
	p, err := snpfake.New(snpfake.Config{TCB: tcb, ChipID: chipID, Policy: snpfake.Policy{SMT: true}, Now: chainCreatedAt})
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	return p
}

// report obtains a report from the platform the way the tsm acquirer does:
// the evidence bytes, with the platform's own bundled chain discarded, because
// on real hardware there is none.
func report(t *testing.T, p *snpfake.Platform) []byte {
	t.Helper()
	ev, err := p.Acquire(context.Background(), [attest.CallerSuppliedBytesSize]byte{})
	if err != nil {
		t.Fatalf("acquiring a report: %v", err)
	}
	return ev.Bytes
}

func options(p *snpfake.Platform, kds provision.Getter) provision.Options {
	return provision.Options{
		Getter:        kds,
		VendorRootPEM: p.VendorRootPEM(),
		ProductLine:   p.ProductLine(),
		Now:           whenChainsAreValid,
	}
}

func fetchAndWrite(t *testing.T, p *snpfake.Platform) (string, provision.Chain) {
	t.Helper()
	dir := t.TempDir()
	chain, err := provision.Fetch(context.Background(), report(t, p), options(p, p.KDS()))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := provision.Write(dir, chain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir, chain
}

func refused(t *testing.T, err error, wantInDetail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a refusal mentioning %q", wantInDetail)
	}
	if !errors.Is(err, provision.ErrChainRefused) {
		t.Errorf("error does not match ErrChainRefused: %v", err)
	}
	if !strings.Contains(err.Error(), wantInDetail) {
		t.Errorf("refusal %q does not mention %q", err, wantInDetail)
	}
	if !strings.Contains(err.Error(), "ADR-0005") {
		t.Errorf("refusal %q does not name ADR-0005, which is what points an operator at re-provisioning", err)
	}
}

// TestAProvisionedChainVerifiesThePlatformsEvidence is the control: the chain
// fetched for a platform, written and read back, is one a verifier accepts
// that platform's evidence with — which is the entire purpose of provisioning
// it.
func TestAProvisionedChainVerifiesThePlatformsEvidence(t *testing.T) {
	p := platform(t, platformTCB)
	dir, written := fetchAndWrite(t, p)

	if written.Vendor != attest.VendorAMDSEVSNP || written.ProductLine != p.ProductLine() {
		t.Errorf("chain is for %q/%q; want %q/%q", written.Vendor, written.ProductLine, attest.VendorAMDSEVSNP, p.ProductLine())
	}
	if !bytes.Equal(written.ChipID, chipID) || written.TCB != platformTCB {
		t.Errorf("chain recorded for chip %x at %+v; want %x at %+v", written.ChipID, written.TCB, chipID, platformTCB)
	}

	// The consumer side: the acquirer loads it for the platform's current
	// report and bundles it with evidence exactly as ticket 02's verifier
	// expects.
	raw := report(t, p)
	loaded, err := provision.LoadFor(dir, raw)
	if err != nil {
		t.Fatalf("LoadFor: %v", err)
	}
	if !bytes.Equal(loaded.Bytes, written.Bytes) {
		t.Fatal("the chain read back differs from the chain written")
	}
	v, err := verify.New(verify.Options{VendorRootPEM: p.VendorRootPEM(), ProductLine: p.ProductLine(), Now: whenChainsAreValid})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: bytes.Repeat([]byte{0xA5}, 48),
		MinimumTCB:        platformTCB,
		GuestPolicy:       attest.GuestPolicy{AllowSMT: true},
	}}}
	if _, err := v.Verify(context.Background(), attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: raw, Chain: loaded.Bytes}, set); err != nil {
		t.Fatalf("a verifier refused evidence carrying the provisioned chain: %v", err)
	}
}

// TestAChainThatDoesNotValidateIsNeverWritten is the acceptance criterion that
// a bad fetch fails at provisioning time rather than at a handshake. The fake
// service here belongs to a different platform: everything it serves is
// well-formed and roots correctly to *its* root, and none of it is for this
// chip.
func TestAChainThatDoesNotValidateIsNeverWritten(t *testing.T) {
	p := platform(t, platformTCB)
	other, err := snpfake.New(snpfake.Config{TCB: platformTCB, ChipID: bytes.Repeat([]byte{0x11}, 64), Now: chainCreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	// A service that serves the other platform's certificates at whatever URL
	// is asked for.
	impostor := &servesAnything{from: other}

	_, err = provision.Fetch(context.Background(), report(t, p), options(p, impostor))
	if err == nil {
		t.Fatal("a chain for another chip was accepted at provisioning time")
	}
	if !strings.Contains(err.Error(), "not written") {
		t.Errorf("error does not say the chain was not written: %v", err)
	}
}

// servesAnything is a key distribution service that answers every request
// with one platform's certificates, whatever chip or TCB was asked for.
type servesAnything struct{ from *snpfake.Platform }

func (s *servesAnything) Get(_ context.Context, url string) ([]byte, error) {
	if strings.HasSuffix(url, "/cert_chain") {
		return s.from.VendorRootPEM(), nil
	}
	return s.from.EndorsementKeyCertificate(), nil
}

// TestAStaleChainIsRefusedLocallyAndNamesTheADR is ADR-0005's consequence for
// the consumer: the platform's TCB was updated after the chain was provisioned,
// and the acquirer must refuse the chain rather than bundle it and let the
// peer discover the mismatch as "malformed evidence".
func TestAStaleChainIsRefusedLocallyAndNamesTheADR(t *testing.T) {
	before := platform(t, platformTCB)
	dir, _ := fetchAndWrite(t, before)

	// The same chip, after a TCB update.
	after := platform(t, updatedTCB)
	_, err := provision.LoadFor(dir, report(t, after))
	refused(t, err, "stale")
	if !strings.Contains(err.Error(), "malformed evidence") {
		t.Errorf("refusal does not name the symptom a peer would report: %v", err)
	}

	// And a peer really would refuse the pair as malformed evidence, with a
	// detail naming ADR-0005 — the operational symptom ticket 02 established.
	stale, err := provision.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v, err := verify.New(verify.Options{VendorRootPEM: after.VendorRootPEM(), ProductLine: after.ProductLine(), Now: whenChainsAreValid})
	if err != nil {
		t.Fatal(err)
	}
	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{Vendor: attest.VendorAMDSEVSNP, LaunchMeasurement: bytes.Repeat([]byte{0xA5}, 48), MinimumTCB: platformTCB, GuestPolicy: attest.GuestPolicy{AllowSMT: true}}}}
	_, err = v.Verify(context.Background(), attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: report(t, after), Chain: stale.Bytes}, set)
	if got := attest.ReasonOf(err); got != attest.ReasonMalformedEvidence {
		t.Fatalf("a peer refused the stale chain with %v; want %v", got, attest.ReasonMalformedEvidence)
	}
	var r *attest.Refusal
	errors.As(err, &r)
	if !strings.Contains(r.Detail(), "ADR-0005") {
		t.Errorf("the peer's refusal detail does not name ADR-0005: %s", r.LogString())
	}
}

// TestAChainForAnotherChipIsRefused: a config device moved between hosts.
func TestAChainForAnotherChipIsRefused(t *testing.T) {
	dir, _ := fetchAndWrite(t, platform(t, platformTCB))
	other, err := snpfake.New(snpfake.Config{TCB: platformTCB, ChipID: bytes.Repeat([]byte{0x11}, 64), Now: chainCreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provision.LoadFor(dir, report(t, other))
	refused(t, err, "chip")
}

// TestAMissingChainIsRefusedNotFetched is the fail-closed requirement. The
// consumer half cannot even be handed a service to fetch from, so the check
// here is that a missing chain is a refusal naming ADR-0005 and not an absence.
func TestAMissingChainIsRefusedNotFetched(t *testing.T) {
	p := platform(t, platformTCB)
	dir := t.TempDir()

	_, err := provision.LoadFor(dir, report(t, p))
	refused(t, err, "no certificate chain is provisioned")
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing chain surfaces as os.ErrNotExist, which is the one branch a consumer must not be able to take: %v", err)
	}

	// Metadata without the chain, and the chain without metadata, are each
	// refused too.
	_, chain := fetchAndWrite(t, p)
	half := t.TempDir()
	if err := provision.Write(half, chain); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(half, provision.ChainFileName))
	_, err = provision.LoadFor(half, report(t, p))
	refused(t, err, provision.ChainFileName)

	half = t.TempDir()
	if err := provision.Write(half, chain); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(half, provision.MetadataFileName))
	_, err = provision.LoadFor(half, report(t, p))
	refused(t, err, provision.MetadataFileName)
}

// TestMetadataThatDoesNotDescribeTheChainBesideItIsRefused: the metadata is
// what makes staleness detectable, so a metadata file left behind from a
// different provisioning run must not vouch for a chain it does not describe.
func TestMetadataThatDoesNotDescribeTheChainBesideItIsRefused(t *testing.T) {
	dirBefore, _ := fetchAndWrite(t, platform(t, platformTCB))
	dirAfter, _ := fetchAndWrite(t, platform(t, updatedTCB))

	mixed := t.TempDir()
	cp(t, filepath.Join(dirAfter, provision.MetadataFileName), filepath.Join(mixed, provision.MetadataFileName))
	cp(t, filepath.Join(dirBefore, provision.ChainFileName), filepath.Join(mixed, provision.ChainFileName))

	_, err := provision.Load(mixed)
	refused(t, err, "different provisioning runs")
}

// TestFetchAsksForExactlyTheCapturedPlatformsChain uses ticket 01's real
// report to show what a provisioning run on this host asks the key
// distribution service for: the VCEK for this chip at this TCB, on this
// product line, and the product's root chain — and nothing else. The service
// here answers nothing, so the fetch fails and writes nothing.
func TestFetchAsksForExactlyTheCapturedPlatformsChain(t *testing.T) {
	raw, err := os.ReadFile(capturedReport)
	if err != nil {
		t.Skipf("captured report not available: %v", err)
	}
	rec := &recordingService{}
	_, err = provision.Fetch(context.Background(), raw, provision.Options{Getter: rec})
	if err == nil {
		t.Fatal("Fetch succeeded against a service that serves nothing")
	}
	if len(rec.requested) != 1 {
		t.Fatalf("requested %d URLs before failing; want 1 (the VCEK): %v", len(rec.requested), rec.requested)
	}
	// docs/snp/evidence/report-decoded.txt: Genoa, chip 9b3716…5243,
	// reported TCB bootloader=9 tee=0 snp=23 microcode=72.
	want := "https://kdsintf.amd.com/vcek/v1/Genoa/9b371644fd3a24506777c8293ce0747804fc575468e695e4e937d4f1f541ede938fc9e79a26dbb1a328d5f2d73f10b5d02a4e3cb58eae3179e6ba923d2995243?blSPL=9&teeSPL=0&snpSPL=23&ucodeSPL=72"
	if rec.requested[0] != want {
		t.Errorf("asked for\n  %s\nwant\n  %s", rec.requested[0], want)
	}
}

// TestTheCapturedPlatformsProvisionedChainVerifiesItsReport runs only once
// the chain for this host has actually been provisioned and captured beside
// the report. Until then it is skipped, and says so; it is the offline record
// that provisioning was done and that the result verifies against AMD's real
// root.
func TestTheCapturedPlatformsProvisionedChainVerifiesItsReport(t *testing.T) {
	raw, err := os.ReadFile(capturedReport)
	if err != nil {
		t.Skipf("captured report not available: %v", err)
	}
	dir := filepath.Dir(capturedReport)
	if _, err := os.Stat(filepath.Join(dir, provision.ChainFileName)); err != nil {
		t.Skipf("no provisioned chain captured beside the report yet: %v", err)
	}
	chain, err := provision.LoadFor(dir, raw)
	if err != nil {
		t.Fatalf("the captured chain is not the one for the captured report: %v", err)
	}
	v, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The report's own measurement and policy; the point is authenticity
	// against AMD's real root, not admission.
	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: mustHex(t, "84aaf62f431f0a943944e10b0569c7c899bf5e9cfd0c6176af3f70033e241ac1e9d807f5605fd7dd08bf1bf1f09b5da5"),
		MinimumTCB:        chain.TCB,
		GuestPolicy:       attest.GuestPolicy{AllowSMT: true},
	}}}
	if _, err := v.Verify(context.Background(), attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: raw, Chain: chain.Bytes}, set); err != nil {
		var r *attest.Refusal
		errors.As(err, &r)
		t.Fatalf("the captured report with its provisioned chain does not verify against AMD's root: %s", r.LogString())
	}
}

type recordingService struct{ requested []string }

func (r *recordingService) Get(_ context.Context, url string) ([]byte, error) {
	r.requested = append(r.requested, url)
	return nil, errors.New("recording only")
}

func cp(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}
