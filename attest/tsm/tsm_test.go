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

package tsm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/provision"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/tsm"
	"gvisor.dev/gvisor/attest/verify"
)

// Every test here is offline and needs no confidential VM. The platform is
// either the fake one, which mints test-signed evidence over whatever bytes it
// is handed, or ticket 01's captured artifacts: the report a real confidential
// guest on this host produced, and the certificate chain provisioned for it.

var (
	chainCreatedAt     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	whenChainsAreValid = chainCreatedAt.Add(30 * 24 * time.Hour)

	platformTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	updatedTCB  = attest.TCB{Bootloader: 9, TEE: 0, SNP: 24, Microcode: 72}
	chipID      = bytes.Repeat([]byte{0x5A}, 64)
)

// The captured artifacts: the report ticket 01 read out of a live confidential
// guest, and the chain ticket 15 provisioned for the platform that produced
// it.
const capturedDir = "../../docs/snp/evidence"

// capturedCallerSupplied is what ticket 01 wrote to inblob: 00 01 02 … 3f. The
// captured report carries exactly those bytes back, which is the mechanism
// ADR-0002's binding rides on, so a test replaying that report asks for them.
func capturedCallerSupplied() [attest.CallerSuppliedBytesSize]byte {
	var b [attest.CallerSuppliedBytesSize]byte
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// platform builds a fake SEV-SNP platform at a TCB.
func platform(t *testing.T, tcb attest.TCB) *snpfake.Platform {
	t.Helper()
	p, err := snpfake.New(snpfake.Config{TCB: tcb, ChipID: chipID, Policy: snpfake.Policy{SMT: true}, Now: chainCreatedAt})
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	return p
}

// reportInterfaceOf is a fake report interface backed by a fake platform: what
// is written to inblob is what the platform mints evidence over, and auxblob
// is empty, as it is on real hardware here.
func reportInterfaceOf(p *snpfake.Platform) *tsm.FakeReportInterface {
	return &tsm.FakeReportInterface{
		Provider: "sev_guest",
		Evidence: func(callerSupplied []byte) ([]byte, error) {
			var cs [attest.CallerSuppliedBytesSize]byte
			copy(cs[:], callerSupplied)
			ev, err := p.Acquire(context.Background(), cs)
			if err != nil {
				return nil, err
			}
			// Only the report. A real platform bundles no chain with it,
			// which is the whole reason one is provisioned.
			return ev.Bytes, nil
		},
	}
}

// provisionChainFor runs the operator's half against the fake platform's own
// key distribution service and returns the config device directory it wrote.
func provisionChainFor(t *testing.T, p *snpfake.Platform) string {
	t.Helper()
	dir := t.TempDir()
	ev, err := p.Acquire(context.Background(), [attest.CallerSuppliedBytesSize]byte{})
	if err != nil {
		t.Fatalf("acquiring a report to provision against: %v", err)
	}
	chain, err := provision.Fetch(context.Background(), ev.Bytes, provision.Options{
		Getter:        p.KDS(),
		VendorRootPEM: p.VendorRootPEM(),
		ProductLine:   p.ProductLine(),
		Now:           whenChainsAreValid,
	})
	if err != nil {
		t.Fatalf("provision.Fetch: %v", err)
	}
	if err := provision.Write(dir, chain); err != nil {
		t.Fatalf("provision.Write: %v", err)
	}
	return dir
}

// bindingFor is what a tunneld binds its evidence to: a key it just generated,
// and the v1 binding context.
func bindingFor(t *testing.T) attest.Binding {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return attest.Binding{PublicKey: spki, Context: attest.BindingContextV1}
}

// TestEvidenceIsProducedOverTheBindingAndAcceptedByAVerifier is the control,
// and it is the whole ticket in one test: a key is generated, the bytes
// [attest.Binding.CallerSuppliedBytes] produces for it are written to the
// platform in a single write, evidence comes back bound to them, the chain
// from the config device is bundled with it — and a verifier, the consumer
// half of the same seam, accepts the pair against that binding.
func TestEvidenceIsProducedOverTheBindingAndAcceptedByAVerifier(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatalf("tsm.NewOnFake: %v", err)
	}
	if a.Vendor() != attest.VendorAMDSEVSNP {
		t.Errorf("acquirer speaks for %q; want %q", a.Vendor(), attest.VendorAMDSEVSNP)
	}

	binding := bindingFor(t)
	want := binding.CallerSuppliedBytes()
	ev, err := a.Acquire(context.Background(), want)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// One write, of exactly the caller-supplied bytes, to inblob and nothing
	// else. A partial write is a different request (docs/snp-host-stack.md),
	// so this is the acceptance criterion rather than an implementation
	// detail.
	if len(iface.Writes) != 1 {
		t.Fatalf("the platform was written to %d times; want exactly one write: %+v", len(iface.Writes), iface.Writes)
	}
	if iface.Writes[0].Attr != "inblob" {
		t.Errorf("wrote to %q; want inblob", iface.Writes[0].Attr)
	}
	if !bytes.Equal(iface.Writes[0].Data, want[:]) {
		t.Errorf("wrote %x; want the binding's %x", iface.Writes[0].Data, want[:])
	}

	if ev.Vendor != attest.VendorAMDSEVSNP || !ev.Present() {
		t.Fatalf("evidence is %q and %d bytes", ev.Vendor, len(ev.Bytes))
	}
	if len(ev.Chain) == 0 {
		t.Fatal("no certificate chain was bundled with the evidence")
	}

	// The consumer half of the seam, on the evidence this producer just made.
	v, err := verify.New(verify.Options{VendorRootPEM: p.VendorRootPEM(), ProductLine: p.ProductLine(), Now: whenChainsAreValid})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := attest.New(v, attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		LaunchMeasurement: bytes.Repeat([]byte{0xA5}, 48),
		MinimumTCB:        platformTCB,
		GuestPolicy:       attest.GuestPolicy{AllowSMT: true},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verification.Verify(context.Background(), ev, binding); err != nil {
		var r *attest.Refusal
		errors.As(err, &r)
		t.Fatalf("a verifier refused the evidence this acquirer produced: %s", r.LogString())
	}

	// And the same evidence against a different key is refused, which is what
	// says the binding is real rather than incidental.
	if _, err := verification.Verify(context.Background(), ev, bindingFor(t)); attest.ReasonOf(err) != attest.ReasonBindingMismatch {
		t.Errorf("evidence was accepted against another key, with %v", attest.ReasonOf(err))
	}

	// Every request created — the startup probe's and this acquisition's — is
	// removed again, and no two share a name.
	if len(iface.Opened) != 2 || len(iface.Removed) != 2 {
		t.Errorf("opened %v and removed %v; want the startup probe's request and this acquisition's, each removed", iface.Opened, iface.Removed)
	}
	if iface.Opened[0] == iface.Opened[1] {
		t.Errorf("two requests shared the name %q; the second one's inblob would be the first one's evidence", iface.Opened[0])
	}
}

// TestTheEmptyCertificateTableIsRecordedRatherThanRefused is ticket 01's
// finding turned into behaviour: auxblob is empty here, no operator action
// fills it, and an acquirer must read it, say so, and carry on (ADR-0005).
func TestTheEmptyCertificateTableIsRecordedRatherThanRefused(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.LastObservation(); ok {
		t.Error("an acquirer that has acquired nothing reports an observation")
	}
	ev, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("an empty certificate table was treated as a failure: %v", err)
	}
	o, ok := a.LastObservation()
	if !ok {
		t.Fatal("no observation was recorded")
	}
	if o.CertificateTableBytes != 0 || o.CertificateTableError != "" {
		t.Errorf("recorded a %d-byte certificate table (%q); want an empty one", o.CertificateTableBytes, o.CertificateTableError)
	}
	if o.Provider != "sev_guest" || o.Vendor != attest.VendorAMDSEVSNP || o.EvidenceBytes != len(ev.Bytes) || o.Writes != 1 {
		t.Errorf("observation is %+v", o)
	}
	line := o.String()
	for _, want := range []string{"certificate table is empty", "not an error", "ADR-0005"} {
		if !strings.Contains(line, want) {
			t.Errorf("the operator line does not mention %q:\n  %s", want, line)
		}
	}

	// A kernel that does not expose the attribute at all is the same kind of
	// fact, and equally not a failure: nothing here would have used it.
	iface.CertificateTableErr = os.ErrNotExist
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err != nil {
		t.Fatalf("an unreadable certificate table was treated as a failure: %v", err)
	}
	o, _ = a.LastObservation()
	if o.CertificateTableError == "" {
		t.Error("an unreadable certificate table was not recorded")
	}
}

// TestTheChainComesFromTheConfigDeviceEvenWhenThePlatformOffersOne: ADR-0005
// says where the chain comes from, and it is not the platform. A host that
// somehow populated auxblob would still not be the source, because a verifier
// is configured to expect the provisioned one and because a platform-supplied
// chain is exactly the dependency that cannot be relied on.
func TestTheChainComesFromTheConfigDeviceEvenWhenThePlatformOffersOne(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	iface.CertificateTable = bytes.Repeat([]byte{0xEE}, 128)
	dir := provisionChainFor(t, p)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: dir}, iface)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err != nil {
		t.Fatal(err)
	}
	provisioned, err := os.ReadFile(filepath.Join(dir, provision.ChainFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.Chain, provisioned) {
		t.Error("the bundled chain is not the one on the config device")
	}
	if o, _ := a.LastObservation(); o.CertificateTableBytes != 128 {
		t.Errorf("the platform's own table was not recorded: %+v", o)
	}
}

// TestAMissingChainFailsClosedAndNothingIsFetched is the fail-closed
// requirement. There is no getter to hand this side of the design, so what is
// checked is that the refusal is a refusal — not an absence a caller could
// step over — and that it points at provisioning.
func TestAMissingChainFailsClosedAndNothingIsFetched(t *testing.T) {
	p := platform(t, platformTCB)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: t.TempDir()}, reportInterfaceOf(p))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil {
		t.Fatal("evidence was produced with no certificate chain to bundle")
	}
	if !errors.Is(err, provision.ErrChainRefused) {
		t.Errorf("a missing chain is not a chain refusal: %v", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing chain surfaces as os.ErrNotExist, which is the one branch a caller must not be able to take: %v", err)
	}
	if !strings.Contains(err.Error(), "ADR-0005") {
		t.Errorf("the refusal does not point at provisioning: %v", err)
	}

	// And an acquirer with nowhere to read a chain from cannot be built at
	// all, so the failure lands at startup rather than at the first peer.
	if _, err := tsm.New(tsm.Options{}); err == nil || !strings.Contains(err.Error(), "ADR-0005") {
		t.Errorf("an acquirer with no chain directory was built: %v", err)
	}
}

// TestAStaleChainFailsClosed: the platform's TCB moved after the chain was
// provisioned, so the chain is no longer the one for its evidence. Bundling it
// anyway would surface at the peer as malformed evidence about a healthy
// platform, which is the confusing direction; this is the last place the
// failure can be pointed at re-provisioning.
func TestAStaleChainFailsClosed(t *testing.T) {
	dir := provisionChainFor(t, platform(t, platformTCB))
	after := platform(t, updatedTCB)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: dir}, reportInterfaceOf(after))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil {
		t.Fatal("a stale chain was bundled with evidence")
	}
	if !errors.Is(err, provision.ErrChainRefused) || !strings.Contains(err.Error(), "stale") {
		t.Errorf("a stale chain was not refused as stale: %v", err)
	}
}

// TestAPlatformThatDoesNotEchoTheCallerSuppliedBytesIsRefused. The binding is
// the platform copying those bytes into the evidence verbatim; a platform that
// returns evidence over anything else has bound nothing, and saying so here
// costs a peer an unexplained binding refusal.
func TestAPlatformThatDoesNotEchoTheCallerSuppliedBytesIsRefused(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	iface.Evidence = func([]byte) ([]byte, error) {
		var other [attest.CallerSuppliedBytesSize]byte
		other[0] = 0x01
		ev, err := p.Acquire(context.Background(), other)
		if err != nil {
			return nil, err
		}
		return ev.Bytes, nil
	}
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil || !strings.Contains(err.Error(), "binds nothing") {
		t.Fatalf("evidence over other bytes was accepted: %v", err)
	}
}

// TestARacingWriterIsRefused. The request directory is this acquirer's own, so
// this should be impossible; the generation counter is the kernel's way of
// saying it was not, and an acquirer that ignored it could return evidence
// bound to somebody else's key.
func TestARacingWriterIsRefused(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	iface.RacingWriter = true
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil || !strings.Contains(err.Error(), "another writer") {
		t.Fatalf("a racing writer went undetected: %v", err)
	}
}

// TestAnUnimplementedPlatformIsRefusedAtStartup: the report interface is
// vendor-neutral, so it answers on hardware whose evidence this module cannot
// read. Guessing at the format of evidence whose vendor is unknown is how a
// parser becomes an attack surface.
func TestAnUnimplementedPlatformIsRefusedAtStartup(t *testing.T) {
	iface := reportInterfaceOf(platform(t, platformTCB))
	iface.Provider = "tdx_guest"
	_, err := tsm.NewOnFake(tsm.Options{ChainDir: t.TempDir()}, iface)
	if err == nil || !strings.Contains(err.Error(), "tdx_guest") {
		t.Fatalf("an acquirer was built for a platform it cannot read: %v", err)
	}
}

// TestNoReportInterfaceIsRefusedAtStartup exercises the real configfs path:
// a guest that is not confidential, or one where configfs is not mounted and
// the guest driver is not loaded, has no directory to create a request in. A
// tunneld that cannot produce evidence has nothing to offer a peer, so this is
// a refusal to start rather than a first-handshake failure.
func TestNoReportInterfaceIsRefusedAtStartup(t *testing.T) {
	_, err := tsm.New(tsm.Options{ChainDir: t.TempDir(), ReportDir: filepath.Join(t.TempDir(), "no", "report", "interface")})
	if err == nil {
		t.Fatal("an acquirer was built with no report interface to acquire from")
	}
	if !strings.Contains(err.Error(), "not a confidential guest") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestTheCapturedGuestsEvidenceIsBundledWithItsProvisionedChain drives the
// acquisition sequence over the artifacts of a real run: the report ticket 01
// read out of a live confidential guest on this host, and the chain ticket 15
// provisioned for the platform that produced it. Nothing is faked but the
// kernel.
func TestTheCapturedGuestsEvidenceIsBundledWithItsProvisionedChain(t *testing.T) {
	report, err := os.ReadFile(filepath.Join(capturedDir, "report.bin"))
	if err != nil {
		t.Skipf("captured report not available: %v", err)
	}
	chain, err := os.ReadFile(filepath.Join(capturedDir, provision.ChainFileName))
	if err != nil {
		t.Skipf("no provisioned chain captured beside the report: %v", err)
	}
	iface := &tsm.FakeReportInterface{
		Provider: "sev_guest",
		Evidence: func([]byte) ([]byte, error) { return report, nil },
	}
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: capturedDir}, iface)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := a.Acquire(context.Background(), capturedCallerSupplied())
	if err != nil {
		t.Fatalf("Acquire over the captured platform's artifacts: %v", err)
	}
	if !bytes.Equal(ev.Bytes, report) || !bytes.Equal(ev.Chain, chain) {
		t.Error("the bundle is not the captured report with the captured chain")
	}
	o, _ := a.LastObservation()
	// docs/snp-host-stack.md: 1184 bytes of report, an empty auxblob.
	if o.EvidenceBytes != 1184 || o.CertificateTableBytes != 0 || o.Writes != 1 {
		t.Errorf("observation is %+v; want 1184 bytes of evidence, an empty certificate table and one write", o)
	}
	// docs/snp/evidence/certificate-chain.json: chip 9b3716…5243 at TCB
	// bootloader=9 tee=0 snp=23 microcode=72.
	if !strings.HasPrefix(o.ChainChipID, "9b371644") || o.ChainTCB != platformTCB {
		t.Errorf("chain recorded for chip %s at %+v", o.ChainChipID, o.ChainTCB)
	}
	if _, err := hex.DecodeString(o.ChainChipID); err != nil {
		t.Errorf("chip identity is not hexadecimal: %v", err)
	}
}

// TestTheCapturedGuestsChainIsRefusedForAnotherPlatform: the captured chain is
// for one chip, and the fake platform is another. A config device carried
// between hosts fails closed.
func TestTheCapturedGuestsChainIsRefusedForAnotherPlatform(t *testing.T) {
	if _, err := os.Stat(filepath.Join(capturedDir, provision.ChainFileName)); err != nil {
		t.Skipf("no provisioned chain captured: %v", err)
	}
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: capturedDir}, reportInterfaceOf(platform(t, platformTCB)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil || !errors.Is(err, provision.ErrChainRefused) || !strings.Contains(err.Error(), "chip") {
		t.Fatalf("another platform's chain was bundled: %v", err)
	}
}

// TestARequestNameAlreadyTakenIsSteppedOver: a directory left behind by a
// crashed process with this one's process identifier must not be reused, or
// this acquisition would inherit whatever was written to its inblob.
func TestARequestNameAlreadyTakenIsSteppedOver(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	iface.Taken = map[string]bool{}
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	// The name the next acquisition would pick, occupied by a corpse.
	next := nextRequestName(t, iface)
	iface.Taken[next] = true
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if got := iface.Opened[len(iface.Opened)-1]; got == next {
		t.Errorf("reused the occupied request %q", got)
	}
	if !iface.Taken[next] {
		t.Error("the occupied request was removed by an acquisition that does not own it")
	}
}

// nextRequestName is the name the acquirer's next acquisition will try, worked
// out from the one its startup probe used.
func nextRequestName(t *testing.T, iface *tsm.FakeReportInterface) string {
	t.Helper()
	if len(iface.Opened) == 0 {
		t.Fatal("the acquirer opened no request while probing")
	}
	last := iface.Opened[len(iface.Opened)-1]
	i := strings.LastIndex(last, "-")
	if i < 0 {
		t.Fatalf("request name %q has no sequence number", last)
	}
	return last[:i+1] + "1"
}

// TestTheLiveGuestsEvidenceIsBoundToTheKeyItWasAcquiredFor is the offline
// record that this acquirer ran on real silicon and that what came back is
// bound to the key that was generated for it.
//
// docs/snp/evidence/ticket04 holds one acquisition from the confidential guest
// of docs/snp-host-stack.md: the report, the public key it was acquired for,
// and the caller-supplied bytes that were written. Replaying it through the
// acquisition sequence is what checks the binding, because an acquisition
// whose evidence does not carry the bytes it handed the platform is refused —
// so this passing means the report's REPORT_DATA really is
// SHA-512(that key ‖ the v1 context), computed by ADR-0002's own code against
// bytes a machine produced.
//
// It checks nothing about authenticity. That signature belongs to AMD's root
// and to a different ticket; this one produces and bundles.
func TestTheLiveGuestsEvidenceIsBoundToTheKeyItWasAcquiredFor(t *testing.T) {
	const dir = capturedDir + "/ticket04"
	evidence, err := os.ReadFile(filepath.Join(dir, "evidence.bin"))
	if err != nil {
		t.Skipf("no evidence captured from a live guest: %v", err)
	}
	publicKey, err := os.ReadFile(filepath.Join(dir, "public-key.der"))
	if err != nil {
		t.Fatalf("evidence was captured without the key it is bound to: %v", err)
	}
	binding := attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1}

	iface := &tsm.FakeReportInterface{
		Provider: "sev_guest",
		Evidence: func([]byte) ([]byte, error) { return evidence, nil },
	}
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: capturedDir}, iface)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := a.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("the evidence a live guest produced is not bound to the key captured with it: %v", err)
	}
	if !bytes.Equal(ev.Bytes, evidence) {
		t.Error("the bundle does not carry the evidence the guest produced")
	}

	// The bytes recorded beside it are the ones the binding produces, which is
	// what says the captured run used ADR-0002 rather than something of its
	// own.
	want := binding.CallerSuppliedBytes()
	recorded, err := os.ReadFile(filepath.Join(dir, "caller-supplied.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recorded, want[:]) {
		t.Errorf("the captured caller-supplied bytes are %x; the binding produces %x", recorded, want[:])
	}

	// And the same evidence against another key is refused, which is what
	// makes the first result mean something.
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err == nil {
		t.Error("a live guest's evidence was accepted as bound to a key it was never acquired for")
	}
}

// TestARefusedAcquisitionStillRemovesItsRequest: the request directory is
// removed whichever way an acquisition ends. Only sixteen names are tried
// before the acquirer refuses outright, so a request left behind on refusal
// would turn a transient refusal into a permanent one.
func TestARefusedAcquisitionStillRemovesItsRequest(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	iface.RacingWriter = true
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err == nil {
		t.Fatal("an acquisition raced by another writer was accepted")
	}
	if len(iface.Opened) != len(iface.Removed) {
		t.Errorf("opened %v but removed only %v", iface.Opened, iface.Removed)
	}
}

// TestARequestThatCannotBeRemovedIsAnError: a leaked request is reported, not
// shrugged off, so an operator learns of it before the sixteenth one.
func TestARequestThatCannotBeRemovedIsAnError(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	// Control: the same acquisition succeeds when removal works.
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err != nil {
		t.Fatal(err)
	}
	iface.RemoveErr = errors.New("fake: rmdir: device or resource busy")
	if _, err := a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes()); err == nil || !strings.Contains(err.Error(), "removing the request") {
		t.Errorf("a request that could not be removed was not reported: %v", err)
	}
}

// TestAPlatformRejectionNamesThePrivilegeFloor: privlevel is left at the
// kernel's default, so on a guest above VMPL0 the platform rejects the
// request; the refusal says what the floor was, which is the one fact an
// operator needs.
func TestAPlatformRejectionNamesThePrivilegeFloor(t *testing.T) {
	p := platform(t, platformTCB)
	iface := reportInterfaceOf(p)
	a, err := tsm.NewOnFake(tsm.Options{ChainDir: provisionChainFor(t, p)}, iface)
	if err != nil {
		t.Fatal(err)
	}
	iface.RejectWrite = errors.New("fake: the platform rejected the request: invalid argument")
	iface.PrivlevelFloor = "2"
	_, err = a.Acquire(context.Background(), bindingFor(t).CallerSuppliedBytes())
	if err == nil || !strings.Contains(err.Error(), "privlevel_floor is 2") {
		t.Errorf("a platform rejection did not name the privilege floor: %v", err)
	}
}
