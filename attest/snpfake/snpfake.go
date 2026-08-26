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

// Package snpfake is a fake SEV-SNP platform: it mints evidence with arbitrary
// launch measurements, TCB levels, guest policies and caller-supplied bytes,
// signed by a test certificate chain.
//
// It is not a mock of verification. The evidence it produces is a real SEV-SNP
// report in AMD's ABI format, signed with a real ECDSA P-384 key, carrying a
// real X.509 chain with AMD's KDS certificate extensions — built by
// go-sev-guest's own test signing rather than by anything invented here. A
// verifier handed this evidence runs the same parsing, the same chain
// validation and the same predicates it runs against hardware. What is fake is
// the platform, and only the platform; substituting it happens at the vendor
// seam, below everything worth testing.
//
// This is what lets the whole verification path be exercised with no
// confidential VM and no network.
//
// It is not a _test package because tunneld's own tests will inject it through
// a constructor (ticket 09), and a _test package cannot be imported. It must
// not be linked into a production binary: go-sev-guest's test signing pulls in
// the standard testing package and registers command-line flags at init.
package snpfake

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"gvisor.dev/gvisor/attest"
)

// DefaultProductLine is the AMD product line the fake platform claims. It
// matches the host in docs/snp-host-stack.md.
const DefaultProductLine = "Milan"

// DefaultTCB is the TCB level the fake platform reports if a config does not
// choose one. It is the level the host in docs/snp-host-stack.md actually
// produced, recorded there as a fact about that machine rather than as a
// recommended floor.
var DefaultTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}

// Policy is the guest policy the fake platform launched with — what its
// evidence claims, as distinct from [attest.GuestPolicy], which is what a
// reference value permits. The two are separate types because reading a claim
// as a permission, or the reverse, is the mistake worth making impossible.
type Policy struct {
	// ABIMajor and ABIMinor are the SNP ABI version the guest demanded.
	ABIMajor uint8
	ABIMinor uint8

	// SMT is set if the guest was launched allowing symmetric multithreading.
	SMT bool

	// MigrationAgent is set if the guest may have a migration agent.
	MigrationAgent bool

	// Debug is set if the host may decrypt the guest for debugging. A platform
	// with this set is the one a reference value that does not permit debugging
	// has to refuse.
	Debug bool

	// SingleSocket is set if the guest may only be active on a single socket.
	SingleSocket bool
}

// Config describes the platform to fake.
type Config struct {
	// ProductLine is the AMD product line. Empty means [DefaultProductLine].
	ProductLine string

	// LaunchMeasurement is the measurement the platform's evidence attests. It
	// is padded or truncated to the report's measurement field width. Empty
	// means a fixed non-zero value, so that a report never accidentally attests
	// all zeros.
	LaunchMeasurement []byte

	// TCB is the trusted computing base level the platform reports. It is
	// reported coherently: the same level appears as the current, reported,
	// committed and launch TCB and in the endorsement key certificate, because
	// a real platform's report that disagreed with itself would be refused as
	// malformed and would test nothing.
	//
	// The zero value means [DefaultTCB]. A platform genuinely at TCB zero is
	// not a case worth being able to express by accident.
	TCB attest.TCB

	// Policy is the guest policy the platform launched with.
	Policy Policy

	// ChipID identifies the chip. Empty means a fixed value. It is written both
	// into the report and into the endorsement key certificate, as a real
	// platform's would be.
	ChipID []byte

	// Now is the creation time of the fake certificate chain. Zero means a
	// fixed instant, so that a test's outcome does not depend on the day it
	// runs.
	Now time.Time
}

// A Platform is a fake SEV-SNP platform. It implements [attest.Acquirer], which
// is the producer half of the vendor seam; the acquirer that talks to real
// hardware through the platform's vendor-neutral report interface is
// gvisor.dev/gvisor/attest/tsm.
type Platform struct {
	cfg         Config
	productLine string
	signer      *sevtest.AmdSigner
	chain       []byte
	rootPEM     []byte
	tcb         kds.TCBParts
	measurement [abi.MeasurementSize]byte
	chipID      [abi.ChipIDSize]byte
	fms         uint32
}

var _ attest.Acquirer = (*Platform)(nil)

// fixedNow is the instant a fake chain is created at when a config does not
// choose one.
var fixedNow = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// New builds a fake platform from cfg.
func New(cfg Config) (*Platform, error) {
	p := &Platform{cfg: cfg, productLine: cfg.ProductLine}
	if p.productLine == "" {
		p.productLine = DefaultProductLine
	}
	tcb := cfg.TCB
	if tcb == (attest.TCB{}) {
		tcb = DefaultTCB
	}
	p.tcb = kds.TCBParts{BlSpl: tcb.Bootloader, TeeSpl: tcb.TEE, SnpSpl: tcb.SNP, UcodeSpl: tcb.Microcode}

	if len(cfg.LaunchMeasurement) == 0 {
		for i := range p.measurement {
			p.measurement[i] = 0xA5
		}
	} else {
		copy(p.measurement[:], cfg.LaunchMeasurement)
	}
	if len(cfg.ChipID) == 0 {
		for i := range p.chipID {
			p.chipID[i] = 0x5A
		}
	} else {
		copy(p.chipID[:], cfg.ChipID)
	}

	now := cfg.Now
	if now.IsZero() {
		now = fixedNow
	}
	tcbVersion, err := kds.ComposeTCBParts(p.tcb)
	if err != nil {
		return nil, fmt.Errorf("snpfake: TCB %+v is not representable: %w", tcb, err)
	}
	if p.fms, err = productFms(p.productLine); err != nil {
		return nil, err
	}
	productName := p.productLine + "-B0"
	b := &sevtest.AmdSignerBuilder{
		Keys:             sevtest.DefaultAmdKeys(),
		ProductName:      productName,
		CSPID:            "gvisor-attest-snpfake",
		ArkCreationTime:  now,
		AskCreationTime:  now,
		AsvkCreationTime: now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		HWID:             p.chipID,
		TCB:              tcbVersion,
		// The builder's own HWID and TCB fields do not reach the endorsement
		// key certificate's KDS extensions, and a verifier reads the TCB and
		// the chip ID from exactly there. Setting them explicitly is what makes
		// the fake chain agree with the fake report.
		VcekCustom: sevtest.CertOverride{
			Extensions: sevtest.CustomExtensions(p.tcb, p.chipID[:], "gvisor-attest-snpfake", productName),
		},
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		return nil, fmt.Errorf("snpfake: building the test certificate chain: %w", err)
	}
	p.signer = signer

	chain, err := signer.CertTableBytes()
	if err != nil {
		return nil, fmt.Errorf("snpfake: serializing the certificate table: %w", err)
	}
	p.chain = chain

	// The KDS cert_chain format: ASK then ARK, PEM encoded. This is what ticket
	// 15 provisions onto the config device and what a verifier is configured
	// with, so the fake emits the same thing rather than a shape of its own.
	var root bytes.Buffer
	if err := pem.Encode(&root, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ask.Raw}); err != nil {
		return nil, fmt.Errorf("snpfake: encoding the ASK: %w", err)
	}
	if err := pem.Encode(&root, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ark.Raw}); err != nil {
		return nil, fmt.Errorf("snpfake: encoding the ARK: %w", err)
	}
	p.rootPEM = root.Bytes()
	return p, nil
}

// Vendor implements [attest.Acquirer].
func (p *Platform) Vendor() attest.Vendor { return attest.VendorAMDSEVSNP }

// Acquire implements [attest.Acquirer]. It returns evidence over the given
// caller-supplied bytes, which come back in the report verbatim exactly as
// hardware returns them.
//
// The certificate chain is bundled with the evidence, as ADR-0005 requires and
// as gvisor.dev/gvisor/attest/tsm does from the config device. The platform's
// own certificate table is empty on the host this was built against and no
// operator action fills it, so a chain that arrived with the evidence is the
// only kind there is.
func (p *Platform) Acquire(_ context.Context, callerSupplied [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	raw, err := p.report(callerSupplied)
	if err != nil {
		return attest.Evidence{}, err
	}
	return attest.Evidence{
		Vendor: attest.VendorAMDSEVSNP,
		Bytes:  raw,
		Chain:  append([]byte(nil), p.chain...),
	}, nil
}

// AcquireForged returns evidence carrying a launch measurement the platform
// never signed over: a genuine signature, from a genuine chain, on a report
// that has been rewritten to say something else.
//
// This is the shape an attacker takes when it holds a real report of one image
// and wants to be admitted as another. It is not a broken report — it parses,
// its chain is complete and roots correctly — so a verifier that stopped at
// parsing and chain building would admit it. Only checking the signature over
// the bytes actually presented catches it.
//
// The forgery is done by reserializing the parsed report with a different
// measurement and the original signature, so this carries no knowledge of where
// any field sits in AMD's ABI layout.
func (p *Platform) AcquireForged(ctx context.Context, callerSupplied [attest.CallerSuppliedBytesSize]byte, forgedMeasurement []byte) (attest.Evidence, error) {
	ev, err := p.Acquire(ctx, callerSupplied)
	if err != nil {
		return attest.Evidence{}, err
	}
	report, err := abi.ReportToProto(ev.Bytes)
	if err != nil {
		return attest.Evidence{}, fmt.Errorf("snpfake: reparsing the report to forge it: %w", err)
	}
	forged := make([]byte, abi.MeasurementSize)
	copy(forged, forgedMeasurement)
	report.Measurement = forged
	raw, err := abi.ReportToAbiBytes(report)
	if err != nil {
		return attest.Evidence{}, fmt.Errorf("snpfake: reserializing the forged report: %w", err)
	}
	ev.Bytes = raw
	return ev, nil
}

// VendorRootPEM returns this fake platform's root of trust in the format
// verify.Options takes: the ASK and ARK, PEM encoded, as AMD's key distribution
// service serves them.
//
// A verifier configured with a *different* root — another fake platform's, or
// the real AMD roots go-sev-guest embeds — refuses this platform's evidence,
// which is how the chain-does-not-root refusal is tested without inventing a
// broken certificate.
func (p *Platform) VendorRootPEM() []byte { return append([]byte(nil), p.rootPEM...) }

// EndorsementKeyCertificate returns this platform's VCEK in DER, as the key
// distribution service serves it. It is what [KDS] answers with, exposed so
// that a test can build a service that serves the wrong platform's
// certificate at the right URL.
func (p *Platform) EndorsementKeyCertificate() []byte {
	return append([]byte(nil), p.signer.Vcek.Raw...)
}

// ProductLine returns the AMD product line this platform claims, for
// configuring a verifier that should trust it.
func (p *Platform) ProductLine() string { return p.productLine }

// KDS returns a fake of the vendor's key distribution service for this
// platform, in the shape gvisor.dev/gvisor/attest/provision fetches through:
// it serves this platform's VCEK at the URL for its chip and TCB, and its ASK
// and ARK at the product line's cert_chain URL, and answers anything else —
// another chip, another TCB, another product — the way the real service does,
// with no certificate. That last part is what lets a test show that a chain
// requested for the wrong TCB never gets written.
func (p *Platform) KDS() *KDS {
	return &KDS{platform: p}
}

// A KDS is a fake key distribution service. See [Platform.KDS].
type KDS struct {
	platform *Platform

	// Requested records every URL asked for, in order, so that a test can
	// assert on what was fetched — and, from the consumer side, that nothing
	// was.
	Requested []string
}

// Get serves one URL. It has the signature provision.Getter asks for without
// naming that package, so that snpfake stays importable from anywhere.
func (k *KDS) Get(_ context.Context, url string) ([]byte, error) {
	k.Requested = append(k.Requested, url)
	p := k.platform
	if url == kds.ProductCertChainURL(abi.VcekReportSigner, p.productLine) {
		return p.VendorRootPEM(), nil
	}
	tcbVersion, err := kds.ComposeTCBParts(p.tcb)
	if err != nil {
		return nil, err
	}
	if url == kds.VCEKCertURL(p.productLine, p.chipID[:], tcbVersion) {
		return p.EndorsementKeyCertificate(), nil
	}
	return nil, fmt.Errorf("snpfake: the key distribution service has no certificate at %s", url)
}

// report builds and signs one SEV-SNP report.
func (p *Platform) report(callerSupplied [attest.CallerSuppliedBytesSize]byte) ([]byte, error) {
	tcbVersion, err := kds.ComposeTCBParts(p.tcb)
	if err != nil {
		return nil, fmt.Errorf("snpfake: composing the TCB version: %w", err)
	}
	r := &spb.Report{
		// Version 3 carries the CPUID family/model/stepping, which is what lets
		// a verifier work out the product line without being told. It is the
		// version the host in docs/snp-host-stack.md produces.
		Version:         3,
		Policy:          abi.SnpPolicyToBytes(snpPolicy(p.cfg.Policy)),
		FamilyId:        make([]byte, abi.FamilyIDSize),
		ImageId:         make([]byte, abi.ImageIDSize),
		Vmpl:            0,
		SignatureAlgo:   abi.SignEcdsaP384Sha384,
		CurrentTcb:      uint64(tcbVersion),
		SignerInfo:      abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
		ReportData:      callerSupplied[:],
		Measurement:     p.measurement[:],
		HostData:        make([]byte, abi.HostDataSize),
		IdKeyDigest:     make([]byte, abi.IDKeyDigestSize),
		AuthorKeyDigest: make([]byte, abi.AuthorKeyDigestSize),
		ReportId:        make([]byte, abi.ReportIDSize),
		ReportIdMa:      bytes.Repeat([]byte{0xff}, abi.ReportIDMASize),
		ReportedTcb:     uint64(tcbVersion),
		ChipId:          p.chipID[:],
		CommittedTcb:    uint64(tcbVersion),
		LaunchTcb:       uint64(tcbVersion),
		Signature:       make([]byte, abi.SignatureSize),
		Cpuid1EaxFms:    p.fms,
	}
	raw, err := abi.ReportToAbiBytes(r)
	if err != nil {
		return nil, fmt.Errorf("snpfake: serializing the report: %w", err)
	}
	sigR, sigS, err := p.signer.Sign(abi.SignedComponent(raw))
	if err != nil {
		return nil, fmt.Errorf("snpfake: signing the report: %w", err)
	}
	if err := abi.SetSignature(sigR, sigS, raw); err != nil {
		return nil, fmt.Errorf("snpfake: setting the report signature: %w", err)
	}
	return raw, nil
}

func snpPolicy(p Policy) abi.SnpPolicy {
	return abi.SnpPolicy{
		ABIMajor:     p.ABIMajor,
		ABIMinor:     p.ABIMinor,
		SMT:          p.SMT,
		MigrateMA:    p.MigrationAgent,
		Debug:        p.Debug,
		SingleSocket: p.SingleSocket,
	}
}

// productFms is the CPUID family/model/stepping a product line reports, taken
// from the library's own table rather than restated here. A verifier derives
// the product line from these bytes, so a value invented locally would drift
// and fail chain validation for a reason that has nothing to do with the test.
func productFms(productLine string) (uint32, error) {
	product, err := kds.ParseProductLine(productLine)
	if err != nil {
		return 0, fmt.Errorf("snpfake: unknown product line %q: %w", productLine, err)
	}
	return abi.MaskedCpuid1EaxFromSevProduct(product), nil
}
