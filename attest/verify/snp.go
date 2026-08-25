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

// Package verify is the SEV-SNP implementation of the vendor seam's consumer
// half. It answers the vendor's questions about evidence — does it parse, does
// it chain to AMD's root, does it satisfy a reference value — and answers
// nothing else.
//
// It wraps github.com/google/go-sev-guest for report parsing, chain validation
// and the TCB and policy predicates, per ADR-0003. Hand-rolling that would mean
// owning ASN.1 and AMD's certificate semantics inside the security boundary the
// whole design rests on, in a prototype where that code is not the
// contribution.
//
// The cost of that decision is that the library's API shape wants to leak, and
// containing it to this one package is what makes a second vendor tractable
// later. No go-sev-guest type appears in this package's exported surface: the
// root of trust comes in as PEM bytes, the reference values come in as
// gvisor.dev/gvisor/attest types, and the verdict goes out as
// [attest.Attested] or [attest.Refusal].
//
// Nothing here reaches the network. The chain is provisioned ahead of use and
// carried in the evidence (ADR-0005), certificate fetching is disabled, and the
// HTTP getter handed to the library refuses every request so that a fetch
// introduced by accident fails loudly instead of silently reinstating the
// dependency ADR-0005 removed.
package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"gvisor.dev/gvisor/attest"
)

// Options configures an SEV-SNP verifier.
type Options struct {
	// VendorRootPEM is AMD's root of trust: the ASK and ARK certificates, PEM
	// encoded, in the form AMD's key distribution service serves at
	// .../cert_chain. Ticket 15 provisions this onto the config device beside
	// the reference value set; this package only reads it.
	//
	// Empty means the AMD root certificates embedded in go-sev-guest, which is
	// the right default in production and the wrong one in a test — test-signed
	// evidence does not chain to the real AMD root, which is exactly what makes
	// it a usable negative control.
	VendorRootPEM []byte

	// ProductLine is the AMD product line VendorRootPEM is for, such as "Milan"
	// or "Genoa". Required when VendorRootPEM is set, because AMD's roots are
	// per product line and trusting a root for the wrong one would be a silent
	// mistake.
	ProductLine string

	// Now is the instant at which certificate validity is judged. Zero means
	// time.Now at each call.
	//
	// This is the AMD chain's validity, which is a real control: an expired
	// VCEK means the platform's provisioned chain went stale and the peer needs
	// re-provisioning. It is unrelated to the validity dates on the certificate
	// a peer presents at the handshake, which are not a control at all.
	Now time.Time
}

// SNP verifies SEV-SNP evidence. Construct one with [New].
type SNP struct {
	roots map[string][]*trust.AMDRootCerts
	now   func() time.Time
}

var _ attest.Verifier = (*SNP)(nil)

// New builds an SEV-SNP verifier.
func New(opts Options) (*SNP, error) {
	s := &SNP{now: time.Now}
	if !opts.Now.IsZero() {
		at := opts.Now
		s.now = func() time.Time { return at }
	}
	if len(opts.VendorRootPEM) > 0 {
		if opts.ProductLine == "" {
			return nil, errors.New("verify: VendorRootPEM given without a ProductLine")
		}
		root := trust.AMDRootCertsProduct(opts.ProductLine)
		if err := root.FromKDSCertBytes(opts.VendorRootPEM); err != nil {
			return nil, fmt.Errorf("verify: parsing vendor root: %w", err)
		}
		s.roots = map[string][]*trust.AMDRootCerts{opts.ProductLine: {root}}
	}
	return s, nil
}

// Vendor implements [attest.Verifier].
func (s *SNP) Vendor() attest.Vendor { return attest.VendorAMDSEVSNP }

// Verify implements [attest.Verifier]. It checks that ev is authentic under
// AMD's root and that it satisfies at least one reference value in set.
//
// The binding of ADR-0002 is not checked here. The caller-supplied bytes are
// returned in the claims and the caller checks them, because that binding is
// this design's invention rather than AMD's, and a second vendor should not
// have to reimplement it to be admitted through this seam.
func (s *SNP) Verify(ctx context.Context, ev attest.Evidence, set attest.ReferenceValueSet) (attest.Attested, error) {
	if ev.Vendor != attest.VendorAMDSEVSNP {
		return attest.Attested{}, attest.Refuse(attest.ReasonUnsupportedVendor,
			"evidence is from vendor %q, this verifier reads %q", ev.Vendor, attest.VendorAMDSEVSNP)
	}
	if !ev.Present() {
		return attest.Attested{}, attest.Refuse(attest.ReasonNoEvidence, "peer presented no evidence")
	}

	att, err := parse(ev)
	if err != nil {
		return attest.Attested{}, err
	}
	if err := s.checkAuthentic(ctx, att); err != nil {
		return attest.Attested{}, err
	}

	// From here the report is authentic, so reading values out of it is safe.
	claims, err := claimsOf(att.GetReport())
	if err != nil {
		return attest.Attested{}, err
	}

	// The report's own guest policy, used as the ceiling in every pass where
	// policy is not the predicate under test. Handing the library the report's
	// policy makes that predicate trivially pass without enumerating which bits
	// are permissive, which would go stale the moment go-sev-guest learns a new
	// one.
	selfPolicy, err := abi.ParseSnpPolicy(att.GetReport().GetPolicy())
	if err != nil {
		return attest.Attested{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"guest policy does not parse: %v", err)
	}

	// One pass with no predicate armed still runs go-sev-guest's internal
	// coherence checks — committed TCB equals current, reported TCB equals the
	// one the endorsement key was issued for, chip ID equals the certificate's
	// HWID. Running it once up front means a report that contradicts itself is
	// reported as malformed rather than as whichever predicate happened to be
	// checked first.
	//
	// Two of these will be met in the field rather than in a test. A peer whose
	// reported TCB differs from its certificate's is a peer whose provisioned
	// chain went stale when its platform's TCB was updated, which ADR-0005
	// warns points in the confusing direction: the peer is fine locally and
	// fails at everyone else. And a peer mid-firmware-update, with a committed
	// TCB below its current one, is refused here because provisional firmware
	// is not permitted — the conservative default, and a deliberate one.
	if err := validate(att, sevvalidate.Options{GuestPolicy: selfPolicy}); err != nil {
		return attest.Attested{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"evidence is internally inconsistent; if this names the endorsement key certificate's TCB, "+
				"the peer's provisioned certificate chain is stale and needs re-provisioning (ADR-0005): %v", err)
	}

	// Evidence is accepted if it satisfies any one reference value, which is
	// what lets a new image roll out while the old one is still running.
	var specific error
	for _, rv := range set.Values {
		err := satisfies(att, selfPolicy, rv)
		if err == nil {
			return attest.Attested{Vendor: attest.VendorAMDSEVSNP, Claims: claims, Satisfied: rv}, nil
		}
		// A value whose measurement does not match is a value about a different
		// image and says nothing about this peer. A value whose measurement
		// does match and which refused for some other reason is the one an
		// operator wants to read about, so it outranks the generic answer.
		if attest.ReasonOf(err) != attest.ReasonMeasurementNotInSet && specific == nil {
			specific = err
		}
	}
	if specific != nil {
		return attest.Attested{}, specific
	}
	return attest.Attested{}, attest.Refuse(attest.ReasonMeasurementNotInSet,
		"launch measurement matches none of the %d reference values in the set", len(set.Values))
}

// satisfies reports whether the report satisfies one reference value, refusing
// with the reason for the first predicate it fails.
//
// Each predicate is armed on its own so that its failure carries its own
// reason; a single call with every option set would collapse three distinct
// answers into one library error string. selfPolicy is the report's own policy,
// passed as the ceiling in the passes where policy is not under test.
func satisfies(att *spb.Attestation, selfPolicy abi.SnpPolicy, rv attest.ReferenceValue) error {
	if err := validate(att, sevvalidate.Options{
		GuestPolicy: selfPolicy,
		Measurement: rv.LaunchMeasurement,
	}); err != nil {
		return attest.Refuse(attest.ReasonMeasurementNotInSet, "%v", err)
	}
	if err := validate(att, sevvalidate.Options{
		GuestPolicy: selfPolicy,
		MinimumTCB:  tcbParts(rv.MinimumTCB),
	}); err != nil {
		return attest.Refuse(attest.ReasonTCBBelowFloor, "%v", err)
	}
	if err := validate(att, sevvalidate.Options{
		GuestPolicy: snpPolicy(rv.GuestPolicy),
	}); err != nil {
		return attest.Refuse(attest.ReasonPolicyMismatch, "%v", err)
	}
	return nil
}

func validate(att *spb.Attestation, opts sevvalidate.Options) error {
	return sevvalidate.SnpAttestation(att, &opts)
}

// parse turns evidence into the library's attestation shape. The evidence is a
// raw SEV-SNP report; the chain is AMD's certificate table format, the same
// bytes the platform's report interface would have returned in its certificate
// table had it ever returned any.
func parse(ev attest.Evidence) (*spb.Attestation, error) {
	report, err := abi.ReportToProto(ev.Bytes)
	if err != nil {
		return nil, attest.Refuse(attest.ReasonMalformedEvidence, "report does not parse: %v", err)
	}
	if len(ev.Chain) == 0 {
		// Distinct from a chain that fails to root, and reported as such: this
		// is the shape a peer takes when its provisioned chain is missing, and
		// ADR-0005 requires that to fail closed rather than fall back to a
		// fetch.
		return nil, attest.Refuse(attest.ReasonChainNotRooted, "no certificate chain presented with the evidence")
	}
	certs := new(abi.CertTable)
	if err := certs.Unmarshal(ev.Chain); err != nil {
		return nil, attest.Refuse(attest.ReasonMalformedEvidence, "certificate chain does not parse: %v", err)
	}
	return &spb.Attestation{Report: report, CertificateChain: certs.Proto()}, nil
}

// checkAuthentic asks the one question that is genuinely AMD's certificate
// semantics: does this report's signature chain to AMD's root.
func (s *SNP) checkAuthentic(ctx context.Context, att *spb.Attestation) error {
	opts := &sevverify.Options{
		TrustedRoots: s.roots,
		Now:          s.now(),
		// ADR-0005: the chain is provisioned, never fetched at handshake time.
		DisableCertFetching: true,
		Getter:              offlineGetter{},
	}
	if err := sevverify.SnpAttestationContext(ctx, att, opts); err != nil {
		return attest.Refuse(attest.ReasonChainNotRooted, "%v", err)
	}
	return nil
}

// claimsOf reads the platform facts out of an authentic report.
func claimsOf(report *spb.Report) (attest.Claims, error) {
	var csb [attest.CallerSuppliedBytesSize]byte
	data := report.GetReportData()
	if len(data) != len(csb) {
		return attest.Claims{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"report data is %d bytes, want %d", len(data), len(csb))
	}
	copy(csb[:], data)

	// The reported TCB is the one a verifier compares against a floor: it is
	// the level AMD issued the endorsement key for, and therefore the level the
	// signature actually vouches for.
	parts := kds.DecomposeTCBVersion(kds.TCBVersion(report.GetReportedTcb()))
	return attest.Claims{
		LaunchMeasurement:   append([]byte(nil), report.GetMeasurement()...),
		TCB:                 attest.TCB{Bootloader: parts.BlSpl, TEE: parts.TeeSpl, SNP: parts.SnpSpl, Microcode: parts.UcodeSpl},
		CallerSuppliedBytes: csb,
	}, nil
}

// tcbParts maps a reference value's TCB floor onto the library's shape. The
// reserved components stay zero: naming them in a reference value would ask an
// author to have an opinion about fields AMD has not defined.
func tcbParts(t attest.TCB) kds.TCBParts {
	return kds.TCBParts{BlSpl: t.Bootloader, TeeSpl: t.TEE, SnpSpl: t.SNP, UcodeSpl: t.Microcode}
}

// snpPolicy maps a reference value's guest policy onto the library's shape.
//
// The library reads its argument as the most permissive policy it will accept,
// so a capability left false here is a capability refused. Capabilities
// [attest.GuestPolicy] does not name therefore stay false and stay refused,
// which is the fail-closed direction.
func snpPolicy(p attest.GuestPolicy) abi.SnpPolicy {
	return abi.SnpPolicy{
		ABIMajor:     p.ABIMajor,
		ABIMinor:     p.ABIMinor,
		SMT:          p.AllowSMT,
		MigrateMA:    p.AllowMigrationAgent,
		Debug:        p.AllowDebug,
		SingleSocket: p.RequireSingleSocket,
	}
}

// offlineGetter refuses every request. Certificate fetching is already
// disabled; this is here so that a future edit that re-enables it fails loudly
// instead of quietly restoring the network dependency on the critical path of
// establishing a tunnel — which is the failure ADR-0005 exists to prevent and
// the one that would be least visible.
type offlineGetter struct{}

func (offlineGetter) Get(url string) ([]byte, error) {
	return nil, fmt.Errorf("verify: refusing to fetch %q: verification is offline (ADR-0005)", url)
}

func (g offlineGetter) GetContext(_ context.Context, url string) ([]byte, error) {
	return g.Get(url)
}
