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

package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"gvisor.dev/gvisor/attest"
)

// TDXOptions configures an Intel TDX verifier.
type TDXOptions struct {
	// CollateralDir is the directory holding Intel's TCB info, quoting-enclave
	// identity and revocation lists, in the format this file's neighbour
	// documents. It is required: a TDX quote cannot be verified without them,
	// and the alternative to having them locally is fetching them from Intel on
	// the handshake path, which ADR-0005 forbids and Intel's own terms forbid.
	CollateralDir string

	// VendorRootPEM is Intel's root of trust: the Intel SGX Root CA
	// certificate, PEM encoded.
	//
	// Empty means the Intel root embedded in go-tdx-guest, which is the right
	// default in production and the wrong one in a test — test-signed evidence
	// does not chain to the real Intel root, which is exactly what makes it a
	// usable negative control. This is the same doctrine [Options.VendorRootPEM]
	// states for AMD.
	VendorRootPEM []byte

	// Now is the instant at which certificate and collateral validity is
	// judged. Zero means time.Now at each call.
	//
	// For TDX this clock does more work than it does for AMD. Intel's
	// collateral expires on a calendar about a month after it is issued,
	// independently of anything any peer does, so the difference between an
	// accepted peer and [attest.ReasonChainNotRooted] can be the date alone.
	Now time.Time
}

// TDX verifies Intel TDX quotes from provider-booted confidential VMs.
// Construct one with [NewTDX].
//
// It wraps github.com/google/go-tdx-guest at the commit ADR-0003's amendment
// pins, for the same reason [SNP] wraps go-sev-guest: the alternative is owning
// Intel's certificate semantics, the DCAP quote layout and the provisioning
// service's document formats inside the security boundary the design rests on.
// No go-tdx-guest type appears in this package's exported surface.
//
// # Intel's gate runs before the reference value's floor
//
// At this pinned commit go-tdx-guest requires the platform's TCB status to be
// exactly UpToDate, and the quoting enclave's too, inside the same call that
// checks the quote's signature and the collateral's (checkTcbInfoTcbStatus and
// checkQeTcbStatus in verify/verify.go). That check is not separable: it comes
// back as a flat error alongside every authenticity failure, and this verifier
// reports the lot as [attest.ReasonChainNotRooted].
//
// The consequence is worth stating plainly rather than discovering later. A
// platform Intel calls SWHardeningNeeded is refused at that gate, as
// ReasonChainNotRooted, and a reference value whose floor is
// [attest.TDXTCBSWHardeningNeeded] cannot admit it. The weaker floor is
// therefore not weaker in practice until the library is bumped to a version
// that separates the status check from the signature check — at which point the
// floor here starts doing the work its name promises, with no change to any
// reference value.
//
// The floor is not decoration in the meantime. [attest.TDXTCBFloor] has two
// fields and the other one is live: EvaluationDataNumber is compared against
// the tcbEvaluationDataNumber of the collateral the *verifier* was provisioned
// with, and that is a real control. Intel raises that number at every TCB
// recovery, and collateral from before a recovery verifies perfectly and still
// calls a since-vulnerable platform UpToDate. A host that provisions last
// year's collateral is caught by the floor and by nothing else.
//
// # Nothing here reaches the network
//
// The collateral is read off a directory and served to the library by a getter
// that answers Intel's four URLs from that directory and refuses every other
// address (ADR-0005). Certificate and CRL fetching is not disabled — the
// library has no such switch — it is satisfied locally, and any request the
// library makes that the directory does not answer fails loudly.
type TDX struct {
	collateralDir string
	roots         *x509.CertPool
	now           func() time.Time
}

var _ attest.Verifier = (*TDX)(nil)

// NewTDX builds an Intel TDX verifier.
func NewTDX(opts TDXOptions) (*TDX, error) {
	if opts.CollateralDir == "" {
		return nil, errors.New("verify: NewTDX needs a CollateralDir; Intel collateral is provisioned, never fetched (ADR-0005)")
	}
	t := &TDX{collateralDir: opts.CollateralDir, now: time.Now}
	if !opts.Now.IsZero() {
		at := opts.Now
		t.now = func() time.Time { return at }
	}
	if len(opts.VendorRootPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(opts.VendorRootPEM) {
			return nil, errors.New("verify: VendorRootPEM holds no PEM certificates")
		}
		t.roots = pool
	}
	return t, nil
}

// Vendor implements [attest.Verifier].
func (t *TDX) Vendor() attest.Vendor { return attest.VendorIntelTDX }

// Verify implements [attest.Verifier]. It checks that ev is authentic under
// Intel's root and the provisioned collateral, and that it satisfies at least
// one Intel TDX reference value in set.
//
// The order is [SNP.Verify]'s order, for the same reasons: the vendor and the
// presence of evidence first, because neither needs a parser; the parse next,
// because everything after it reads fields; authenticity before any field is
// believed; and the reference values last, one predicate at a time so that each
// failure carries its own reason.
//
// The binding of ADR-0002 is not checked here. The caller-supplied bytes are
// returned in the claims and [attest.Verification] checks them, for both
// vendors, in one place.
func (t *TDX) Verify(ctx context.Context, ev attest.Evidence, set attest.ReferenceValueSet) (attest.Attested, error) {
	if ev.Vendor != attest.VendorIntelTDX {
		return attest.Attested{}, attest.Refuse(attest.ReasonUnsupportedVendor,
			"evidence is from vendor %q, this verifier reads %q", ev.Vendor, attest.VendorIntelTDX)
	}
	if !ev.Present() {
		return attest.Attested{}, attest.Refuse(attest.ReasonNoEvidence, "peer presented no evidence")
	}

	quote, chain, exts, err := parseQuote(ev)
	if err != nil {
		return attest.Attested{}, err
	}

	// The collateral is looked up by what the peer's own PCK certificate says
	// it is. A platform this verifier was not provisioned for is refused rather
	// than fetched for, and the file names are built from values checked
	// against their shapes first.
	ca, err := pckCA(chain)
	if err != nil {
		return attest.Attested{}, err
	}
	collateral, err := LoadTDXCollateral(t.collateralDir, exts.FMSPC, ca)
	if err != nil {
		// A missing document is not a distinct reason. It is the shape a
		// verifier takes when nothing can establish that this quote is
		// authentic, which is [attest.ReasonChainNotRooted]'s question, and it
		// is the same answer [SNP.Verify] gives a peer whose provisioned chain
		// is absent.
		return attest.Attested{}, attest.Refuse(attest.ReasonChainNotRooted, "%v", err)
	}

	// Expiry is judged here, before the library is asked anything, so that
	// stale collateral is reported as stale rather than as one more flat error
	// among the library's own authenticity failures. It refuses as
	// [attest.ReasonChainNotRooted], the same reason a forged chain gets,
	// because a chain judged against collateral that is not valid now cannot be
	// called rooted now either. The detail is what tells the operator this is
	// the verifier's own provisioning gone stale, not something the peer did.
	now := t.now()
	if err := collateral.CheckFresh(now); err != nil {
		return attest.Attested{}, attest.Refuse(attest.ReasonChainNotRooted,
			"the provisioned Intel collateral is not valid at %s: %v — the peer may be fine; "+
				"re-provision the collateral directory (ADR-0007)",
			now.UTC().Format(time.RFC3339), err)
	}

	if err := t.checkAuthentic(quote, collateral, now); err != nil {
		return attest.Attested{}, err
	}

	// From here the quote is authentic and the collateral it was judged against
	// carries Intel's signature, so reading values out of either is safe.
	claims, err := t.claimsOf(quote, collateral, exts)
	if err != nil {
		return attest.Attested{}, err
	}

	// Evidence is accepted if it satisfies any one reference value, which is
	// what lets a new image roll out while the old one is still running. Values
	// for another vendor are skipped rather than refused: a set holding AMD and
	// Intel entries is one signed document naming peers on both, and an Intel
	// peer has nothing to say about an AMD entry.
	var specific, firstMismatch error
	tdxValues := 0
	for _, rv := range set.Values {
		if rv.Vendor != attest.VendorIntelTDX || rv.TDX == nil {
			continue
		}
		tdxValues++
		err := satisfiesTDX(claims, rv)
		if err == nil {
			return attest.Attested{Vendor: attest.VendorIntelTDX, Claims: claims, Satisfied: rv}, nil
		}
		// A value whose registers do not match is a value about a different
		// image and says nothing about this peer. A value whose registers do
		// match and which refused for some other reason is the one an operator
		// wants to read about, so it outranks the generic answer.
		if attest.ReasonOf(err) != attest.ReasonMeasurementNotInSet {
			if specific == nil {
				specific = err
			}
			continue
		}
		if firstMismatch == nil {
			firstMismatch = err
		}
	}
	if specific != nil {
		return attest.Attested{}, specific
	}
	// With one reference value there is one answer, and it names the register
	// that disagreed. With several, naming any one value's disagreement would
	// be arbitrary — so the TD's own registers go in the log instead, and the
	// operator diffs them against the set they already hold.
	if tdxValues == 1 && firstMismatch != nil {
		return attest.Attested{}, firstMismatch
	}
	td := claims.TDX
	return attest.Attested{}, attest.Refuse(attest.ReasonMeasurementNotInSet,
		"the TD's registers match none of the %d Intel TDX reference values in the set of %d: "+
			"MRTD %x, RTMR0 %x, RTMR1 %x, RTMR2 %x",
		tdxValues, len(set.Values), td.MRTD, td.RTMR0, td.RTMR1, td.RTMR2)
}

// satisfiesTDX reports whether an authentic TD's claims satisfy one reference
// value, refusing with the reason for the first predicate it fails.
//
// The predicates run registers, then TCB, then policy — [satisfies]'s order for
// AMD — so that a peer running a different image is told that and nothing else,
// and a peer running the right image with the wrong platform is told which of
// the remaining two it failed.
func satisfiesTDX(claims attest.Claims, rv attest.ReferenceValue) error {
	td := claims.TDX
	ref := rv.TDX

	for _, r := range []struct {
		name string
		got  []byte
		want [][]byte
	}{
		{"MRTD", td.MRTD, ref.ObservedMRTD},
		{"RTMR0", td.RTMR0, ref.ObservedRTMR0},
		{"RTMR1", td.RTMR1, ref.ObservedRTMR1},
	} {
		if !anyOf(r.got, r.want) {
			return attest.Refuse(attest.ReasonMeasurementNotInSet,
				"the TD's observed %s is %x, which is none of the %d values this reference value lists",
				r.name, r.got, len(r.want))
		}
	}
	if !bytes.Equal(td.RTMR2, ref.PredictedRTMR2) {
		return attest.Refuse(attest.ReasonMeasurementNotInSet,
			"the TD's RTMR2 is %x, and this reference value predicts %x", td.RTMR2, ref.PredictedRTMR2)
	}

	if rank(td.TCBStatus) < rank(ref.MinimumTCB.Status) {
		return attest.Refuse(attest.ReasonTCBBelowFloor,
			"Intel reports this platform %q, and this reference value's floor is %q",
			td.TCBStatus, ref.MinimumTCB.Status)
	}
	if td.TCBEvaluationDataNumber < ref.MinimumTCB.EvaluationDataNumber {
		return attest.Refuse(attest.ReasonTCBBelowFloor,
			"the TCB info this verifier holds is evaluation data number %d, and this reference value's floor is %d; "+
				"the collateral predates a TCB recovery and needs re-provisioning",
			td.TCBEvaluationDataNumber, ref.MinimumTCB.EvaluationDataNumber)
	}

	if debugEnabled(td.TDAttributes) && !ref.TDPolicy.AllowDebug {
		return attest.Refuse(attest.ReasonPolicyMismatch,
			"the TD was created with TD_ATTRIBUTES.DEBUG (attributes %x), which lets the host read its memory, "+
				"and this reference value does not permit it", td.TDAttributes)
	}
	return nil
}

// debugEnabled reports TD_ATTRIBUTES bit 0, the DEBUG bit. The field is eight
// little-endian bytes, so bit 0 is the low bit of the first one.
func debugEnabled(attrs [8]byte) bool { return attrs[0]&0x01 != 0 }

// anyOf reports whether got equals one of want. An empty want matches nothing,
// which is the fail-closed direction; [attest.ReferenceValueSet] refuses a
// value with an empty list before it ever reaches here.
func anyOf(got []byte, want [][]byte) bool {
	for _, w := range want {
		if bytes.Equal(got, w) {
			return true
		}
	}
	return false
}

// rank orders Intel's statuses so that a floor can be compared against a
// platform. Only the two a reference value may name are above the floor of
// nothing; every other status Intel can return — ConfigurationNeeded,
// OutOfDate, Revoked and their combinations — ranks below both, which is the
// conservative reading and the one ADR-0005's replacement states.
func rank(s attest.TDXTCBStatus) int {
	switch s {
	case attest.TDXTCBUpToDate:
		return 2
	case attest.TDXTCBSWHardeningNeeded:
		return 1
	default:
		return 0
	}
}

// parseQuote turns evidence into the library's quote shape, together with the
// PCK certificate chain the quote carries and the SGX extensions of its leaf.
//
// A TDX quote carries its own chain, so [attest.Evidence.Chain] is unused for
// this vendor and is not consulted: an acquirer that filled it would be
// describing something this verifier does not read.
func parseQuote(ev attest.Evidence) (*tdxpb.QuoteV4, []*x509.Certificate, *pcs.PckExtensions, error) {
	any, err := tdxabi.QuoteToProto(ev.Bytes)
	if err != nil {
		return nil, nil, nil, attest.Refuse(attest.ReasonMalformedEvidence, "quote does not parse: %v", err)
	}
	quote, ok := any.(*tdxpb.QuoteV4)
	if !ok {
		return nil, nil, nil, attest.Refuse(attest.ReasonMalformedEvidence,
			"quote parsed as %T, and this verifier reads only version 4 quotes", any)
	}
	raw := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	if len(raw) == 0 {
		return nil, nil, nil, attest.Refuse(attest.ReasonChainNotRooted,
			"the quote carries no PCK certificate chain")
	}
	chain, err := parsePEMCertificates(bytes.TrimRight(raw, "\x00"))
	if err != nil {
		return nil, nil, nil, attest.Refuse(attest.ReasonMalformedEvidence,
			"the quote's PCK certificate chain does not parse: %v", err)
	}
	if len(chain) != 3 {
		return nil, nil, nil, attest.Refuse(attest.ReasonMalformedEvidence,
			"the quote's PCK certificate chain holds %d certificates, want a leaf, an intermediate and a root", len(chain))
	}
	exts, err := pcs.PckCertificateExtensions(chain[0])
	if err != nil {
		return nil, nil, nil, attest.Refuse(attest.ReasonMalformedEvidence,
			"the quote's PCK certificate carries no readable SGX extensions: %v", err)
	}
	return quote, chain, exts, nil
}

// pckCA names the Intel issuer that signed the peer's PCK certificate, which
// selects which revocation list the collateral directory must hold. It is read
// off the leaf's issuer name, exactly as go-tdx-guest reads it
// (extractCaFromPckCert in verify/verify.go).
func pckCA(chain []*x509.Certificate) (string, error) {
	switch chain[0].Issuer.CommonName {
	case "Intel SGX PCK Platform CA":
		return "platform", nil
	case "Intel SGX PCK Processor CA":
		return "processor", nil
	default:
		return "", attest.Refuse(attest.ReasonMalformedEvidence,
			"the quote's PCK certificate names issuer %q, which is neither Intel PCK CA",
			chain[0].Issuer.CommonName)
	}
}

// checkAuthentic asks the questions that are genuinely Intel's: does this
// quote's signature chain through its quoting enclave and PCK certificate to
// Intel's root, is the collateral Intel signed, and is nothing in the chain
// revoked.
//
// Every failure is [attest.ReasonChainNotRooted], and the errors are not
// inspected to say more. go-tdx-guest wraps everything with %v, so the reason a
// caller could recover by matching strings would be a reason that changes when
// the library changes its wording — and authenticity in the widest sense is one
// question anyway: is any of this real.
//
// Intel's own UpToDate-only TCB gate also lives inside this call, which is the
// behaviour [TDX] documents at length.
func (t *TDX) checkAuthentic(quote *tdxpb.QuoteV4, collateral *TDXCollateral, now time.Time) error {
	// A fresh Options per call: go-tdx-guest writes the collateral, the chain
	// and a defaulted clock back into the struct it is handed.
	opts := &tdxverify.Options{
		GetCollateral:    true,
		CheckRevocations: true,
		Getter:           collateral.getter(),
		Now:              now,
		TrustedRoots:     t.roots,
	}
	if err := tdxverify.TdxQuote(quote, opts); err != nil {
		return attest.Refuse(attest.ReasonChainNotRooted, "%v", err)
	}
	return nil
}

// claimsOf reads the platform facts out of an authentic quote.
func (t *TDX) claimsOf(quote *tdxpb.QuoteV4, collateral *TDXCollateral, exts *pcs.PckExtensions) (attest.Claims, error) {
	body := quote.GetTdQuoteBody()

	var csb [attest.CallerSuppliedBytesSize]byte
	data := body.GetReportData()
	if len(data) != len(csb) {
		return attest.Claims{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"report data is %d bytes, want %d", len(data), len(csb))
	}
	copy(csb[:], data)

	rtmrs := body.GetRtmrs()
	if len(rtmrs) != 4 {
		return attest.Claims{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"the TD reports %d runtime measurement registers, want 4", len(rtmrs))
	}
	var attrs [8]byte
	got := body.GetTdAttributes()
	if len(got) != len(attrs) {
		return attest.Claims{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"TD_ATTRIBUTES is %d bytes, want %d", len(got), len(attrs))
	}
	copy(attrs[:], got)

	status, err := tcbStatusOf(collateral.tcbInfo.TcbInfo, body.GetTeeTcbSvn(), exts)
	if err != nil {
		// The quote and the TCB info have both been verified by now, so this is
		// a platform Intel's own document does not describe: no TCB level in it
		// covers this SVN. That is not authenticity and it is not a floor, it
		// is evidence that contradicts the collateral it was checked against.
		return attest.Claims{}, attest.Refuse(attest.ReasonMalformedEvidence,
			"Intel's TCB info for FMSPC %s does not resolve this platform's level: %v", exts.FMSPC, err)
	}

	return attest.Claims{
		LaunchMeasurement: append([]byte(nil), rtmrs[2]...),
		TDX: &attest.TDXClaims{
			MRTD:                    append([]byte(nil), body.GetMrTd()...),
			RTMR0:                   append([]byte(nil), rtmrs[0]...),
			RTMR1:                   append([]byte(nil), rtmrs[1]...),
			RTMR2:                   append([]byte(nil), rtmrs[2]...),
			RTMR3:                   append([]byte(nil), rtmrs[3]...),
			TDAttributes:            attrs,
			TCBStatus:               status,
			TCBEvaluationDataNumber: collateral.EvaluationDataNumber(),
			FMSPC:                   exts.FMSPC,
		},
		CallerSuppliedBytes: csb,
	}, nil
}

// tcbStatusOf resolves the platform's TCB status out of Intel's TCB info.
//
// This reimplements Intel's matching algorithm rather than asking the library
// for it, because the library does not answer the question: at this pinned
// commit it computes the status only to compare it against UpToDate and
// discards it (checkTcbInfoTcbStatus, verify/verify.go:940). The claims have to
// carry the status itself, so the algorithm is reproduced here from the same
// file: getMatchingTcbLevel at verify/verify.go:917, isCPUSvnHigherOrEqual at
// :870, isTdxTcbSvnHigherOrEqual at :882 and getMatchingTdxModuleTcbLevel at
// :898.
//
// The composition of the two levels is this file's own reading. Intel resolves
// a TD's standing from the platform's TCB level and, when the quote names a TDX
// module, from that module's level too; the library requires both to be
// UpToDate. Taking the weaker of the two here is the same judgement expressed
// as a value rather than as a gate, and it is the conservative direction: a
// current platform running an out-of-date module is reported out of date.
func tcbStatusOf(info pcs.TcbInfo, teeTCBSvn []byte, exts *pcs.PckExtensions) (attest.TDXTCBStatus, error) {
	if len(teeTCBSvn) < 2 {
		return "", fmt.Errorf("TEE_TCB_SVN is %d bytes", len(teeTCBSvn))
	}
	level, err := matchingTCBLevel(info.TcbLevels, teeTCBSvn, exts.TCB.PCESvn, exts.TCB.CPUSvnComponents)
	if err != nil {
		return "", err
	}
	status := attest.TDXTCBStatus(level.TcbStatus)

	// A non-zero second byte of TEE_TCB_SVN names a TDX module version, and
	// Intel then publishes that module's own levels under an identity keyed by
	// it.
	if teeTCBSvn[1] > 0 {
		moduleLevel, err := matchingModuleTCBLevel(info.TdxModuleIdentities, teeTCBSvn)
		if err != nil {
			return "", err
		}
		if s := attest.TDXTCBStatus(moduleLevel.TcbStatus); rank(s) < rank(status) {
			status = s
		}
	}
	return status, nil
}

// matchingTCBLevel is getMatchingTcbLevel: the first level in Intel's
// descending list every component of this platform is at or above.
func matchingTCBLevel(levels []pcs.TcbLevel, teeTCBSvn []byte, pceSvn uint16, cpuSvnComponents []byte) (pcs.TcbLevel, error) {
	for _, level := range levels {
		if svnsAtLeast(cpuSvnComponents, level.Tcb.SgxTcbcomponents) &&
			pceSvn >= level.Tcb.Pcesvn &&
			tdxSVNsAtLeast(teeTCBSvn, level.Tcb.TdxTcbcomponents) {
			return level, nil
		}
	}
	return pcs.TcbLevel{}, errors.New("no TCB level in Intel's TCB info matches this platform's SVNs")
}

// svnsAtLeast is isCPUSvnHigherOrEqual.
func svnsAtLeast(got []byte, want []pcs.TcbComponent) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] < want[i].Svn {
			return false
		}
	}
	return true
}

// tdxSVNsAtLeast is isTdxTcbSvnHigherOrEqual. The first two bytes of
// TEE_TCB_SVN name the TDX module rather than the platform's TDX TCB, so when
// a module is named they are compared through the module's own identity
// instead of here.
func tdxSVNsAtLeast(teeTCBSvn []byte, want []pcs.TcbComponent) bool {
	if len(teeTCBSvn) != len(want) {
		return false
	}
	start := 0
	if teeTCBSvn[1] > 0 {
		start = 2
	}
	for i := start; i < len(teeTCBSvn); i++ {
		if teeTCBSvn[i] < want[i].Svn {
			return false
		}
	}
	return true
}

// matchingModuleTCBLevel is getMatchingTdxModuleTcbLevel: the identity keyed by
// the module version in TEE_TCB_SVN[1], then the first of its levels the
// module's ISVSVN in TEE_TCB_SVN[0] reaches.
func matchingModuleTCBLevel(identities []pcs.TdxModuleIdentity, teeTCBSvn []byte) (pcs.TcbLevel, error) {
	id := "TDX_" + hex.EncodeToString(teeTCBSvn[1:2])
	isvSvn := uint32(teeTCBSvn[0])
	for _, identity := range identities {
		if identity.ID != id {
			continue
		}
		for _, level := range identity.TcbLevels {
			if isvSvn >= level.Tcb.Isvsvn {
				return level, nil
			}
		}
		return pcs.TcbLevel{}, fmt.Errorf("TDX module identity %q has no TCB level matching ISVSVN %d", id, isvSvn)
	}
	return pcs.TcbLevel{}, fmt.Errorf("Intel's TCB info names no TDX module identity %q", id)
}
