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

// Package tdxfake is a fake Intel TDX platform: it mints quotes with arbitrary
// registers, TD attributes and TCB levels, signed by a test certificate chain,
// together with the Intel collateral a verifier needs to check them.
//
// # Why this one re-signs a recording
//
// gvisor.dev/gvisor/attest/snpfake builds an SEV-SNP report from nothing,
// because an SEV-SNP report is a flat structure with one signature over it. A
// TDX quote is not: it is a TD report, a quoting-enclave report whose report
// data commits to an attestation key, a signature by that key over the TD
// report, a signature by the platform's provisioning certification key over the
// quoting-enclave report, and a PEM certificate chain with Intel's SGX
// extensions carried inside the quote — and none of it means anything without
// four separately signed documents from Intel's provisioning service.
// Inventing all of that would be inventing Intel's format, and a fake that
// disagrees with the format tests the disagreement rather than the verifier.
//
// So this starts from a quote a real Google TDX VM produced, which is on this
// branch under docs/snp/evidence/tdx, and re-signs it: the same layout, the
// same field widths, the same SGX extension bytes in the PCK certificate, the
// same quoting-enclave identity — with every key replaced by a generated test
// key and every field a test wants to move, moved. What is fake is the
// platform and Intel, and only those; the verifier under test runs the same
// parse, the same chain walk, the same collateral signature checks and the same
// predicates it runs against hardware.
//
// # What a test can ask for
//
// Every refusal a TDX verifier can produce has a [Config] that provokes it: a
// register moved, TD_ATTRIBUTES.DEBUG set, a TCB level Intel calls out of date,
// collateral from before a TCB recovery, collateral that expired, collateral
// signed by a stranger, and — by verifying one platform's evidence against
// another platform's root — a chain that does not root.
//
// It must not be linked into a production binary. It exists to be substituted
// at the vendor seam, below everything worth testing.
package tdxfake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"gvisor.dev/gvisor/attest"
)

// DefaultNow is the instant a fake platform's certificates and collateral are
// dated around when a config does not choose one. It is inside the validity of
// the Intel collateral recorded on this branch, so a test can drive the fake
// and a recorded quote from one clock.
var DefaultNow = time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)

// DefaultEvaluationDataNumber is the tcbEvaluationDataNumber the fake's
// collateral carries. It is the number Intel's real TCB info for these
// platforms carried when it was fetched (docs/snp/evidence/tdx/collateral),
// recorded here as a fact about that document rather than as a recommended
// floor.
const DefaultEvaluationDataNumber = 20

// Intel's masks, as its real quoting-enclave identity and TCB info carry them
// (docs/snp/evidence/tdx/collateral). They are copied rather than invented
// because a mask is a statement about which bits of a platform's attributes
// Intel promises to pin, and a fake that pinned different bits would be
// testing a policy nobody deployed. The values under them are derived from the
// recorded quote through the mask, exactly as Intel derives its own.
var (
	qeMiscSelectMask    = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	qeAttributesMask    = mustHex("FBFFFFFFFFFFFFFF0000000000000000")
	seamAttributesMask  = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	collateralValidFor  = 30 * 24 * time.Hour
	certificateValidFor = 365 * 24 * time.Hour
)

// Config describes the platform to fake and the Intel collateral a verifier
// holds for it.
//
// Every field left at its zero value keeps whatever the recorded quote or the
// real collateral said, so a config that sets one field changes one thing and
// the rest is a control.
type Config struct {
	// RecordedQuote is a real TDX quote in Intel's ABI format, whose layout,
	// field widths and quoting-enclave identity this platform reuses. Required:
	// there is nothing to re-sign without one.
	RecordedQuote []byte

	// CollateralDir is where the four Intel documents are written, in the
	// format gvisor.dev/gvisor/attest/verify reads. Required, and a test should
	// pass t.TempDir() — this package writes files and never removes them,
	// because a fake that cleans up after itself hides what it wrote when a
	// test fails.
	CollateralDir string

	// Now is the instant the certificates and collateral are dated around.
	// Zero means [DefaultNow], so that a test's outcome does not depend on the
	// day it runs.
	Now time.Time

	// MRTD, RTMR0, RTMR1, RTMR2 and RTMR3 replace the recorded registers. Each
	// must be 48 bytes; nil keeps what the recording said.
	MRTD  []byte
	RTMR0 []byte
	RTMR1 []byte
	RTMR2 []byte
	RTMR3 []byte

	// TDAttributes replaces TD_ATTRIBUTES, the eight bytes describing what the
	// TD was created with. Bit 0 of the first byte is DEBUG, and a platform
	// with it set is the one a reference value that does not permit debugging
	// has to refuse. Nil keeps the recording's.
	TDAttributes []byte

	// TeeTCBSvn replaces TEE_TCB_SVN, the sixteen bytes naming the platform's
	// TDX security version. It is what Intel's TCB info is matched against, so
	// moving it moves which level the platform lands on. Nil keeps the
	// recording's, and the generated collateral is built so that the
	// recording's lands on [Config.TCBStatus].
	TeeTCBSvn []byte

	// TCBStatus is the status Intel's generated TCB info gives the level this
	// platform matches. Empty means UpToDate.
	//
	// Any other value is refused by go-tdx-guest inside the same call that
	// checks the quote's signature, so a test that sets this should expect
	// [attest.ReasonChainNotRooted] rather than a TCB floor refusal — see the
	// [verify.TDX] type comment for why that is, and for what it means for the
	// reference value's floor.
	TCBStatus attest.TDXTCBStatus

	// EvaluationDataNumber is the tcbEvaluationDataNumber the generated
	// collateral carries. Zero means [DefaultEvaluationDataNumber]. A number
	// below a reference value's floor is collateral from before a TCB recovery,
	// and is the one TCB refusal this library commit lets a reference value
	// make.
	EvaluationDataNumber uint32

	// CollateralNextUpdate is when the generated collateral stops being usable.
	// Zero means a month after Now. A value in the past relative to the
	// verifier's clock is collateral that has expired on the calendar, which
	// refuses as [attest.ReasonChainNotRooted] — the same reason a forged chain
	// gets, because collateral that is not valid now cannot root a chain now
	// either.
	CollateralNextUpdate time.Time

	// CollateralSignedByStranger signs the TCB info and quoting-enclave
	// identity with a key that is not the one the issuer chain names, leaving
	// everything else intact. It is a forged Intel document, and the verifier
	// must refuse it for the same reason it refuses a forged quote.
	CollateralSignedByStranger bool
}

// A Platform is a fake Intel TDX platform. It implements [attest.Acquirer],
// the producer half of the vendor seam.
type Platform struct {
	cfg Config
	now time.Time

	recorded *tdxpb.QuoteV4

	rootKey, intermediateKey, pckKey *ecdsa.PrivateKey
	root, intermediate, pck          *x509.Certificate
	chainPEM                         []byte

	fmspc string
	ca    string
}

var _ attest.Acquirer = (*Platform)(nil)

// New builds a fake platform from cfg, and writes its Intel collateral into
// cfg.CollateralDir.
//
// The collateral is written once, at construction, because it describes the
// platform rather than any one quote: a verifier holds it for every peer on
// that FMSPC and re-provisions it on a calendar, and writing it per quote would
// model something that does not happen.
func New(cfg Config) (*Platform, error) {
	if len(cfg.RecordedQuote) == 0 {
		return nil, errors.New("tdxfake: no RecordedQuote; there is nothing to re-sign")
	}
	if cfg.CollateralDir == "" {
		return nil, errors.New("tdxfake: no CollateralDir; the collateral has to be written somewhere a verifier can read it")
	}
	parsed, err := tdxabi.QuoteToProto(cfg.RecordedQuote)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: the recorded quote does not parse: %w", err)
	}
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("tdxfake: the recorded quote parsed as %T, want a version 4 quote", parsed)
	}

	p := &Platform{cfg: cfg, recorded: quote, now: cfg.Now}
	if p.now.IsZero() {
		p.now = DefaultNow
	}
	if err := p.mintChain(); err != nil {
		return nil, err
	}
	if err := p.writeCollateral(); err != nil {
		return nil, err
	}
	return p, nil
}

// Vendor implements [attest.Acquirer].
func (p *Platform) Vendor() attest.Vendor { return attest.VendorIntelTDX }

// Acquire implements [attest.Acquirer]. It returns a freshly signed quote over
// the given caller-supplied bytes, which come back in the TD report verbatim
// exactly as hardware returns them.
//
// [attest.Evidence.Chain] is left empty, and that is not an omission: a TDX
// quote carries its PCK certificate chain inside itself, so there is nothing
// for an acquirer to bundle alongside it and nothing a verifier reads there.
func (p *Platform) Acquire(_ context.Context, callerSupplied [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	raw, err := p.quote(callerSupplied)
	if err != nil {
		return attest.Evidence{}, err
	}
	return attest.Evidence{Vendor: attest.VendorIntelTDX, Bytes: raw}, nil
}

// VendorRootPEM returns this platform's root of trust, in the form
// verify.TDXOptions takes: the test Intel SGX Root CA, PEM encoded.
//
// A verifier configured with a different root — another fake platform's, or the
// real Intel root go-tdx-guest embeds — refuses this platform's evidence, which
// is how the chain-does-not-root refusal is reached without inventing a broken
// certificate.
func (p *Platform) VendorRootPEM() []byte { return certPEM(p.root) }

// CollateralDir returns the directory the platform's Intel collateral was
// written to, for handing to verify.TDXOptions.
func (p *Platform) CollateralDir() string { return p.cfg.CollateralDir }

// FMSPC returns the platform identifier the collateral is filed under. It comes
// from the SGX extension of the recorded PCK certificate, which this platform's
// own PCK certificate carries byte for byte.
func (p *Platform) FMSPC() string { return p.fmspc }

// quote builds and signs one quote.
func (p *Platform) quote(callerSupplied [attest.CallerSuppliedBytesSize]byte) ([]byte, error) {
	quote := cloneQuote(p.recorded)
	body := quote.TdQuoteBody

	for _, sub := range []struct {
		name string
		into *[]byte
		with []byte
		size int
	}{
		{"MRTD", &body.MrTd, p.cfg.MRTD, tdxabi.MrTdSize},
		{"RTMR0", &body.Rtmrs[0], p.cfg.RTMR0, tdxabi.RtmrSize},
		{"RTMR1", &body.Rtmrs[1], p.cfg.RTMR1, tdxabi.RtmrSize},
		{"RTMR2", &body.Rtmrs[2], p.cfg.RTMR2, tdxabi.RtmrSize},
		{"RTMR3", &body.Rtmrs[3], p.cfg.RTMR3, tdxabi.RtmrSize},
		{"TD_ATTRIBUTES", &body.TdAttributes, p.cfg.TDAttributes, tdxabi.TdAttributesSize},
		{"TEE_TCB_SVN", &body.TeeTcbSvn, p.cfg.TeeTCBSvn, tdxabi.TeeTcbSvnSize},
	} {
		if sub.with == nil {
			continue
		}
		if len(sub.with) != sub.size {
			return nil, fmt.Errorf("tdxfake: %s is %d bytes, want %d", sub.name, len(sub.with), sub.size)
		}
		*sub.into = append([]byte(nil), sub.with...)
	}
	body.ReportData = append([]byte(nil), callerSupplied[:]...)

	// A fresh attestation key per quote, as a real quoting enclave produces.
	// The quote is only as good as the QE report's commitment to this key, so
	// reusing one across quotes would model a platform that does not exist.
	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: generating an attestation key: %w", err)
	}
	attestKeyBytes := rawPublicKey(&attestKey.PublicKey)

	// The quoting-enclave report data is the digest that binds the attestation
	// key to the certificate chain: SHA-256 over the key concatenated with the
	// QE authentication data, zero padded to the report data's width. This is
	// verifyHash256 in go-tdx-guest's verify/verify.go, read the other way
	// round.
	signedData := quote.SignedData
	qeCertData := signedData.CertificationData.QeReportCertificationData
	authData := qeCertData.QeAuthData.GetData()
	digest := sha256.Sum256(append(append([]byte(nil), attestKeyBytes...), authData...))
	reportData := make([]byte, tdxabi.ReportDataSize)
	copy(reportData, digest[:])
	qeCertData.QeReport.ReportData = reportData

	qeReportBytes, err := tdxabi.EnclaveReportToAbiBytes(qeCertData.GetQeReport())
	if err != nil {
		return nil, fmt.Errorf("tdxfake: serialising the QE report: %w", err)
	}
	qeSignature, err := signRaw(p.pckKey, qeReportBytes)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: signing the QE report: %w", err)
	}
	qeCertData.QeReportSignature = qeSignature
	qeCertData.PckCertificateChainData.PckCertChain = append([]byte(nil), p.chainPEM...)
	qeCertData.PckCertificateChainData.Size = uint32(len(p.chainPEM))

	// The attestation key signs the header and TD report, which is the whole of
	// what the quote asserts about the TD.
	header, err := tdxabi.HeaderToAbiBytes(quote.GetHeader())
	if err != nil {
		return nil, fmt.Errorf("tdxfake: serialising the quote header: %w", err)
	}
	bodyBytes, err := tdxabi.TdQuoteBodyToAbiBytes(body)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: serialising the TD report: %w", err)
	}
	signature, err := signRaw(attestKey, append(header, bodyBytes...))
	if err != nil {
		return nil, fmt.Errorf("tdxfake: signing the quote: %w", err)
	}
	signedData.Signature = signature
	signedData.EcdsaAttestationKey = attestKeyBytes

	// The three nested length fields, recomputed for the chain that is actually
	// there. They are laid out in go-tdx-guest's abi package: a QE report
	// certification datum is the QE report, its signature, the authentication
	// data with a two-byte length, and the certificate chain with a six-byte
	// header; the certification datum wraps that with six more.
	const (
		qeReportSize      = 0x180
		signatureSize     = 0x40
		authDataHeader    = 0x02
		chainHeader       = 0x06
		certDataHeader    = 0x06
		signedDataKnown   = 0x80
		qeReportCertBytes = qeReportSize + signatureSize
	)
	certSize := uint32(qeReportCertBytes + authDataHeader + len(authData) + chainHeader + len(p.chainPEM))
	signedData.CertificationData.Size = certSize
	quote.SignedDataSize = signedDataKnown + certDataHeader + certSize

	raw, err := tdxabi.QuoteToAbiBytes(quote)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: serialising the quote: %w", err)
	}
	return raw, nil
}

// mintChain generates the test PCK certificate chain.
//
// Each certificate mirrors the one it replaces in the recorded quote: the same
// subject and issuer names, which go-tdx-guest checks by string, and the same
// X.509 extensions byte for byte — including the PCK certificate's SGX
// extension, so the FMSPC, PCEID, CPUSVN and PCESVN this platform claims are
// the ones the recording claimed and the ones Intel's real TCB info was fetched
// for. Only the keys and the validity dates are this package's.
func (p *Platform) mintChain() error {
	real, err := chainOf(p.recorded)
	if err != nil {
		return err
	}
	realLeaf, realIntermediate, realRoot := real[0], real[1], real[2]

	if p.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("tdxfake: generating the root key: %w", err)
	}
	if p.intermediateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("tdxfake: generating the intermediate key: %w", err)
	}
	if p.pckKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("tdxfake: generating the PCK key: %w", err)
	}

	if p.root, err = p.mirror(realRoot, 1, nil, p.rootKey, &p.rootKey.PublicKey); err != nil {
		return fmt.Errorf("tdxfake: the root certificate: %w", err)
	}
	if p.intermediate, err = p.mirror(realIntermediate, 2, p.root, p.rootKey, &p.intermediateKey.PublicKey); err != nil {
		return fmt.Errorf("tdxfake: the intermediate certificate: %w", err)
	}
	if p.pck, err = p.mirror(realLeaf, 3, p.intermediate, p.intermediateKey, &p.pckKey.PublicKey); err != nil {
		return fmt.Errorf("tdxfake: the PCK certificate: %w", err)
	}

	exts, err := pcs.PckCertificateExtensions(p.pck)
	if err != nil {
		return fmt.Errorf("tdxfake: the minted PCK certificate's SGX extensions do not read back: %w", err)
	}
	p.fmspc = exts.FMSPC
	switch p.pck.Issuer.CommonName {
	case "Intel SGX PCK Platform CA":
		p.ca = "platform"
	case "Intel SGX PCK Processor CA":
		p.ca = "processor"
	default:
		return fmt.Errorf("tdxfake: the recorded PCK certificate names issuer %q, which is neither Intel PCK CA", p.pck.Issuer.CommonName)
	}

	p.chainPEM = append(append(certPEM(p.pck), certPEM(p.intermediate)...), certPEM(p.root)...)
	return nil
}

// mirror mints one certificate with the same names and extensions as model,
// signed by the given parent key. A nil parent means self-signed.
func (p *Platform) mirror(model *x509.Certificate, serial int64, parent *x509.Certificate, signer *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(serial),
		RawSubject:         model.RawSubject,
		NotBefore:          p.now.Add(-certificateValidFor),
		NotAfter:           p.now.Add(certificateValidFor),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		// Every extension comes across verbatim, which is what keeps the basic
		// constraints, the key usages, the CRL distribution points and the SGX
		// extension exactly as Intel issued them. Passing them here rather than
		// through the typed fields also stops crypto/x509 adding a second copy
		// of any of them.
		ExtraExtensions: model.Extensions,
	}
	issuer := template
	if parent != nil {
		issuer = parent
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// chainOf pulls the three PEM certificates out of a quote's certification data.
func chainOf(quote *tdxpb.QuoteV4) ([]*x509.Certificate, error) {
	raw := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	var out []*x509.Certificate
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tdxfake: the recorded PCK chain does not parse: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) != 3 {
		return nil, fmt.Errorf("tdxfake: the recorded PCK chain holds %d certificates, want 3", len(out))
	}
	return out, nil
}

// cloneQuote deep copies the parts of a quote this package rewrites, so that
// one recording can back any number of platforms and any number of quotes.
func cloneQuote(q *tdxpb.QuoteV4) *tdxpb.QuoteV4 {
	body := q.GetTdQuoteBody()
	rtmrs := make([][]byte, len(body.GetRtmrs()))
	for i, r := range body.GetRtmrs() {
		rtmrs[i] = append([]byte(nil), r...)
	}
	qeCert := q.GetSignedData().GetCertificationData().GetQeReportCertificationData()
	qe := qeCert.GetQeReport()
	return &tdxpb.QuoteV4{
		Header: q.GetHeader(),
		TdQuoteBody: &tdxpb.TDQuoteBody{
			TeeTcbSvn:      append([]byte(nil), body.GetTeeTcbSvn()...),
			MrSeam:         body.GetMrSeam(),
			MrSignerSeam:   body.GetMrSignerSeam(),
			SeamAttributes: body.GetSeamAttributes(),
			TdAttributes:   append([]byte(nil), body.GetTdAttributes()...),
			Xfam:           body.GetXfam(),
			MrTd:           append([]byte(nil), body.GetMrTd()...),
			MrConfigId:     body.GetMrConfigId(),
			MrOwner:        body.GetMrOwner(),
			MrOwnerConfig:  body.GetMrOwnerConfig(),
			Rtmrs:          rtmrs,
			ReportData:     append([]byte(nil), body.GetReportData()...),
		},
		SignedDataSize: q.GetSignedDataSize(),
		SignedData: &tdxpb.Ecdsa256BitQuoteV4AuthData{
			Signature:           append([]byte(nil), q.GetSignedData().GetSignature()...),
			EcdsaAttestationKey: append([]byte(nil), q.GetSignedData().GetEcdsaAttestationKey()...),
			CertificationData: &tdxpb.CertificationData{
				CertificateDataType: q.GetSignedData().GetCertificationData().GetCertificateDataType(),
				Size:                q.GetSignedData().GetCertificationData().GetSize(),
				QeReportCertificationData: &tdxpb.QEReportCertificationData{
					QeReport: &tdxpb.EnclaveReport{
						CpuSvn:     qe.GetCpuSvn(),
						MiscSelect: qe.GetMiscSelect(),
						Reserved1:  qe.GetReserved1(),
						Attributes: qe.GetAttributes(),
						MrEnclave:  qe.GetMrEnclave(),
						Reserved2:  qe.GetReserved2(),
						MrSigner:   qe.GetMrSigner(),
						Reserved3:  qe.GetReserved3(),
						IsvProdId:  qe.GetIsvProdId(),
						IsvSvn:     qe.GetIsvSvn(),
						Reserved4:  qe.GetReserved4(),
						ReportData: append([]byte(nil), qe.GetReportData()...),
					},
					QeReportSignature:       append([]byte(nil), qeCert.GetQeReportSignature()...),
					QeAuthData:              qeCert.GetQeAuthData(),
					PckCertificateChainData: &tdxpb.PCKCertificateChainData{CertificateDataType: qeCert.GetPckCertificateChainData().GetCertificateDataType()},
				},
			},
		},
		ExtraBytes: q.GetExtraBytes(),
	}
}

// signRaw signs a message the way Intel's structures carry a signature: ECDSA
// over its SHA-256 digest, with r and s as two fixed-width big-endian halves
// rather than DER. go-tdx-guest converts back with abi.SignatureToDER.
func signRaw(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// rawPublicKey is an uncompressed P-256 point without the leading tag byte,
// which is how a quote carries its attestation key.
func rawPublicKey(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 64)
	pub.X.FillBytes(out[:32])
	pub.Y.FillBytes(out[32:])
	return out
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("tdxfake: " + err.Error())
	}
	return b
}

func applyMask(mask, value []byte) []byte {
	out := make([]byte, len(mask))
	for i := range mask {
		if i < len(value) {
			out[i] = mask[i] & value[i]
		}
	}
	return out
}

func writeFile(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("tdxfake: writing %s: %w", path, err)
	}
	return nil
}

// headerBlock is a recorded HTTP response header block, in the shape curl -D
// writes and gvisor.dev/gvisor/attest/verify reads.
func headerBlock(key, value string) []byte {
	return []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		key + ": " + url.QueryEscape(value) + "\r\n" +
		"\r\n")
}

func plainHeaderBlock(contentType string) []byte {
	return []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"\r\n")
}

// signedDocument wraps an already-marshalled inner document with the hex ECDSA
// signature Intel puts beside it, over the inner document's exact bytes.
func signedDocument(field string, inner []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := signRaw(key, inner)
	if err != nil {
		return nil, err
	}
	return []byte(`{"` + field + `":` + string(inner) + `,"signature":"` + hex.EncodeToString(sig) + `"}`), nil
}

// The JSON shapes of Intel's two signed documents. They are declared here
// rather than reused from go-tdx-guest's pcs package because that package's
// types are for reading: its hex fields decode on the way in and have no way
// back out, and the exact bytes matter — the signature is over them.
type tcbInfoDocument struct {
	ID                      string              `json:"id"`
	Version                 int                 `json:"version"`
	IssueDate               string              `json:"issueDate"`
	NextUpdate              string              `json:"nextUpdate"`
	Fmspc                   string              `json:"fmspc"`
	PceID                   string              `json:"pceId"`
	TcbType                 int                 `json:"tcbType"`
	TcbEvaluationDataNumber uint32              `json:"tcbEvaluationDataNumber"`
	TdxModule               tdxModule           `json:"tdxModule"`
	TdxModuleIdentities     []tdxModuleIdentity `json:"tdxModuleIdentities"`
	TcbLevels               []tcbLevel          `json:"tcbLevels"`
}

type tdxModule struct {
	Mrsigner       string `json:"mrsigner"`
	Attributes     string `json:"attributes"`
	AttributesMask string `json:"attributesMask"`
}

type tdxModuleIdentity struct {
	ID             string     `json:"id"`
	Mrsigner       string     `json:"mrsigner"`
	Attributes     string     `json:"attributes"`
	AttributesMask string     `json:"attributesMask"`
	TcbLevels      []tcbLevel `json:"tcbLevels"`
}

type tcbLevel struct {
	Tcb       tcbComponents `json:"tcb"`
	TcbDate   string        `json:"tcbDate"`
	TcbStatus string        `json:"tcbStatus"`
}

type tcbComponents struct {
	SgxTcbcomponents []svn  `json:"sgxtcbcomponents,omitempty"`
	Pcesvn           uint16 `json:"pcesvn,omitempty"`
	TdxTcbcomponents []svn  `json:"tdxtcbcomponents,omitempty"`
	Isvsvn           uint32 `json:"isvsvn,omitempty"`
}

type svn struct {
	Svn byte `json:"svn"`
}

type enclaveIdentityDocument struct {
	ID                      string     `json:"id"`
	Version                 int        `json:"version"`
	IssueDate               string     `json:"issueDate"`
	NextUpdate              string     `json:"nextUpdate"`
	TcbEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	Miscselect              string     `json:"miscselect"`
	MiscselectMask          string     `json:"miscselectMask"`
	Attributes              string     `json:"attributes"`
	AttributesMask          string     `json:"attributesMask"`
	Mrsigner                string     `json:"mrsigner"`
	IsvProdID               uint16     `json:"isvprodid"`
	TcbLevels               []tcbLevel `json:"tcbLevels"`
}
