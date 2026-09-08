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

package tdxfake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/verify"
)

// writeCollateral generates and writes the four Intel documents this platform's
// quotes are verified against.
//
// They are generated rather than copied because the point of the fake is to be
// able to move them: a level Intel calls out of date, an evaluation data number
// from before a recovery, a nextUpdate in the past, a signature by a stranger.
// Their shape mirrors Intel's real answers for these platforms
// (docs/snp/evidence/tdx/collateral), and the values that have to agree with
// the quote — the FMSPC, the PCEID, the SEAM measurements, the quoting
// enclave's identity — are derived from the quote rather than restated, so that
// a fake built from a different recording is still self-consistent.
func (p *Platform) writeCollateral() error {
	tcbSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tdxfake: generating the TCB signing key: %w", err)
	}
	tcbSigning, err := p.mintTCBSigning(&tcbSigningKey.PublicKey)
	if err != nil {
		return err
	}
	// The key the documents are actually signed with. When a test asks for
	// collateral signed by a stranger this is a key nothing vouches for, while
	// the issuer chain still names the legitimate signing certificate — which
	// is what a forged Intel document looks like.
	documentKey := tcbSigningKey
	if p.cfg.CollateralSignedByStranger {
		if documentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return fmt.Errorf("tdxfake: generating a stranger's key: %w", err)
		}
	}

	nextUpdate := p.cfg.CollateralNextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = p.now.Add(collateralValidFor)
	}
	issued := nextUpdate.Add(-collateralValidFor)

	tcbInfo, err := p.tcbInfoDocument(issued, nextUpdate)
	if err != nil {
		return err
	}
	tcbInfoDoc, err := signedDocument("tcbInfo", tcbInfo, documentKey)
	if err != nil {
		return fmt.Errorf("tdxfake: signing the TCB info: %w", err)
	}
	qeIdentity, err := p.enclaveIdentityDocument(issued, nextUpdate)
	if err != nil {
		return err
	}
	qeIdentityDoc, err := signedDocument("enclaveIdentity", qeIdentity, documentKey)
	if err != nil {
		return fmt.Errorf("tdxfake: signing the enclave identity: %w", err)
	}

	rootCRL, err := p.mintCRL(p.root, p.rootKey, 1, issued, nextUpdate)
	if err != nil {
		return fmt.Errorf("tdxfake: the root CA CRL: %w", err)
	}
	pckCRL, err := p.mintCRL(p.intermediate, p.intermediateKey, 2, issued, nextUpdate)
	if err != nil {
		return fmt.Errorf("tdxfake: the PCK CRL: %w", err)
	}

	// The issuer chain Intel puts in a response header: the signing certificate
	// and then the root, PEM encoded and URL escaped.
	signingChain := string(certPEM(tcbSigning)) + string(certPEM(p.root))
	crlChain := string(certPEM(p.intermediate)) + string(certPEM(p.root))

	dir := p.cfg.CollateralDir
	files := []struct {
		name string
		data []byte
	}{
		{verify.CollateralTCBInfoName(p.fmspc) + ".body", tcbInfoDoc},
		{verify.CollateralTCBInfoName(p.fmspc) + ".headers", headerBlock("TCB-Info-Issuer-Chain", signingChain)},
		{verify.CollateralQEIdentityName + ".body", qeIdentityDoc},
		{verify.CollateralQEIdentityName + ".headers", headerBlock("SGX-Enclave-Identity-Issuer-Chain", signingChain)},
		{verify.CollateralPCKCRLName(p.ca) + ".body", pckCRL},
		{verify.CollateralPCKCRLName(p.ca) + ".headers", headerBlock("SGX-PCK-CRL-Issuer-Chain", crlChain)},
		{verify.CollateralRootCRLName + ".body", rootCRL},
		{verify.CollateralRootCRLName + ".headers", plainHeaderBlock("binary/octet-stream")},
	}
	for _, f := range files {
		if err := writeFile(dir, f.name, f.data); err != nil {
			return err
		}
	}
	return nil
}

// mintTCBSigning issues the certificate Intel signs its TCB info and enclave
// identity with, under this platform's test root. go-tdx-guest checks its
// common name by string and chains it to the trusted root, so it has to be
// named exactly this and issued by exactly that.
func (p *Platform) mintTCBSigning(pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName:   "Intel SGX TCB Signing",
			Organization: []string{"Intel Corporation"},
			Locality:     []string{"Santa Clara"},
			Province:     []string{"CA"},
			Country:      []string{"US"},
		},
		NotBefore:             p.now.Add(-certificateValidFor),
		NotAfter:              p.now.Add(certificateValidFor),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.root, pub, p.rootKey)
	if err != nil {
		return nil, fmt.Errorf("tdxfake: the TCB signing certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// mintCRL issues an empty revocation list under one of the test CAs. It is
// empty because revocation is not what any of these tests are about; what
// matters is that it exists, is signed by the right key, names the right
// issuer, and expires when the rest of the collateral does.
func (p *Platform) mintCRL(issuer *x509.Certificate, key *ecdsa.PrivateKey, number int64, issued, nextUpdate time.Time) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: issued,
		NextUpdate: nextUpdate,
	}, issuer, key)
}

// tcbInfoDocument builds the inner tcbInfo object, whose exact bytes are what
// Intel's signature covers.
//
// The levels are built around this platform rather than transcribed: the first
// one is exactly the platform's own SVNs, so it is the level Intel's matching
// algorithm lands on, and it carries whatever status the config asked for. One
// strictly lower level follows it, because Intel publishes a descending list
// and a list of one would not show that the first match is the one that counts.
func (p *Platform) tcbInfoDocument(issued, nextUpdate time.Time) ([]byte, error) {
	exts, err := pcs.PckCertificateExtensions(p.pck)
	if err != nil {
		return nil, err
	}
	body := p.recorded.GetTdQuoteBody()
	teeTCBSvn := body.GetTeeTcbSvn()
	if p.cfg.TeeTCBSvn != nil {
		teeTCBSvn = p.cfg.TeeTCBSvn
	}

	status := p.cfg.TCBStatus
	if status == "" {
		status = attest.TDXTCBUpToDate
	}
	evaluation := p.cfg.EvaluationDataNumber
	if evaluation == 0 {
		evaluation = DefaultEvaluationDataNumber
	}

	match := tcbLevel{
		Tcb: tcbComponents{
			SgxTcbcomponents: svns(exts.TCB.CPUSvnComponents),
			Pcesvn:           exts.TCB.PCESvn,
			TdxTcbcomponents: svns(teeTCBSvn),
		},
		TcbDate:   issued.UTC().Format(time.RFC3339),
		TcbStatus: string(status),
	}
	below := tcbLevel{
		Tcb: tcbComponents{
			SgxTcbcomponents: svns(decrement(exts.TCB.CPUSvnComponents)),
			Pcesvn:           decrementU16(exts.TCB.PCESvn),
			TdxTcbcomponents: svns(decrement(teeTCBSvn)),
		},
		TcbDate:   issued.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		TcbStatus: "OutOfDate",
	}

	doc := tcbInfoDocument{
		ID:                      "TDX",
		Version:                 3,
		IssueDate:               issued.UTC().Format(time.RFC3339),
		NextUpdate:              nextUpdate.UTC().Format(time.RFC3339),
		Fmspc:                   exts.FMSPC,
		PceID:                   exts.PCEID,
		TcbType:                 0,
		TcbEvaluationDataNumber: evaluation,
		TdxModule: tdxModule{
			Mrsigner:       strings.ToUpper(hex.EncodeToString(body.GetMrSignerSeam())),
			Attributes:     strings.ToUpper(hex.EncodeToString(applyMask(seamAttributesMask, body.GetSeamAttributes()))),
			AttributesMask: strings.ToUpper(hex.EncodeToString(seamAttributesMask)),
		},
		TcbLevels: []tcbLevel{match, below},
	}

	// A non-zero second byte of TEE_TCB_SVN names a TDX module version, and
	// Intel then publishes that module's own levels under an identity keyed by
	// it. go-tdx-guest requires that identity to exist and to call the module
	// up to date, so a fake without it would be refused for a reason no test
	// asked about.
	if len(teeTCBSvn) >= 2 && teeTCBSvn[1] > 0 {
		doc.TdxModuleIdentities = []tdxModuleIdentity{{
			ID:             "TDX_" + hex.EncodeToString(teeTCBSvn[1:2]),
			Mrsigner:       strings.ToUpper(hex.EncodeToString(body.GetMrSignerSeam())),
			Attributes:     strings.ToUpper(hex.EncodeToString(applyMask(seamAttributesMask, body.GetSeamAttributes()))),
			AttributesMask: strings.ToUpper(hex.EncodeToString(seamAttributesMask)),
			TcbLevels: []tcbLevel{{
				Tcb:       tcbComponents{Isvsvn: uint32(teeTCBSvn[0])},
				TcbDate:   issued.UTC().Format(time.RFC3339),
				TcbStatus: "UpToDate",
			}},
		}}
	}
	return json.Marshal(doc)
}

// enclaveIdentityDocument builds the inner enclaveIdentity object.
//
// Everything in it is derived from the quoting-enclave report the recording
// carries, through Intel's own masks: a fake whose identity did not describe
// the quoting enclave in its own quote would be refused for a reason no test
// asked about.
func (p *Platform) enclaveIdentityDocument(issued, nextUpdate time.Time) ([]byte, error) {
	qe := p.recorded.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()

	miscSelect := make([]byte, 4)
	binary.LittleEndian.PutUint32(miscSelect, qe.GetMiscSelect()&binary.LittleEndian.Uint32(qeMiscSelectMask))

	doc := enclaveIdentityDocument{
		ID:                      "TD_QE",
		Version:                 2,
		IssueDate:               issued.UTC().Format(time.RFC3339),
		NextUpdate:              nextUpdate.UTC().Format(time.RFC3339),
		TcbEvaluationDataNumber: p.cfg.EvaluationDataNumber,
		Miscselect:              strings.ToUpper(hex.EncodeToString(miscSelect)),
		MiscselectMask:          strings.ToUpper(hex.EncodeToString(qeMiscSelectMask)),
		Attributes:              strings.ToUpper(hex.EncodeToString(applyMask(qeAttributesMask, qe.GetAttributes()))),
		AttributesMask:          strings.ToUpper(hex.EncodeToString(qeAttributesMask)),
		Mrsigner:                strings.ToUpper(hex.EncodeToString(qe.GetMrSigner())),
		IsvProdID:               uint16(qe.GetIsvProdId()),
		TcbLevels: []tcbLevel{{
			Tcb:       tcbComponents{Isvsvn: qe.GetIsvSvn()},
			TcbDate:   issued.UTC().Format(time.RFC3339),
			TcbStatus: "UpToDate",
		}},
	}
	if doc.TcbEvaluationDataNumber == 0 {
		doc.TcbEvaluationDataNumber = DefaultEvaluationDataNumber
	}
	return json.Marshal(doc)
}

func svns(components []byte) []svn {
	out := make([]svn, len(components))
	for i, c := range components {
		out[i] = svn{Svn: c}
	}
	return out
}

func decrement(components []byte) []byte {
	out := make([]byte, len(components))
	for i, c := range components {
		if c > 0 {
			out[i] = c - 1
		}
	}
	return out
}

func decrementU16(v uint16) uint16 {
	if v == 0 {
		return 0
	}
	return v - 1
}
