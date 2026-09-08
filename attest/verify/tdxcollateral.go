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
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

// The collateral directory format.
//
// Intel's provisioning certification service answers four requests, and this
// directory is those four answers written down. Each is a pair of files: the
// response body exactly as Intel served it, and the response headers exactly as
// they came back, because Intel puts the certificate chain that signed the body
// in a header rather than in the body and go-tdx-guest reads it from there.
//
//	tcbinfo-<fmspc>.body      tcbinfo-<fmspc>.headers      TCB info for one platform
//	qeidentity.body           qeidentity.headers           quoting-enclave identity
//	pckcrl-<ca>.body          pckcrl-<ca>.headers          PCK revocation list for one CA
//	rootcrl.body              rootcrl.headers              Intel SGX root CA revocation list
//
// <fmspc> is the twelve lowercase hexadecimal digits of the platform's FMSPC,
// as it appears in the PCK certificate's SGX extension; <ca> is "platform" or
// "processor", the two issuers Intel operates. Both come out of the peer's own
// evidence, so both are checked against those shapes before they are put in a
// path — a file name assembled from an attacker's bytes is a directory
// traversal waiting to be found.
//
// The names are fixed and nothing is discovered by globbing. A verifier asked
// for a platform whose collateral is not here refuses; it does not fetch, and
// it does not fall back to a neighbouring file that happens to be present.
// ADR-0005 is why: a fetch on the handshake path is an availability dependency
// on Intel and a report to Intel of which platforms are talking, and Intel's
// terms forbid it in any case.
const (
	// CollateralQEIdentityName is the file stem of the quoting-enclave
	// identity, which is per Intel rather than per platform.
	CollateralQEIdentityName = "qeidentity"

	// CollateralRootCRLName is the file stem of the Intel SGX root CA's
	// revocation list.
	CollateralRootCRLName = "rootcrl"

	bodySuffix    = ".body"
	headersSuffix = ".headers"
)

// CollateralTCBInfoName is the file stem of the TCB info for one FMSPC.
func CollateralTCBInfoName(fmspc string) string { return "tcbinfo-" + fmspc }

// CollateralPCKCRLName is the file stem of the PCK revocation list for one CA.
func CollateralPCKCRLName(ca string) string { return "pckcrl-" + ca }

// ErrCollateralRefused is what every collateral-loading failure matches: a
// directory that is missing a file, holds one that does not parse, or was
// asked for a platform it was not provisioned for. They are one error because
// they have one remedy — provision, or re-provision, the directory — and
// because the one thing a loader must never do with any of them is fetch.
var ErrCollateralRefused = errors.New("verify: Intel collateral refused")

func refuseCollateral(format string, args ...any) error {
	return fmt.Errorf("%w: %s (ADR-0005)", ErrCollateralRefused, fmt.Sprintf(format, args...))
}

// A CollateralDocument is one Intel response as it was received: the raw body
// and the raw headers, parsed into the map net/http would have produced.
//
// Both halves are kept because both are verified. go-tdx-guest checks the
// body's signature against the certificate chain in the header, so a directory
// that kept only the bodies would hold documents nothing could authenticate.
type CollateralDocument struct {
	// Name is the file stem the two halves were read from.
	Name string

	// Body is the response body, byte for byte.
	Body []byte

	// Header is the response headers with canonical MIME keys, which is what
	// the issuer-chain lookup expects to find them under.
	Header map[string][]string
}

// A TDXCollateral is the Intel collateral one verifier holds for one platform:
// the four documents, plus what was read out of them so that expiry can be
// judged and the root CRL's address known without going near the network.
//
// It is a value read off a directory and nothing more. Whether the documents
// are authentic is not decided here — that is go-tdx-guest's job at every
// verification, against the peer's own PCK chain root — and this type
// deliberately does not pretend to have decided it.
type TDXCollateral struct {
	// Dir is where the four documents were read from.
	Dir string

	// FMSPC and CA are the platform and issuer this collateral is for. A quote
	// naming any other pair needs a different directory, and gets a refusal
	// rather than these documents.
	FMSPC string
	CA    string

	// TCBInfo, QEIdentity, PCKCRL and RootCRL are the four documents.
	TCBInfo    CollateralDocument
	QEIdentity CollateralDocument
	PCKCRL     CollateralDocument
	RootCRL    CollateralDocument

	// tcbInfo is the parsed TCB info. The verifier reads the platform's TCB
	// status out of it after go-tdx-guest has verified its signature; nothing
	// reads it before that.
	tcbInfo pcs.TdxTcbInfo

	// rootCRLURLs are the addresses the root CRL answers to, taken from the
	// CRL distribution points of the root certificate in the quoting-enclave
	// identity's issuer chain — which is exactly where go-tdx-guest looks for
	// them. The getter serves the root CRL at these and refuses every other
	// address.
	rootCRLURLs []string

	// expiries is every instant at which some part of this collateral stops
	// being usable, with a name an operator can act on.
	expiries []CollateralExpiry
}

// A CollateralExpiry is one instant at which one part of the collateral goes
// stale, and the name of that part.
type CollateralExpiry struct {
	// What names the document or certificate, for an operator reading a
	// warning: "the TCB info", "the PCK CRL signing certificate".
	What string

	// At is when it stops being usable.
	At time.Time
}

// LoadTDXCollateral reads the collateral for one FMSPC and one PCK CA out of
// dir.
//
// It is named for its vendor because this package now holds two verifiers and
// a bare Load would not say whose collateral it read. Everything it touches is
// on the local filesystem; there is no code path here that reaches the network,
// and a document that is absent is a refusal rather than a hole to be filled.
func LoadTDXCollateral(dir, fmspc, ca string) (*TDXCollateral, error) {
	if dir == "" {
		return nil, refuseCollateral("no collateral directory was configured")
	}
	if err := checkFMSPC(fmspc); err != nil {
		return nil, err
	}
	if err := checkCA(ca); err != nil {
		return nil, err
	}

	c := &TDXCollateral{Dir: dir, FMSPC: fmspc, CA: ca}
	var err error
	if c.TCBInfo, err = readDocument(dir, CollateralTCBInfoName(fmspc)); err != nil {
		return nil, err
	}
	if c.QEIdentity, err = readDocument(dir, CollateralQEIdentityName); err != nil {
		return nil, err
	}
	if c.PCKCRL, err = readDocument(dir, CollateralPCKCRLName(ca)); err != nil {
		return nil, err
	}
	if c.RootCRL, err = readDocument(dir, CollateralRootCRLName); err != nil {
		return nil, err
	}
	if err := c.interpret(); err != nil {
		return nil, err
	}
	return c, nil
}

// checkFMSPC refuses anything that is not twelve lowercase hexadecimal digits.
// The FMSPC comes out of the peer's PCK certificate, so it is an attacker's
// bytes, and it is about to become part of a file name.
func checkFMSPC(fmspc string) error {
	const want = 12
	if len(fmspc) != want {
		return refuseCollateral("FMSPC %q is %d characters, want %d hexadecimal digits", fmspc, len(fmspc), want)
	}
	for i := 0; i < len(fmspc); i++ {
		c := fmspc[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return refuseCollateral("FMSPC %q is not lowercase hexadecimal", fmspc)
		}
	}
	return nil
}

// checkCA refuses any issuer name Intel does not operate, for the same reason.
func checkCA(ca string) error {
	switch ca {
	case "platform", "processor":
		return nil
	default:
		return refuseCollateral("PCK CA %q is neither %q nor %q", ca, "platform", "processor")
	}
}

// readDocument reads one body-and-headers pair.
func readDocument(dir, name string) (CollateralDocument, error) {
	bodyPath := filepath.Join(dir, name+bodySuffix)
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		return CollateralDocument{}, refuseCollateral("reading %s: %v; this platform's collateral is not provisioned here — provision it, do not fetch", bodyPath, err)
	}
	if len(body) == 0 {
		return CollateralDocument{}, refuseCollateral("%s is empty", bodyPath)
	}
	headersPath := filepath.Join(dir, name+headersSuffix)
	raw, err := os.ReadFile(headersPath)
	if err != nil {
		return CollateralDocument{}, refuseCollateral("reading %s: %v; the body without its headers holds no issuer chain and cannot be verified", headersPath, err)
	}
	header, err := parseHeaders(raw)
	if err != nil {
		return CollateralDocument{}, refuseCollateral("parsing %s: %v", headersPath, err)
	}
	return CollateralDocument{Name: name, Body: body, Header: header}, nil
}

// parseHeaders turns a recorded HTTP response header block into the map an
// HTTP client would have produced.
//
// The file is what curl -D wrote: a status line, then the headers, CRLF
// terminated. Keys are canonicalised, because go-tdx-guest looks its
// issuer chains up by exact key — header["Tcb-Info-Issuer-Chain"], not
// http.Header.Get — and Intel sends "TCB-Info-Issuer-Chain". Canonicalising
// here is what makes those two the same string.
func parseHeaders(raw []byte) (map[string][]string, error) {
	text := string(raw)
	// Skip any number of status lines: a response that was redirected or that
	// negotiated a protocol upgrade has more than one header block, and the
	// last one is the one that carries the body's headers.
	blocks := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n")
	var last string
	for _, b := range blocks {
		if strings.TrimSpace(b) != "" {
			last = b
		}
	}
	if last == "" {
		return nil, errors.New("no headers found")
	}
	lines := strings.Split(last, "\n")
	if len(lines) > 0 && strings.HasPrefix(strings.ToUpper(lines[0]), "HTTP/") {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil, errors.New("the header block holds only a status line")
	}
	body := strings.Join(lines, "\r\n") + "\r\n\r\n"
	mime, err := textproto.NewReader(bufio.NewReader(strings.NewReader(body))).ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(mime))
	for k, v := range mime {
		out[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	return out, nil
}

// interpret reads out of the four documents everything the verifier needs
// before it can decide anything: the expiry of each part, and where the root
// CRL lives.
//
// Nothing here is a trust decision. The signatures on these documents are
// checked by go-tdx-guest against the root the peer's own PCK chain descends
// from, every time a quote is verified, and this parse would happily read a
// document nobody signed.
func (c *TDXCollateral) interpret() error {
	if err := json.Unmarshal(c.TCBInfo.Body, &c.tcbInfo); err != nil {
		return refuseCollateral("%s does not parse as Intel TCB info: %v", c.TCBInfo.Name+bodySuffix, err)
	}
	if got := c.tcbInfo.TcbInfo.Fmspc; !strings.EqualFold(got, c.FMSPC) {
		return refuseCollateral("%s is the TCB info for FMSPC %q, but it is filed under %q", c.TCBInfo.Name+bodySuffix, got, c.FMSPC)
	}
	var qe pcs.QeIdentity
	if err := json.Unmarshal(c.QEIdentity.Body, &qe); err != nil {
		return refuseCollateral("%s does not parse as an Intel enclave identity: %v", c.QEIdentity.Name+bodySuffix, err)
	}

	pckCRL, err := x509.ParseRevocationList(c.PCKCRL.Body)
	if err != nil {
		return refuseCollateral("%s does not parse as a CRL: %v", c.PCKCRL.Name+bodySuffix, err)
	}
	rootCRL, err := x509.ParseRevocationList(c.RootCRL.Body)
	if err != nil {
		return refuseCollateral("%s does not parse as a CRL: %v", c.RootCRL.Name+bodySuffix, err)
	}

	// The issuer chains, under the keys go-tdx-guest reads them from. Each is
	// a signing certificate followed by the Intel root.
	tcbSigner, tcbRoot, err := issuerChain(c.TCBInfo, "Tcb-Info-Issuer-Chain")
	if err != nil {
		return err
	}
	qeSigner, qeRoot, err := issuerChain(c.QEIdentity, "Sgx-Enclave-Identity-Issuer-Chain")
	if err != nil {
		return err
	}
	crlSigner, crlRoot, err := issuerChain(c.PCKCRL, "Sgx-Pck-Crl-Issuer-Chain")
	if err != nil {
		return err
	}

	c.rootCRLURLs = append([]string(nil), qeRoot.CRLDistributionPoints...)
	if len(c.rootCRLURLs) == 0 {
		return refuseCollateral("the root certificate in %s names no CRL distribution point, so nothing says where %s belongs",
			c.QEIdentity.Name+headersSuffix, c.RootCRL.Name+bodySuffix)
	}

	c.expiries = []CollateralExpiry{
		{"the TCB info", c.tcbInfo.TcbInfo.NextUpdate},
		{"the quoting-enclave identity", qe.EnclaveIdentity.NextUpdate},
		{"the PCK CRL", pckCRL.NextUpdate},
		{"the root CA CRL", rootCRL.NextUpdate},
		{"the TCB info signing certificate", tcbSigner.NotAfter},
		{"the TCB info issuer root certificate", tcbRoot.NotAfter},
		{"the quoting-enclave identity signing certificate", qeSigner.NotAfter},
		{"the quoting-enclave identity issuer root certificate", qeRoot.NotAfter},
		{"the PCK CRL signing certificate", crlSigner.NotAfter},
		{"the PCK CRL issuer root certificate", crlRoot.NotAfter},
	}
	return nil
}

// issuerChain pulls the signing and root certificates out of one document's
// issuer-chain header, the way go-tdx-guest will: one header value, URL
// escaped, holding two PEM certificates.
func issuerChain(doc CollateralDocument, key string) (signer, root *x509.Certificate, err error) {
	values, ok := doc.Header[key]
	if !ok || len(values) != 1 || values[0] == "" {
		return nil, nil, refuseCollateral("%s carries no %s header, so the body it accompanies has no issuer chain", doc.Name+headersSuffix, key)
	}
	chain, err := url.QueryUnescape(values[0])
	if err != nil {
		return nil, nil, refuseCollateral("the %s header in %s is not URL escaped: %v", key, doc.Name+headersSuffix, err)
	}
	certs, err := parsePEMCertificates([]byte(chain))
	if err != nil {
		return nil, nil, refuseCollateral("the %s header in %s: %v", key, doc.Name+headersSuffix, err)
	}
	if len(certs) != 2 {
		return nil, nil, refuseCollateral("the %s header in %s holds %d certificates, want a signing certificate and a root", key, doc.Name+headersSuffix, len(certs))
	}
	return certs[0], certs[1], nil
}

// CheckFresh reports whether every part of the collateral is still usable at
// now, naming the first part that is not.
//
// This is run before go-tdx-guest is asked anything, so that stale collateral
// is reported as stale rather than as whatever flat error the library returns
// when its own expiry check fails — indistinguishable, at the reason level,
// from a peer that forged its chain. Both refuse as
// [attest.ReasonChainNotRooted], because both answer the same question: is
// this evidence rooted now. What tells them apart is the refusal's detail,
// which names the verifier's own provisioning directory and ADR-0007 rather
// than anything the peer did.
func (c *TDXCollateral) CheckFresh(now time.Time) error {
	for _, e := range c.expiries {
		if now.After(e.At) {
			return fmt.Errorf("%s expired at %s, and it is now %s",
				e.What, e.At.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// EarliestExpiry is the first moment this collateral stops being usable, and
// the name of the part that goes first. It is what an operator tool warns on:
// the directory has to be re-provisioned before this instant, or every peer is
// refused, however healthy every peer is.
func (c *TDXCollateral) EarliestExpiry() CollateralExpiry {
	earliest := c.expiries[0]
	for _, e := range c.expiries[1:] {
		if e.At.Before(earliest.At) {
			earliest = e
		}
	}
	return earliest
}

// EvaluationDataNumber is the TCB info's tcbEvaluationDataNumber: Intel raises
// it at every TCB recovery, so it says how recent this collateral is. A
// reference value's floor is compared against it, which is what stops a host
// provisioning collateral from before the recovery that matters.
func (c *TDXCollateral) EvaluationDataNumber() uint32 {
	n := c.tcbInfo.TcbInfo.TcbEvaluationDataNumber
	if n < 0 {
		return 0
	}
	return uint32(n)
}

// getter serves the four provisioned documents at the four addresses Intel
// serves them from, and refuses every other request.
//
// go-tdx-guest has no offline mode: GetCollateral means "fetch these four
// URLs", and the only way to run it against a directory is to hand it
// something that answers those URLs from the directory. Every other URL is
// refused loudly rather than silently, so that a library upgrade that starts
// fetching a fifth thing fails visibly instead of quietly reinstating the
// network dependency ADR-0005 removed.
func (c *TDXCollateral) getter() tdxtrust.HTTPSGetter {
	served := map[string]CollateralDocument{
		pcs.TcbInfoURL(c.FMSPC): c.TCBInfo,
		pcs.QeIdentityURL():     c.QEIdentity,
		pcs.PckCrlURL(c.CA):     c.PCKCRL,
	}
	for _, u := range c.rootCRLURLs {
		served[u] = c.RootCRL
	}
	return provisionedGetter{served: served, dir: c.Dir}
}

type provisionedGetter struct {
	served map[string]CollateralDocument
	dir    string
}

func (g provisionedGetter) Get(u string) (map[string][]string, []byte, error) {
	doc, ok := g.served[u]
	if !ok {
		return nil, nil, fmt.Errorf("verify: refusing to fetch %q: Intel collateral is provisioned in %s and never fetched (ADR-0005)", u, g.dir)
	}
	return doc.Header, doc.Body, nil
}

// parsePEMCertificates decodes a concatenation of PEM certificate blocks.
func parsePEMCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := pemBytes; len(bytes.TrimSpace(rest)) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("trailing bytes that are not a PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block type is %q, want %q", block.Type, "CERTIFICATE")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d does not parse: %v", len(out), err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificates found")
	}
	return out, nil
}
