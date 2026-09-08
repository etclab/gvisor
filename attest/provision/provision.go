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

// Package provision fetches the certificate chain for one SEV-SNP platform
// from AMD's key distribution service, validates it, and writes it where a
// tunneld reads it locally — so that establishing a tunnel later reaches no
// network (ADR-0005).
//
// # Why this exists
//
// Ticket 01 established that the platform's own certificate table is empty on
// the host this was built against and that no operator action fills it. The
// chain therefore has to come from somewhere else, and the only alternative to
// provisioning it ahead of time is fetching it at handshake time — which puts
// an outbound call to AMD on the critical path of every tunnel and lets AMD
// observe which chips are talking. The chain is public, self-validating
// against the AMD root and worthless to forge, so it can ride the same
// read-only config device as the reference value set (ADR-0004's argument).
//
// # The two halves
//
// [Fetch] is the operator-side half: it reads the chip identity and TCB out of
// an attestation report the platform produced, asks the key distribution
// service for exactly that chain, and validates the pair through the same
// verifier a peer will use before returning it. A chain that would not verify
// is never written, so a bad fetch fails here rather than at a handshake. The
// chip identity and TCB are recorded beside the chain so that staleness is
// detectable rather than inferred from a failure.
//
// [Load] and [Chain.CheckFor] are the consumer-side half, for the acquirer in
// gvisor.dev/gvisor/attest/tsm: read the artifact back, confirm the metadata
// describes the chain beside it, and confirm the chain is the one for the
// platform's *current* report. A missing chain, or one whose recorded TCB is
// not the platform's reported TCB, is refused with an error naming ADR-0005. Nothing here fetches
// on the consumer's behalf; a silent fallback would reinstate exactly the
// dependency ADR-0005 removes, and do it invisibly.
//
// # The stale-chain symptom
//
// The chain is per chip and per TCB, so a TCB update makes the provisioned
// chain stale. Locally that is caught by [Chain.CheckFor]. If it is not — if a
// stale chain reaches a handshake — the verification library compares the
// report's TCB against the chain's and refuses the pair as malformed evidence,
// and that refusal appears at the *peer*, not here. That is the confusing
// direction, which is why the verifier's detail already names ADR-0005 and why
// re-provisioning is part of any TCB update.
//
// # Vendor specificity
//
// Everything here is AMD-specific: the key distribution service, the
// certificate table format, the chip identity. It is provisioning tooling
// rather than the verification path, and it keeps go-sev-guest's types out of
// its exported surface for the same reason gvisor.dev/gvisor/attest/verify
// does.
package provision

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/verify"
)

// ChainFileName is the name of the chain on the config device: the VCEK, ASK
// and ARK in AMD's certificate table format — the same bytes the platform's
// report interface would have returned had it ever returned any, and the
// bytes an acquirer puts in [attest.Evidence.Chain] verbatim.
const ChainFileName = "certificate-chain.bin"

// MetadataFileName is the name of the document beside the chain recording
// which chip and which TCB it was fetched for. It is JSON so that an operator
// can read it; the check that it describes the chain beside it is [Load]'s.
const MetadataFileName = "certificate-chain.json"

// MetadataFormat is the value of the metadata document's format field.
const MetadataFormat = "gvisor.dev/gvisor/attest/certificate-chain"

// MetadataVersion is the document version this package writes and the only
// one it reads.
const MetadataVersion = 1

// ErrChainRefused is what every consumer-side failure matches: a chain that is
// missing, does not parse, disagrees with its metadata, or is not the chain
// for the platform's current report. They are one error deliberately — the
// one thing a consumer must never do is treat any of them as permission to
// fetch.
var ErrChainRefused = errors.New("provision: certificate chain refused")

// refuse builds a consumer-side refusal. Every one names ADR-0005, because
// every one has the same remedy — provision, or re-provision, the chain — and
// an operator reading any of them should be pointed there rather than at the
// evidence or the peer.
func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s (ADR-0005)", ErrChainRefused, fmt.Sprintf(format, args...))
}

// A Getter fetches one URL from the key distribution service. It is the one
// place this package reaches the network, and it is an interface so that tests
// can stand in a fake service and so that the consumer half cannot be handed
// one at all.
type Getter interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// Options configures a [Fetch].
type Options struct {
	// Getter fetches from the key distribution service. Nil means HTTPS with
	// go-sev-guest's retry policy, which honours AMD's stated rate limit.
	Getter Getter

	// VendorRootPEM and ProductLine configure the root the fetched chain is
	// validated against, with the meaning [verify.Options] gives them. Empty
	// means the AMD roots embedded in go-sev-guest, which is right in
	// production and wrong in a test.
	VendorRootPEM []byte
	ProductLine   string

	// Now is the instant at which certificate validity is judged. Zero means
	// time.Now.
	Now time.Time
}

// A Chain is a provisioned certificate chain together with the identity it
// was fetched for.
type Chain struct {
	// Vendor is the hardware the chain endorses.
	Vendor attest.Vendor

	// ProductLine is the AMD product line, such as "Genoa", which selects the
	// root the chain descends from.
	ProductLine string

	// ChipID is the chip the endorsement key belongs to: the report's CHIP_ID.
	ChipID []byte

	// TCB is the level the endorsement key was issued for. A report from this
	// chip verifies against this chain only while its reported TCB is exactly
	// this.
	TCB attest.TCB

	// FetchedAt is when the chain was retrieved, for an operator reading the
	// metadata. It is recorded, never checked.
	FetchedAt time.Time

	// Bytes is the chain in AMD's certificate table format.
	Bytes []byte
}

// Fetch retrieves and validates the chain for the platform that produced
// report, an SEV-SNP attestation report in its ABI form.
//
// The chip identity, TCB and product line come from the report; nothing is
// taken from the caller that the platform did not say. The chain is validated
// by handing the report and the fetched chain to the verifier a peer would use
// (gvisor.dev/gvisor/attest/verify), against a reference value built from the
// report's own measurement, TCB and policy — so what is checked is precisely
// that this report, with this chain, would be accepted. A chain that fails is
// returned as an error and never reaches [Write].
func Fetch(ctx context.Context, report []byte, opts Options) (Chain, error) {
	id, err := identify(report)
	if err != nil {
		return Chain{}, err
	}
	getter := opts.Getter
	if getter == nil {
		getter = kdsGetter{trust.DefaultHTTPSGetter()}
	}

	vcekURL := kds.VCEKCertURL(id.productLine, id.chipID, id.tcbVersion)
	vcek, err := getter.Get(ctx, vcekURL)
	if err != nil {
		return Chain{}, fmt.Errorf("provision: fetching the VCEK from %s: %w", vcekURL, err)
	}
	rootURL := kds.ProductCertChainURL(abi.VcekReportSigner, id.productLine)
	rootPEM, err := getter.Get(ctx, rootURL)
	if err != nil {
		return Chain{}, fmt.Errorf("provision: fetching the ASK and ARK from %s: %w", rootURL, err)
	}
	ask, ark, err := kds.ParseProductCertChain(rootPEM)
	if err != nil {
		return Chain{}, fmt.Errorf("provision: the ASK and ARK from %s do not parse: %w", rootURL, err)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	c := Chain{
		Vendor:      attest.VendorAMDSEVSNP,
		ProductLine: id.productLine,
		ChipID:      id.chipID,
		TCB:         id.tcb,
		FetchedAt:   now.UTC().Truncate(time.Second),
		Bytes:       certTable(vcek, ask, ark),
	}
	if err := validate(ctx, report, c, opts); err != nil {
		return Chain{}, err
	}
	return c, nil
}

// validate runs the fetched chain through the verifier a peer would use.
func validate(ctx context.Context, report []byte, c Chain, opts Options) error {
	parsed, err := abi.ReportToProto(report)
	if err != nil {
		return fmt.Errorf("provision: report does not parse: %w", err)
	}
	policy, err := abi.ParseSnpPolicy(parsed.GetPolicy())
	if err != nil {
		return fmt.Errorf("provision: report's guest policy does not parse: %w", err)
	}
	v, err := verify.New(verify.Options{VendorRootPEM: opts.VendorRootPEM, ProductLine: opts.ProductLine, Now: opts.Now})
	if err != nil {
		return fmt.Errorf("provision: %w", err)
	}
	// The reference value is the report's own facts: the check is whether this
	// report with this chain is authentic and coherent, not whether the image
	// is one anybody wants to admit — that is the reference value author's
	// question, answered elsewhere.
	self := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: parsed.GetMeasurement(),
		MinimumTCB:        c.TCB,
		GuestPolicy: attest.GuestPolicy{
			ABIMajor:            policy.ABIMajor,
			ABIMinor:            policy.ABIMinor,
			AllowSMT:            policy.SMT,
			AllowMigrationAgent: policy.MigrateMA,
			AllowDebug:          policy.Debug,
			RequireSingleSocket: policy.SingleSocket,
		},
	}}}
	ev := attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: report, Chain: c.Bytes}
	if _, err := v.Verify(ctx, ev, self); err != nil {
		detail := err.Error()
		var r *attest.Refusal
		if errors.As(err, &r) {
			detail = r.LogString()
		}
		return fmt.Errorf("provision: the fetched chain does not verify this platform's report and was not written: %s", detail)
	}
	return nil
}

// Write writes c to dir as [ChainFileName] and [MetadataFileName]. Both are
// written to temporary names and renamed into place, so a reader never sees a
// chain without its metadata or a half-written file.
func Write(dir string, c Chain) error {
	if len(c.Bytes) == 0 {
		return errors.New("provision: refusing to write an empty chain")
	}
	doc, err := json.MarshalIndent(metadata{
		Format:      MetadataFormat,
		Version:     MetadataVersion,
		Vendor:      c.Vendor,
		ProductLine: c.ProductLine,
		ChipID:      hex.EncodeToString(c.ChipID),
		TCB:         metadataTCB{c.TCB.Bootloader, c.TCB.TEE, c.TCB.SNP, c.TCB.Microcode},
		FetchedAt:   c.FetchedAt.UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("provision: encoding metadata: %w", err)
	}
	doc = append(doc, '\n')
	if err := writeAtomically(filepath.Join(dir, ChainFileName), c.Bytes); err != nil {
		return err
	}
	return writeAtomically(filepath.Join(dir, MetadataFileName), doc)
}

// Load reads the chain and its metadata from dir and checks that they describe
// each other: the chain parses as a certificate table holding a VCEK, and the
// chip identity and TCB in that certificate's extensions are the ones the
// metadata records. It does not check the chain against any report — that is
// [Chain.CheckFor], which needs the platform's current report — and it does
// not validate the chain to the root, which is the verifier's job at every
// handshake.
//
// A missing file is [ErrChainRefused] like any other failure, not an absence
// a caller could act on.
func Load(dir string) (Chain, error) {
	docPath := filepath.Join(dir, MetadataFileName)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return Chain{}, refuse("reading %s: %v; no certificate chain is provisioned here — provision one, do not fetch", docPath, err)
	}
	chainPath := filepath.Join(dir, ChainFileName)
	raw, err := os.ReadFile(chainPath)
	if err != nil {
		return Chain{}, refuse("reading %s: %v; no certificate chain is provisioned here — provision one, do not fetch", chainPath, err)
	}
	return parse(doc, raw)
}

// CheckFor reports whether c is the chain for the platform that produced
// report: same chip, and a reported TCB equal to the one the chain was issued
// for. Any other answer is [ErrChainRefused] naming ADR-0005, because a chain
// that passes this check and still fails will fail at the peer, and this is
// the last place the failure can be pointed in the right direction.
func (c Chain) CheckFor(report []byte) error {
	id, err := identify(report)
	if err != nil {
		return err
	}
	if !bytes.Equal(id.chipID, c.ChipID) {
		return refuse("the provisioned chain is for chip %x but this platform reports chip %x; "+
			"re-provision the chain for this platform", c.ChipID, id.chipID)
	}
	if id.tcb != c.TCB {
		return refuse("the provisioned chain was issued for TCB %s but this platform reports TCB %s: "+
			"the chain is stale, which peers would refuse as malformed evidence; "+
			"re-provision the chain after any TCB update", tcbString(c.TCB), tcbString(id.tcb))
	}
	if id.productLine != c.ProductLine {
		return refuse("the provisioned chain is for product line %q but this platform reports %q",
			c.ProductLine, id.productLine)
	}
	return nil
}

// LoadFor is [Load] followed by [Chain.CheckFor]: the one call an acquirer
// makes to obtain the chain to bundle with evidence, with every way of getting
// it wrong refused.
func LoadFor(dir string, report []byte) (Chain, error) {
	c, err := Load(dir)
	if err != nil {
		return Chain{}, err
	}
	if err := c.CheckFor(report); err != nil {
		return Chain{}, err
	}
	return c, nil
}

// identity is what a report says about the platform that produced it, as far
// as fetching its chain is concerned.
type identity struct {
	productLine string
	chipID      []byte
	tcb         attest.TCB
	tcbVersion  kds.TCBVersion
}

func identify(report []byte) (identity, error) {
	parsed, err := abi.ReportToProto(report)
	if err != nil {
		return identity{}, refuse("report does not parse: %v", err)
	}
	info, err := abi.ParseSignerInfo(parsed.GetSignerInfo())
	if err != nil {
		return identity{}, refuse("report's signer info does not parse: %v", err)
	}
	if info.SigningKey != abi.VcekReportSigner {
		return identity{}, refuse("report is signed by key type %v, and only VCEK-signed reports have a chain the key distribution service serves", info.SigningKey)
	}
	if parsed.GetCpuid1EaxFms() == 0 {
		return identity{}, refuse("report version %d carries no CPUID family/model/stepping, so its product line cannot be determined", parsed.GetVersion())
	}
	productLine := kds.ProductLineFromFms(parsed.GetCpuid1EaxFms())
	if _, err := kds.ParseProductLine(productLine); err != nil {
		return identity{}, refuse("report's CPUID %#x names no known product line: %v", parsed.GetCpuid1EaxFms(), err)
	}
	// The reported TCB is the one the endorsement key is issued for and the one
	// the verifier compares against the chain's.
	tcbVersion := kds.TCBVersion(parsed.GetReportedTcb())
	parts := kds.DecomposeTCBVersion(tcbVersion)
	return identity{
		productLine: productLine,
		chipID:      append([]byte(nil), parsed.GetChipId()...),
		tcb:         attest.TCB{Bootloader: parts.BlSpl, TEE: parts.TeeSpl, SNP: parts.SnpSpl, Microcode: parts.UcodeSpl},
		tcbVersion:  tcbVersion,
	}, nil
}

// parse turns the two files into a Chain, refusing any pair that does not
// describe itself consistently.
func parse(doc, raw []byte) (Chain, error) {
	var m metadata
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Chain{}, refuse("metadata does not parse: %v", err)
	}
	if m.Format != MetadataFormat {
		return Chain{}, refuse("metadata format is %q, want %q", m.Format, MetadataFormat)
	}
	if m.Version != MetadataVersion {
		return Chain{}, refuse("metadata version is %d, this reader understands only %d", m.Version, MetadataVersion)
	}
	if m.Vendor != attest.VendorAMDSEVSNP {
		return Chain{}, refuse("metadata vendor is %q, want %q", m.Vendor, attest.VendorAMDSEVSNP)
	}
	chipID, err := hex.DecodeString(m.ChipID)
	if err != nil || len(chipID) != abi.ChipIDSize {
		return Chain{}, refuse("metadata chip_id is not a %d-byte hexadecimal chip identity", abi.ChipIDSize)
	}
	fetchedAt, err := time.Parse(time.RFC3339, m.FetchedAt)
	if err != nil {
		return Chain{}, refuse("metadata fetched_at does not parse: %v", err)
	}
	c := Chain{
		Vendor:      m.Vendor,
		ProductLine: m.ProductLine,
		ChipID:      chipID,
		TCB:         attest.TCB{Bootloader: m.TCB.Bootloader, TEE: m.TCB.TEE, SNP: m.TCB.SNP, Microcode: m.TCB.Microcode},
		FetchedAt:   fetchedAt,
		Bytes:       raw,
	}

	// The chain must be a certificate table holding a VCEK whose extensions say
	// what the metadata says. Otherwise a metadata file left behind beside a
	// chain from a different provisioning run would pass CheckFor and fail at
	// the peer.
	if len(raw) == 0 {
		return Chain{}, refuse("the chain file is empty")
	}
	table := new(abi.CertTable)
	if err := table.Unmarshal(raw); err != nil {
		return Chain{}, refuse("the chain does not parse as a certificate table: %v", err)
	}
	der, err := table.GetByGUIDString(abi.VcekGUID)
	if err != nil {
		return Chain{}, refuse("the chain holds no VCEK: %v", err)
	}
	vcek, err := x509.ParseCertificate(der)
	if err != nil {
		return Chain{}, refuse("the VCEK does not parse: %v", err)
	}
	exts, err := kds.VcekCertificateExtensions(vcek)
	if err != nil {
		return Chain{}, refuse("the VCEK carries no readable key distribution service extensions: %v", err)
	}
	if !bytes.Equal(exts.HWID, c.ChipID) {
		return Chain{}, refuse("metadata records chip %x but the chain's VCEK is for chip %x; the two files are from different provisioning runs", c.ChipID, exts.HWID)
	}
	parts := kds.DecomposeTCBVersion(exts.TCBVersion)
	certTCB := attest.TCB{Bootloader: parts.BlSpl, TEE: parts.TeeSpl, SNP: parts.SnpSpl, Microcode: parts.UcodeSpl}
	if certTCB != c.TCB {
		return Chain{}, refuse("metadata records TCB %s but the chain's VCEK was issued for %s; the two files are from different provisioning runs", tcbString(c.TCB), tcbString(certTCB))
	}
	if got := kds.ProductLineOfProductName(exts.ProductName); got != c.ProductLine {
		return Chain{}, refuse("metadata records product line %q but the chain's VCEK names %q", c.ProductLine, got)
	}
	return c, nil
}

type metadata struct {
	Format      string        `json:"format"`
	Version     int           `json:"version"`
	Vendor      attest.Vendor `json:"vendor"`
	ProductLine string        `json:"product_line"`
	ChipID      string        `json:"chip_id"`
	TCB         metadataTCB   `json:"tcb"`
	FetchedAt   string        `json:"fetched_at"`
}

// metadataTCB is the four named components, as the reference value set
// spells them, because nobody reviews a packed integer.
type metadataTCB struct {
	Bootloader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
}

func tcbString(t attest.TCB) string {
	return fmt.Sprintf("bootloader=%d tee=%d snp=%d microcode=%d", t.Bootloader, t.TEE, t.SNP, t.Microcode)
}

// certTable lays out the three certificates in AMD's certificate table format:
// a header of (GUID, offset, length) entries terminated by a zero entry, then
// the DER blobs. It is written by hand rather than through the library's
// table type so that the table's GUIDs do not pull a UUID package into this
// module's direct dependencies; the verifier unmarshals it with the library,
// which is the round-trip the tests check.
func certTable(vcek, ask, ark []byte) []byte {
	type entry struct {
		guid string
		der  []byte
	}
	entries := []entry{{abi.VcekGUID, vcek}, {abi.AskGUID, ask}, {abi.ArkGUID, ark}}
	headerSize := (len(entries) + 1) * abi.CertTableEntrySize
	size := headerSize
	for _, e := range entries {
		size += len(e.der)
	}
	out := make([]byte, size)
	cursor := headerSize
	for i, e := range entries {
		h := abi.CertTableHeaderEntry{Offset: uint32(cursor), Length: uint32(len(e.der))}
		guid, err := hex.DecodeString(stripDashes(e.guid))
		if err != nil || len(guid) != abi.GUIDSize {
			panic("provision: malformed certificate table GUID constant")
		}
		copy(h.GUID[:], guid)
		if err := h.Write(out[i*abi.CertTableEntrySize:]); err != nil {
			panic("provision: certificate table header does not fit: " + err.Error())
		}
		copy(out[cursor:], e.der)
		cursor += len(e.der)
	}
	return out
}

func stripDashes(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			b = append(b, s[i])
		}
	}
	return string(b)
}

func writeAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("provision: creating %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("provision: writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("provision: closing %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("provision: setting mode on %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("provision: renaming into %s: %w", path, err)
	}
	return nil
}

// kdsGetter adapts go-sev-guest's getter to [Getter] without letting its type
// into this package's surface.
type kdsGetter struct{ g trust.HTTPSGetter }

func (k kdsGetter) Get(ctx context.Context, url string) ([]byte, error) {
	return trust.GetWith(ctx, k.g, url)
}
