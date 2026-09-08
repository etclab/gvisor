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

package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// The signed reference value set: the on-disk form of this design's trust root,
// its signature, and the loader that turns the pair into a
// [ReferenceValueSet].
//
// # Why the set is signed at all
//
// A reference value set inside the launch measurement cannot be updated:
// accepting a peer's new image changes your own measurement, which forces every
// peer to change theirs, and the cascade does not terminate. A set outside the
// measurement and unsigned is supplied by the untrusted host, which supplies a
// permissive one. Signing breaks the cycle — the set is delivered from outside
// the measurement and only the author's public key lives inside it, so updating
// values needs no new measurement and only rotating the author key does
// (ADR-0004).
//
// # A detached signature, not an envelope (ADR-0006)
//
// The signature is detached: the document is a plain JSON file, and its
// signature is a second file beside it. The alternative — an envelope whose
// payload is an opaque blob parsed only after the blob's signature verifies —
// gives the same unambiguous signed region, and was rejected for one reason:
// the entire purpose of this file is that a human can read and review it, and a
// base64 payload cannot be read or reviewed. Nothing is gained by hiding the
// trust root from the person whose job is to audit it.
//
// What both structures buy, and what a naive signed-JSON format loses, is that
// the signed region is unambiguous. The signature covers the document's exact
// bytes as delivered. No canonicalisation exists, so there is nothing for two
// implementations to disagree about; nothing is ever re-serialised and then
// checked, so a parser that drops a field, reorders a key or normalises a
// number cannot produce bytes that verify while meaning something else. This is
// enforced by the shape of the API rather than by discipline: [SignReferenceValueSet]
// and [LoadReferenceValueSet] both take the document as bytes, and there is no
// path from a parsed set back to a signature check.
//
// # Every value names its vendor (version 2)
//
// Each reference value in the document carries a "vendor" field, and the rest
// of its fields are that vendor's: an amd-sev-snp value names a launch
// measurement, a four-component TCB floor and a guest policy; an intel-tdx
// value names the provider's observed registers, the image's predicted RTMR2, a
// TD attributes policy and an Intel TCB floor. A field belonging to the other
// vendor is refused rather than ignored, because a value whose author was
// writing about one vendor and named another's constraint would otherwise be
// enforced as the half that matched — which is weaker than what they wrote.
//
// Version 1 documents had no vendor field and could name only an SEV-SNP launch
// digest. They are refused rather than read as SEV-SNP by default: a default is
// a guess about what an author meant, and this file is the one place in the
// design where guessing is not allowed. Re-emit the set and sign it again.
//
// # The document is a policy, and its digest travels (version 3)
//
// A version 3 document carries a top-level "egress" section saying what leaves
// the sandbox, which is what makes the file a policy rather than a guest list.
// The section is required and its one field is required with it: a document
// that does not say whether unattested egress is permitted has not said it is
// forbidden, and a reader that supplied the answer would be deciding policy on
// the author's behalf.
//
// The whole document is then addressable: its policy digest is SHA-256 over
// exactly the bytes the signature covers ([PolicyDigestOf]), a peer folds that
// digest into its evidence under ADR-0002's binding version 2, and a verifier
// checks it against the peer's reference value entry before recomputing the
// binding. That is why the digest is over the signed bytes rather than over the
// file: the signed region is the unambiguous one, and a digest over anything
// else would name a document nobody authorised.
//
// Version history, since a reader meeting an old file needs it in one place:
// version 1 had no vendor on a value, version 2 had no egress section and no
// per-entry policy digest, version 3 has both.
//
// # Order of operations
//
// [LoadReferenceValueSet] verifies before it parses. Everything in the document
// — its structure, its nesting depth, its field names — reaches the JSON parser
// only after the author's signature over those exact bytes has held, so a host
// that substitutes a document cannot reach the parser at all. The only thing
// parsed beforehand is the signature file itself, which is a fixed-size
// hexadecimal string and is checked to be exactly that.
//
// # Ed25519, and no algorithm agility
//
// The author key is Ed25519: the key type tunneld already uses, with no
// parameters — no curve choice, no hash choice, no padding mode — for two
// implementations to disagree about. There is deliberately no algorithm field
// in either file. A signature scheme named by the document would let an
// attacker choose the scheme a verifier applies, which is the oldest mistake in
// signed-document formats; instead the loader knows one scheme and the scheme
// is bound into the signature by [signaturePrefix]. Changing it is a new loader
// and therefore a new measurement — the same flag day as rotating the author
// key, which ADR-0004 already accepts as the one remaining cascade. ADR-0006
// records all of this.
//
// # Signing is an author-side operation
//
// [MarshalReferenceValueSet] and [SignReferenceValueSet] exist so that the
// image build can emit a set and authorise it in one traceable step (ticket 07)
// and so that producer and consumer agree by construction rather than by
// comment. Nothing inside the measured image calls them: a guest holds the
// author's public key and never its private key.

// ReferenceValueSetFormat is the value of a document's format field. It names
// what the document is, so that a loader pointed at some other JSON refuses it
// rather than interpreting whichever fields it happens to recognise.
const ReferenceValueSetFormat = "gvisor.dev/gvisor/attest/reference-value-set"

// ReferenceValueSetVersion is the document version this package writes and the
// only one it reads. A document claiming any other version is refused rather
// than read on a best-effort basis, for the reason ADR-0002 gives about the
// binding context: a reader that skips what it does not understand admits a
// value weaker than its author intended.
//
// Version 2 added the per-value vendor field and version 3 the egress section
// and the per-entry policy digest. Versions 1 and 2 are each refused with a
// message saying what is missing and what to do about it, because reading
// either on a best-effort basis would be this loader deciding what an author
// did not write down (ADR-0006, addendum).
const ReferenceValueSetVersion = 3

// egressSectionVersion is the version of the egress section this loader reads,
// and the only one it writes. It versions separately from the document because
// the section is what ticket 19 grows, and a document that gains a field
// elsewhere does not change what egress means.
const egressSectionVersion = 1

// A PolicyDigest names one signed reference value set: SHA-256 over exactly the
// bytes the author's signature covers.
//
// It is the sandbox's policy reduced to something a peer can carry and a
// verifier can compare. A peer folds it into the caller-supplied bytes of its
// evidence (ADR-0002, version 2) and presents it beside the binding context; a
// verifier holds the digests it will admit in [ReferenceValue.PolicyDigest].
// Nothing about it is secret — it is a digest of a document delivered on an
// untrusted device — so it is compared with plain equality.
type PolicyDigest [sha256.Size]byte

// String renders the digest as lowercase hexadecimal, which is the form an
// operator copies out of a start log and into a peer's reference value set.
func (d PolicyDigest) String() string { return hex.EncodeToString(d[:]) }

// PolicyDigestOf is the digest of a reference value set document.
//
// It is defined over [signedBytes] rather than over the file's own bytes, so
// that the digest names exactly the region the author's signature covers. A
// consequence worth stating out loud: sha256sum of reference-values.json is
// *not* this value, and a tool that wants a peer's digest must compute it here
// or read it from something that did.
//
// It takes a document rather than a loaded set so that a tool can name a set it
// is not going to load — a build emitting a peer's allow-list, a test computing
// what a peer will present — without holding the author's public key.
func PolicyDigestOf(document []byte) PolicyDigest {
	return sha256.Sum256(signedBytes(document))
}

// SignatureFileSuffix is appended to a document's path to find its signature.
// A set delivered on the config device is therefore two files —
// reference-values.json and reference-values.json.sig — and a document with no
// signature beside it is refused, not loaded.
const SignatureFileSuffix = ".sig"

// signaturePrefix is prepended to the document before signing and before
// verifying. It is domain separation: the reference value author's key is this
// system's trust root and may one day sign something else, and a signature over
// a bare document would then be replayable as a signature over any other bare
// document of a different kind. It also pins the signature scheme, since it is
// the scheme's version rather than the document's — the two version themselves
// separately, because a document that gains a field does not change how it is
// signed.
//
// It is a constant, never negotiated and never read out of a file.
const signaturePrefix = "gvisor.dev/gvisor/attest reference-value-set signature v1\x00"

// ErrSetRefused is what every failure to load a reference value set matches.
//
// There is exactly one outcome other than a loaded set, and it is refusal. A
// set whose signature does not hold, whose signature is absent, whose signature
// is by another key, or whose file is not there at all are all this same
// failure — deliberately, because the one thing a caller must never do is treat
// an unverifiable set as an absent one and carry on. That is the substitution
// attack ADR-0004 exists to prevent, and a caller that can distinguish "missing"
// from "invalid" is a caller that can be tempted to.
//
// This is why [LoadReferenceValueSetFile] reports a missing file with %v rather
// than %w: the underlying [io/fs.ErrNotExist] does not survive into the error,
// so errors.Is(err, fs.ErrNotExist) is false for a set that is simply not
// there. The operator-facing text still says exactly which file was missing.
var ErrSetRefused = errors.New("attest: reference value set refused")

// refuseSet builds a refusal with operator-facing text.
//
// Unlike a [Refusal], this text is not undifferentiated. A verification refusal
// is provoked by a peer and observed by it, so telling it which check failed
// tells it what to target next. A set is loaded once at startup, from a local
// file, and the only person who reads the failure is the operator who has to
// fix the file. Withholding the reason there would protect nobody and would
// leave an unbootable guest with nothing to say for itself.
func refuseSet(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSetRefused, fmt.Sprintf(format, args...))
}

// MarshalReferenceValueSet renders a set as a document for an author to review
// and sign.
//
// Every field is written out, including those whose value is the zero value,
// because the document is reviewed by eye and a reviewer should not have to
// know which absent field means which default. The output ends in a newline and
// is indented; neither is load-bearing, since the signature covers whatever
// bytes come out and no canonical form exists.
//
// The bytes this returns are the bytes to sign and the bytes to ship. Rendering
// a set twice and signing one rendering to check the other is exactly the
// mistake this format is shaped to prevent, so do not do it: sign what you
// wrote, ship what you signed.
func MarshalReferenceValueSet(set ReferenceValueSet) ([]byte, error) {
	if err := set.validate(); err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	egress, err := egressSection(set.Egress)
	if err != nil {
		return nil, err
	}
	doc := wireDocument{
		Format:  ReferenceValueSetFormat,
		Version: ReferenceValueSetVersion,
		Egress:  egress,
	}
	for i, rv := range set.Values {
		// rv.vendor(), not rv.Vendor: an empty Vendor means SEV-SNP in memory,
		// and this format always writes the tag explicitly, so a value built
		// by code from before version 2 is rendered exactly as its version-2
		// equivalent would be.
		switch rv.vendor() {
		case VendorAMDSEVSNP:
			doc.ReferenceValues = append(doc.ReferenceValues, wireAMDOut{
				Vendor:            string(VendorAMDSEVSNP),
				PolicyDigest:      renderPolicyDigest(rv.PolicyDigest),
				LaunchMeasurement: hex.EncodeToString(rv.LaunchMeasurement),
				MinimumTCB: wireTCBOut{
					Bootloader: rv.MinimumTCB.Bootloader,
					TEE:        rv.MinimumTCB.TEE,
					SNP:        rv.MinimumTCB.SNP,
					Microcode:  rv.MinimumTCB.Microcode,
				},
				GuestPolicy: wirePolicy{
					ABIMajor:            rv.GuestPolicy.ABIMajor,
					ABIMinor:            rv.GuestPolicy.ABIMinor,
					AllowSMT:            rv.GuestPolicy.AllowSMT,
					AllowMigrationAgent: rv.GuestPolicy.AllowMigrationAgent,
					AllowDebug:          rv.GuestPolicy.AllowDebug,
					RequireSingleSocket: rv.GuestPolicy.RequireSingleSocket,
				},
			})
		case VendorIntelTDX:
			doc.ReferenceValues = append(doc.ReferenceValues, wireTDXOut{
				Vendor:             string(VendorIntelTDX),
				PolicyDigest:       renderPolicyDigest(rv.PolicyDigest),
				ObservedMRTD:       hexEach(rv.TDX.ObservedMRTD),
				ObservedRTMR0:      hexEach(rv.TDX.ObservedRTMR0),
				ObservedRTMR1:      hexEach(rv.TDX.ObservedRTMR1),
				PredictedRTMR2:     hex.EncodeToString(rv.TDX.PredictedRTMR2),
				TDAttributesPolicy: wireTDPolicy{AllowDebug: rv.TDX.TDPolicy.AllowDebug},
				MinimumTCB: wireTDXTCBOut{
					Status:               string(rv.TDX.MinimumTCB.Status),
					EvaluationDataNumber: rv.TDX.MinimumTCB.EvaluationDataNumber,
				},
			})
		default:
			// Unreachable: validate above refuses a value naming any other
			// vendor. It is written down anyway, because a format that
			// silently omitted a value it could not render would ship a
			// weaker set than the one it was handed.
			return nil, fmt.Errorf("attest: reference value %d names vendor %q, which this format cannot write", i, rv.Vendor)
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("attest: rendering the reference value set: %w", err)
	}
	return append(out, '\n'), nil
}

// egressSection renders a set's egress section, refusing one this package's own
// loader would not read back.
//
// A zero Version is written as [egressSectionVersion]: an in-memory set built
// by code from before the section existed is rendered exactly as its version 3
// equivalent would be, which is the same courtesy [MarshalReferenceValueSet]
// extends to a value with no vendor tag. A set claiming unattested egress is
// refused here rather than rendered, so that "sign what you wrote, ship what
// you signed" cannot produce a document that does not load.
func egressSection(e Egress) (wireEgressOut, error) {
	version := e.Version
	if version == 0 {
		version = egressSectionVersion
	}
	if version != egressSectionVersion {
		return wireEgressOut{}, fmt.Errorf("attest: the egress section is version %d; this package writes version %d", e.Version, egressSectionVersion)
	}
	if e.Unattested {
		return wireEgressOut{}, errors.New("attest: the egress section permits unattested egress, which nothing here enforces; a document claiming it would not load back")
	}
	return wireEgressOut{Version: version, Unattested: e.Unattested}, nil
}

// SignReferenceValueSet signs a document with the reference value author's key,
// returning the contents of the signature file that belongs beside it.
//
// document is signed exactly as given. It is the author's job to sign the bytes
// they intend to ship and to ship the bytes they signed; there is no
// canonicalisation step here that could quietly make those two different.
func SignReferenceValueSet(document []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attest: reference value author key is %d bytes, want an Ed25519 private key of %d", len(key), ed25519.PrivateKeySize)
	}
	signature := ed25519.Sign(key, signedBytes(document))
	out := make([]byte, hex.EncodedLen(len(signature))+1)
	hex.Encode(out, signature)
	out[len(out)-1] = '\n'
	return out, nil
}

// LoadReferenceValueSet verifies a document against the reference value
// author's public key and, only if that holds, parses it.
//
// Every way this can fail is a refusal matching [ErrSetRefused], and there is
// no other outcome and no other entry point. In particular there is no way to
// load a document without a signature, and no way to ask for the document's
// contents when its signature did not hold: a caller cannot fall back to an
// unsigned set because this package offers nothing to fall back to.
func LoadReferenceValueSet(document, signature []byte, author ed25519.PublicKey) (ReferenceValueSet, error) {
	if len(author) != ed25519.PublicKeySize {
		return ReferenceValueSet{}, refuseSet("the reference value author public key is %d bytes, want an Ed25519 public key of %d", len(author), ed25519.PublicKeySize)
	}
	sig, err := parseSignature(signature)
	if err != nil {
		return ReferenceValueSet{}, err
	}
	if !ed25519.Verify(author, signedBytes(document), sig) {
		return ReferenceValueSet{}, refuseSet(
			"the signature is not this reference value author's signature over these bytes; " +
				"either the document was modified in delivery or it was signed by a different key")
	}
	// Past this line, and not before it, the document is the author's.
	return parseReferenceValueSetDocument(document)
}

// LoadReferenceValueSetFile loads the set at path, whose signature is the file
// at path+[SignatureFileSuffix].
//
// A missing signature file is a refusal like any other, not an absence. So is a
// missing document. Neither error matches [io/fs.ErrNotExist], so a caller
// cannot write the one branch this design cannot survive — the one that treats
// "there is no set here" as permission to proceed without one.
func LoadReferenceValueSetFile(path string, author ed25519.PublicKey) (ReferenceValueSet, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return ReferenceValueSet{}, refuseSet("reading the reference value set at %s: %v", path, err)
	}
	sigPath := path + SignatureFileSuffix
	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return ReferenceValueSet{}, refuseSet("reading the signature at %s: %v", sigPath, err)
	}
	return LoadReferenceValueSet(document, signature, author)
}

// signedBytes is what the author's key actually signs: the domain separation
// prefix followed by the document's exact bytes. It is used by the signer and
// the verifier, so the two cannot drift.
func signedBytes(document []byte) []byte {
	msg := make([]byte, 0, len(signaturePrefix)+len(document))
	msg = append(msg, signaturePrefix...)
	return append(msg, document...)
}

// parseSignature reads the signature file: one hexadecimal Ed25519 signature,
// with surrounding whitespace ignored so that a file written by an editor or by
// a shell redirect both work.
//
// An empty signature file is refused here rather than left to fail the
// signature check, so that the log says the signature was absent — which is a
// provisioning mistake with a different fix from a signature that did not hold.
// It is refused either way; only the sentence differs.
func parseSignature(signature []byte) ([]byte, error) {
	text := strings.TrimSpace(string(signature))
	if text == "" {
		return nil, refuseSet("no signature was presented with the reference value set")
	}
	sig, err := hex.DecodeString(text)
	if err != nil {
		return nil, refuseSet("the signature is not hexadecimal: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, refuseSet("the signature is %d bytes, want an Ed25519 signature of %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// parseReferenceValueSetDocument turns a document whose signature has already
// held into a set.
//
// It is strict in three ways that each exist for the same reason: a reference
// value must not end up weaker than the author who signed it believed it to be.
// A field nobody recognises is refused rather than skipped. A field named twice
// is refused rather than resolved to the last one, because a reviewer reads the
// first. Bytes after the document are refused rather than ignored.
func parseReferenceValueSetDocument(document []byte) (ReferenceValueSet, error) {
	if err := rejectRepeatedFields(document); err != nil {
		return ReferenceValueSet{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(document))
	dec.DisallowUnknownFields()
	var doc wireSet
	if err := dec.Decode(&doc); err != nil {
		return ReferenceValueSet{}, refuseSet("the document does not parse: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return ReferenceValueSet{}, refuseSet("the document carries bytes after the reference value set")
	}

	if doc.Format == nil {
		return ReferenceValueSet{}, refuseSet("the document does not say what format it is; want %q", ReferenceValueSetFormat)
	}
	if *doc.Format != ReferenceValueSetFormat {
		return ReferenceValueSet{}, refuseSet("the document is in format %q, this loader reads %q", *doc.Format, ReferenceValueSetFormat)
	}
	if doc.Version == nil {
		return ReferenceValueSet{}, refuseSet("the document does not say what version it is; want %d", ReferenceValueSetVersion)
	}
	if *doc.Version == 1 {
		return ReferenceValueSet{}, refuseSet(
			"the document is version 1 and this loader reads version %d: a version 1 reference value "+
				"carries no vendor tag, so it does not say whose evidence it admits, and reading one as "+
				"SEV-SNP would be this loader deciding what its author did not write down; "+
				"re-emit the set with a vendor on every value and sign it again", ReferenceValueSetVersion)
	}
	if *doc.Version == 2 {
		return ReferenceValueSet{}, refuseSet(
			"the document is version 2 and this loader reads version %d: a version 2 document carries no "+
				"egress section, so it says nothing about what leaves the sandbox, and a policy digest over "+
				"it would vouch for a policy that was never written; "+
				"add \"egress\": {\"version\": %d, \"unattested\": false} and sign it again",
			ReferenceValueSetVersion, egressSectionVersion)
	}
	if *doc.Version != ReferenceValueSetVersion {
		return ReferenceValueSet{}, refuseSet("the document is version %d, this loader reads version %d", *doc.Version, ReferenceValueSetVersion)
	}
	egress, err := doc.Egress.egress()
	if err != nil {
		return ReferenceValueSet{}, err
	}

	// The digest of the document, taken here so that every loaded set carries
	// the name a peer will present for it. It is over the signed bytes, which
	// is the region the signature just held over.
	set := ReferenceValueSet{Egress: egress, PolicyDigest: PolicyDigestOf(document)}
	for i, raw := range doc.ReferenceValues {
		rv, err := parseReferenceValue(raw)
		if err != nil {
			return ReferenceValueSet{}, refuseSet("reference value %d: %v", i, err)
		}
		set.Values = append(set.Values, rv)
	}
	if err := set.validate(); err != nil {
		return ReferenceValueSet{}, refuseSet("%v", err)
	}
	return set, nil
}

// wireSet is the document as it is read. Its required fields are pointers so
// that absent and zero are distinguishable: a document that forgot to say what
// version it is must not be read as version zero.
//
// Its reference values are held unparsed. Which fields an entry may carry
// depends on the vendor it names, and two vendors put objects of different
// shapes under the same "minimum_tcb" key, so an entry is decoded once its
// vendor is known and not before.
type wireSet struct {
	Format          *string           `json:"format"`
	Version         *int              `json:"version"`
	Egress          *wireEgress       `json:"egress"`
	ReferenceValues []json.RawMessage `json:"reference_values"`
}

// wireEgress is the egress section as it is read. Both fields are pointers for
// the reason [wireSet]'s are: a section that forgot to say whether unattested
// egress is permitted must not be read as having permitted nothing by accident.
// The author of a policy says what the policy is.
type wireEgress struct {
	Version    *int  `json:"version"`
	Unattested *bool `json:"unattested"`
}

// wireEgressOut is the egress section as it is written.
type wireEgressOut struct {
	Version    int  `json:"version"`
	Unattested bool `json:"unattested"`
}

// egress reads the section, refusing every way it can fail to be a policy.
//
// The permissive case is refused for a reason worth separating from the others:
// the section is well-formed and its author meant it, and nothing in this build
// implements it. A verifier that admitted the document would hand a peer a
// policy digest vouching for a capability no code enforces, which is exactly
// the failure the digest exists to prevent.
func (w *wireEgress) egress() (Egress, error) {
	if w == nil {
		return Egress{}, refuseSet(
			"the document has no egress section; a version %d document says what leaves the sandbox as well as "+
				"whom it may talk to, and one that says nothing has not said no; "+
				"add \"egress\": {\"version\": %d, \"unattested\": false} and sign it again",
			ReferenceValueSetVersion, egressSectionVersion)
	}
	if w.Version == nil {
		return Egress{}, refuseSet("the egress section does not say what version it is; want %d", egressSectionVersion)
	}
	if *w.Version != egressSectionVersion {
		return Egress{}, refuseSet("the egress section is version %d, this loader reads version %d", *w.Version, egressSectionVersion)
	}
	if w.Unattested == nil {
		return Egress{}, refuseSet(
			"the egress section does not say whether unattested egress is permitted; the field is required rather " +
				"than defaulted, because a policy a verifier vouches for is one its author wrote down")
	}
	if *w.Unattested {
		return Egress{}, refuseSet(
			"the egress section permits unattested egress and nothing here enforces that permission; " +
				"a policy claiming a capability no code implements is weaker than it reads, so it is refused rather " +
				"than admitted with the claim quietly dropped")
	}
	return Egress{Version: *w.Version, Unattested: *w.Unattested}, nil
}

// wireDocument is the document as it is written, and is deliberately a
// different type from wireSet. What is written is one shape per vendor with
// every field present; what is read has to be strict about fields that are
// absent, repeated, or belong to the other vendor. Sharing one type between the
// two jobs is how a renderer ends up defining the format.
type wireDocument struct {
	Format          string        `json:"format"`
	Version         int           `json:"version"`
	Egress          wireEgressOut `json:"egress"`
	ReferenceValues []any         `json:"reference_values"`
}

// wireAMDOut and wireTDXOut are one rendered reference value each.
//
// PolicyDigest is the one field of either that is omitted when it is not set,
// and the exception is the whole point: an entry with no policy_digest is
// unconstrained, and writing "policy_digest": "" would render that as a policy
// nobody has rather than as no constraint at all.
type wireAMDOut struct {
	Vendor            string     `json:"vendor"`
	PolicyDigest      string     `json:"policy_digest,omitempty"`
	LaunchMeasurement string     `json:"launch_measurement"`
	MinimumTCB        wireTCBOut `json:"minimum_tcb"`
	GuestPolicy       wirePolicy `json:"guest_policy"`
}

type wireTDXOut struct {
	Vendor             string        `json:"vendor"`
	PolicyDigest       string        `json:"policy_digest,omitempty"`
	ObservedMRTD       []string      `json:"observed_mrtd"`
	ObservedRTMR0      []string      `json:"observed_rtmr0"`
	ObservedRTMR1      []string      `json:"observed_rtmr1"`
	PredictedRTMR2     string        `json:"predicted_rtmr2"`
	TDAttributesPolicy wireTDPolicy  `json:"td_attributes_policy"`
	MinimumTCB         wireTDXTCBOut `json:"minimum_tcb"`
}

type wireTCBOut struct {
	Bootloader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
}

type wireTDXTCBOut struct {
	Status               string `json:"status"`
	EvaluationDataNumber uint32 `json:"tcb_evaluation_data_number"`
}

// renderPolicyDigest renders an entry's policy digest, or the empty string for
// an entry that lists none.
func renderPolicyDigest(d *PolicyDigest) string {
	if d == nil {
		return ""
	}
	return d.String()
}

// hexEach renders a list of observed register values.
func hexEach(values [][]byte) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = hex.EncodeToString(v)
	}
	return out
}

// wireValue is one reference value.
//
// The set is always a list, even when it holds one value, because that is what
// makes an image rollout expressible: the old measurement and the new one sit
// in the file together while both are running, and neither deployment has to
// stop for the other. A format that allowed a bare single value would make the
// common case shorter and the case the design exists to support a special one.
type wireValue struct {
	// Vendor is required and is the first thing read. Every field below it
	// belongs to one vendor or the other, and which of them may appear is
	// decided by this one.
	Vendor *string `json:"vendor"`

	// PolicyDigest is optional and belongs to both vendors, which makes it the
	// only field here that does. It is the digest of the peer's own signed
	// reference value set, in hexadecimal, exactly 32 bytes wide.
	//
	// Absent means unconstrained: this value admits a peer running the named
	// image under any policy. That is the weaker reading of an absent field,
	// which the rest of this format refuses to take — and it is taken here
	// because the alternative refuses every set authored before the field
	// existed, and because an unconstrained entry is reported by
	// [ReferenceValueSet.Unconstrained] rather than passing unremarked.
	PolicyDigest *string `json:"policy_digest"`

	// MinimumTCB is required, for both vendors, and its shape is the vendor's.
	// An author writing a trust root has an opinion about which platform levels
	// to admit, and a floor that defaults silently to zero when the key is left
	// out is a floor nobody chose. It is held unparsed because AMD's floor is
	// four component versions and Intel's is a status and an evaluation number.
	MinimumTCB json.RawMessage `json:"minimum_tcb"`

	// LaunchMeasurement is hexadecimal, and amd-sev-snp's. Its width is not
	// checked, deliberately: how wide a launch measurement is belongs to the
	// hardware vendor, and baking one vendor's digest width into the format is
	// exactly the seam that makes a second vendor tractable. A measurement of
	// the wrong width matches nothing, which fails closed.
	LaunchMeasurement *string `json:"launch_measurement"`

	// GuestPolicy is amd-sev-snp's, and may be omitted: omitting it permits
	// nothing — the zero value of [GuestPolicy] is the fail-closed direction,
	// which is the right default for a reference value whose author did not
	// think about policy. This asymmetry with MinimumTCB is deliberate: an
	// absent field may make a value stricter than intended, never weaker.
	GuestPolicy *wirePolicy `json:"guest_policy"`

	// ObservedMRTD, ObservedRTMR0 and ObservedRTMR1 are intel-tdx's, each a
	// list of hexadecimal values of which a peer must present one. They are
	// named observed because they are the provider's and nobody here can
	// predict them (docs/tdx-rtmr2-prediction.md); a list because the
	// provider's values are not single. Each is required and each must name at
	// least one value: a register with no expected value is a register not
	// checked, which is the fail-open direction.
	ObservedMRTD  []string `json:"observed_mrtd"`
	ObservedRTMR0 []string `json:"observed_rtmr0"`
	ObservedRTMR1 []string `json:"observed_rtmr1"`

	// PredictedRTMR2 is intel-tdx's, hexadecimal, and required. It is named
	// predicted because it is computed from the image before anything boots,
	// under the same rule as an SEV-SNP launch measurement: a value read off a
	// booted guest is not a prediction and a check built on one cannot fail.
	PredictedRTMR2 *string `json:"predicted_rtmr2"`

	// TDAttributesPolicy is intel-tdx's, and like GuestPolicy may be omitted to
	// permit nothing.
	TDAttributesPolicy *wireTDPolicy `json:"td_attributes_policy"`
}

// wireTCB is a TCB floor: four separately named component versions, never the
// packed integer the hardware reports.
//
// The packing is the vendor's business. This file is the trust root and has to
// be reviewable by eye, and nobody reviews a decimal integer for whether it
// means "microcode 72". All four are required, because a floor missing one
// component is a floor of zero for that component, and a reviewer reading three
// lines does not notice the fourth is not there.
type wireTCB struct {
	Bootloader *uint8 `json:"bootloader"`
	TEE        *uint8 `json:"tee"`
	SNP        *uint8 `json:"snp"`
	Microcode  *uint8 `json:"microcode"`
}

// wirePolicy is what a reference value permits. Each field's absence is the
// fail-closed answer, so unlike wireTCB none of them is required.
type wirePolicy struct {
	ABIMajor            uint8 `json:"abi_major"`
	ABIMinor            uint8 `json:"abi_minor"`
	AllowSMT            bool  `json:"allow_smt"`
	AllowMigrationAgent bool  `json:"allow_migration_agent"`
	AllowDebug          bool  `json:"allow_debug"`
	RequireSingleSocket bool  `json:"require_single_socket"`
}

// wireTDPolicy is what an intel-tdx reference value permits of TD_ATTRIBUTES.
// Its one field's absence is the fail-closed answer, as in wirePolicy.
type wireTDPolicy struct {
	AllowDebug bool `json:"allow_debug"`
}

// wireTDXTCB is an Intel TCB floor. Both fields are required, for the reason
// wireTCB gives about a component left out: a status floor with no evaluation
// number admits a TCB info from before any TCB recovery, which still verifies
// and still calls a since-vulnerable platform UpToDate — and that is the field
// the host provisions, so it is the one an author must actually choose.
type wireTDXTCB struct {
	Status               *string `json:"status"`
	EvaluationDataNumber *uint32 `json:"tcb_evaluation_data_number"`
}

// parseReferenceValue turns one entry of the document into a reference value.
//
// The vendor is read first and decides everything after it. The entry is
// decoded strictly, so a field no vendor defines is refused here exactly as an
// unknown field at the top level is.
func parseReferenceValue(raw json.RawMessage) (ReferenceValue, error) {
	var w wireValue
	if err := strictDecode(raw, &w, "the reference value"); err != nil {
		return ReferenceValue{}, err
	}
	if w.Vendor == nil {
		return ReferenceValue{}, errors.New(
			"names no vendor; every value in a version 2 document says whose evidence it admits, " +
				"and one that does not cannot be read as any vendor's without guessing")
	}
	switch vendor := Vendor(*w.Vendor); vendor {
	case VendorAMDSEVSNP:
		return w.amdReferenceValue()
	case VendorIntelTDX:
		return w.tdxReferenceValue()
	default:
		return ReferenceValue{}, fmt.Errorf("names vendor %q; this loader reads %q and %q",
			vendor, VendorAMDSEVSNP, VendorIntelTDX)
	}
}

// amdReferenceValue reads the amd-sev-snp half of the format, which is exactly
// what version 1 held.
func (w wireValue) amdReferenceValue() (ReferenceValue, error) {
	if err := w.refuseTheOtherVendorsFields(VendorAMDSEVSNP); err != nil {
		return ReferenceValue{}, err
	}
	if w.LaunchMeasurement == nil {
		return ReferenceValue{}, errors.New("no launch_measurement")
	}
	measurement, err := hex.DecodeString(*w.LaunchMeasurement)
	if err != nil {
		return ReferenceValue{}, fmt.Errorf("launch_measurement is not hexadecimal: %v", err)
	}
	if w.MinimumTCB == nil {
		return ReferenceValue{}, errors.New("no minimum_tcb; a floor left out is a floor of zero, which admits every firmware level")
	}
	var floor wireTCB
	if err := strictDecode(w.MinimumTCB, &floor, "minimum_tcb"); err != nil {
		return ReferenceValue{}, err
	}
	tcb, err := floor.tcb()
	if err != nil {
		return ReferenceValue{}, err
	}
	policy, err := w.policyDigest()
	if err != nil {
		return ReferenceValue{}, err
	}
	rv := ReferenceValue{Vendor: VendorAMDSEVSNP, LaunchMeasurement: measurement, MinimumTCB: tcb, PolicyDigest: policy}
	if w.GuestPolicy != nil {
		rv.GuestPolicy = GuestPolicy{
			ABIMajor:            w.GuestPolicy.ABIMajor,
			ABIMinor:            w.GuestPolicy.ABIMinor,
			AllowSMT:            w.GuestPolicy.AllowSMT,
			AllowMigrationAgent: w.GuestPolicy.AllowMigrationAgent,
			AllowDebug:          w.GuestPolicy.AllowDebug,
			RequireSingleSocket: w.GuestPolicy.RequireSingleSocket,
		}
	}
	return rv, nil
}

// tdxReferenceValue reads the intel-tdx half.
func (w wireValue) tdxReferenceValue() (ReferenceValue, error) {
	if err := w.refuseTheOtherVendorsFields(VendorIntelTDX); err != nil {
		return ReferenceValue{}, err
	}
	tdx := &TDXReferenceValue{}
	for _, r := range []struct {
		name   string
		values []string
		into   *[][]byte
	}{
		{"observed_mrtd", w.ObservedMRTD, &tdx.ObservedMRTD},
		{"observed_rtmr0", w.ObservedRTMR0, &tdx.ObservedRTMR0},
		{"observed_rtmr1", w.ObservedRTMR1, &tdx.ObservedRTMR1},
	} {
		if r.values == nil {
			return ReferenceValue{}, fmt.Errorf(
				"no %s; a register with no expected value is a register not checked", r.name)
		}
		for i, v := range r.values {
			b, err := hex.DecodeString(v)
			if err != nil {
				return ReferenceValue{}, fmt.Errorf("%s[%d] is not hexadecimal: %v", r.name, i, err)
			}
			*r.into = append(*r.into, b)
		}
	}
	if w.PredictedRTMR2 == nil {
		return ReferenceValue{}, errors.New(
			"no predicted_rtmr2; the value naming the image is the one that must not be left out, " +
				"because a value without it admits every image the provider boots")
	}
	rtmr2, err := hex.DecodeString(*w.PredictedRTMR2)
	if err != nil {
		return ReferenceValue{}, fmt.Errorf("predicted_rtmr2 is not hexadecimal: %v", err)
	}
	tdx.PredictedRTMR2 = rtmr2
	if w.MinimumTCB == nil {
		return ReferenceValue{}, errors.New("no minimum_tcb; a floor left out is a floor nobody chose, which admits a platform at any Intel TCB level")
	}
	var floor wireTDXTCB
	if err := strictDecode(w.MinimumTCB, &floor, "minimum_tcb"); err != nil {
		return ReferenceValue{}, err
	}
	tdx.MinimumTCB, err = floor.floor()
	if err != nil {
		return ReferenceValue{}, err
	}
	if w.TDAttributesPolicy != nil {
		tdx.TDPolicy = TDPolicy{AllowDebug: w.TDAttributesPolicy.AllowDebug}
	}
	policy, err := w.policyDigest()
	if err != nil {
		return ReferenceValue{}, err
	}
	return ReferenceValue{Vendor: VendorIntelTDX, TDX: tdx, PolicyDigest: policy}, nil
}

// policyDigest reads the entry's optional policy digest.
//
// A digest of the wrong width is refused rather than padded or truncated. It
// would match nothing, which fails closed, but it is also unambiguously a
// mistake in a file somebody wrote by hand — and an entry that silently matches
// nothing is an allow-list entry that does not do its job while looking as
// though it does.
func (w wireValue) policyDigest() (*PolicyDigest, error) {
	if w.PolicyDigest == nil {
		return nil, nil
	}
	raw, err := hex.DecodeString(*w.PolicyDigest)
	if err != nil {
		return nil, fmt.Errorf("policy_digest is not hexadecimal: %v", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("policy_digest is %d bytes, want %d; a digest of the wrong width names no policy any peer can present", len(raw), sha256.Size)
	}
	var digest PolicyDigest
	copy(digest[:], raw)
	return &digest, nil
}

// refuseTheOtherVendorsFields refuses a value carrying a field that belongs to
// the vendor it does not name.
//
// Ignoring such a field is the same failure as ignoring an unknown one, and
// worse for being plausible: an author who wrote "predicted_rtmr2" on an
// amd-sev-snp value was thinking about a register this value cannot check, and
// enforcing only the part that parsed would admit more than they wrote down.
func (w wireValue) refuseTheOtherVendorsFields(vendor Vendor) error {
	for _, f := range []struct {
		name    string
		present bool
		owner   Vendor
	}{
		{"launch_measurement", w.LaunchMeasurement != nil, VendorAMDSEVSNP},
		{"guest_policy", w.GuestPolicy != nil, VendorAMDSEVSNP},
		{"observed_mrtd", w.ObservedMRTD != nil, VendorIntelTDX},
		{"observed_rtmr0", w.ObservedRTMR0 != nil, VendorIntelTDX},
		{"observed_rtmr1", w.ObservedRTMR1 != nil, VendorIntelTDX},
		{"predicted_rtmr2", w.PredictedRTMR2 != nil, VendorIntelTDX},
		{"td_attributes_policy", w.TDAttributesPolicy != nil, VendorIntelTDX},
	} {
		if f.present && f.owner != vendor {
			return fmt.Errorf("is a %s value carrying %s, which is a %s field; a value is about one vendor",
				vendor, f.name, f.owner)
		}
	}
	return nil
}

// strictDecode reads one JSON value that has already been extracted from the
// signed document, refusing any field the target type does not define. It is
// how the strictness the top-level decode applies reaches the parts of the
// document that are decoded separately.
func strictDecode(raw json.RawMessage, into any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%s does not parse: %v", what, err)
	}
	return nil
}

func (w wireTCB) tcb() (TCB, error) {
	missing := []string{}
	for _, c := range []struct {
		name  string
		value *uint8
	}{
		{"bootloader", w.Bootloader},
		{"tee", w.TEE},
		{"snp", w.SNP},
		{"microcode", w.Microcode},
	} {
		if c.value == nil {
			missing = append(missing, c.name)
		}
	}
	if len(missing) > 0 {
		return TCB{}, fmt.Errorf("minimum_tcb does not name %s; every component of the floor must be written down, because one left out is a floor of zero for that component", strings.Join(missing, ", "))
	}
	return TCB{
		Bootloader: *w.Bootloader,
		TEE:        *w.TEE,
		SNP:        *w.SNP,
		Microcode:  *w.Microcode,
	}, nil
}

func (w wireTDXTCB) floor() (TDXTCBFloor, error) {
	if w.Status == nil {
		return TDXTCBFloor{}, fmt.Errorf("minimum_tcb does not name status; a floor is %q or %q, and a value that names neither admits a platform Intel has already said is out of date", TDXTCBUpToDate, TDXTCBSWHardeningNeeded)
	}
	if w.EvaluationDataNumber == nil {
		return TDXTCBFloor{}, errors.New("minimum_tcb does not name tcb_evaluation_data_number; a status floor alone is met by TCB info from before any TCB recovery, which still calls a since-vulnerable platform UpToDate")
	}
	return TDXTCBFloor{
		Status:               TDXTCBStatus(*w.Status),
		EvaluationDataNumber: *w.EvaluationDataNumber,
	}, nil
}

// repeatedField and foldedField are the two things the token walk below is
// looking for.
type repeatedField struct{ where string }

func (e *repeatedField) Error() string { return "repeated field " + e.where }

type foldedField struct{ where string }

func (e *foldedField) Error() string { return "field name outside the format's alphabet " + e.where }

// rejectRepeatedFields refuses a document in which any JSON object names the
// same field twice.
//
// Go's JSON decoder resolves a repeated field to the last occurrence, silently.
// That is the same failure as ignoring an unknown field, arrived at from the
// other side: a reviewer reads "allow_debug": false near the top of a value,
// approves it, and the parser takes the "allow_debug": true further down. The
// author signed both, so the signature does not help. Only refusing does.
//
// This runs on a document whose signature has already held, so it is walking
// the author's own bytes rather than an attacker's.
func rejectRepeatedFields(document []byte) error {
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.UseNumber()
	err := walkForRepeats(dec, "")
	var repeat *repeatedField
	if errors.As(err, &repeat) {
		return refuseSet("the document names %s twice; a reviewer reads the first occurrence and a parser takes the last", repeat.where)
	}
	var folded *foldedField
	if errors.As(err, &folded) {
		return refuseSet("the field name %s is not lowercase ASCII; the parser matches names case-insensitively, so a reviewer and a parser could read it as different fields", folded.where)
	}
	// Any other error means the document is not well-formed JSON. The strict
	// decode that follows reports that with far better context than a token
	// walk can, so nothing is said here.
	return nil
}

func walkForRepeats(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // A scalar: nothing inside it to repeat.
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is %v, not a string", keyTok)
			}
			at := key
			if path != "" {
				at = path + "." + key
			}
			// encoding/json matches field names case-insensitively, and
			// folds U+212A and U+017F as well, so "Microcode" and
			// "microcode" are one field to the parser and two to a reviewer
			// — and the exact-match check just below would not see the
			// repeat. Every field this format defines is lowercase ASCII
			// with underscores; anything else is refused before it can
			// alias one.
			if !isFormatFieldName(key) {
				return &foldedField{where: at}
			}
			if seen[key] {
				return &repeatedField{where: at}
			}
			seen[key] = true
			if err := walkForRepeats(dec, at); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkForRepeats(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected %v", delim)
	}
	// The closing delimiter.
	_, err = dec.Token()
	return err
}

// isFormatFieldName reports whether key is drawn from the only alphabet the
// format's field names use: lowercase ASCII letters, digits and underscore.
//
// Digits are here for observed_rtmr0 and its neighbours. They are safe for the
// reason the letters are restricted: what this check exists to stop is one
// field name folding onto another under the parser's case-insensitive match,
// and a digit has no other case to fold to.
func isFormatFieldName(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
