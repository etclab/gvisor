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
)

// The signed policy: a sandbox's own statement about its behaviour, the digest
// a peer checks it by, and the loader that turns document and signature into a
// [Policy].
//
// # Why the policy is not the reference value set (ticket 19)
//
// Ticket 18 made the reference value set do both jobs: it was the guest list a
// verifier enforced and, through its own digest, the policy a sandbox
// presented. The live run showed what that costs. An allow-list entry names a
// peer's policy digest, so for A and B to pin each other A's set would have to
// name the digest of B's set while B's named the digest of A's — and each
// digest is taken over a document that would then already have to contain it.
// Nobody can author that pair. Constrained admission was one-directional per
// pair, and a fully constrained pair admitted nothing in either direction.
//
// The two jobs are therefore two documents. `policy.json` is what a sandbox
// *is*: the egress section, and `forward_to`, the measurements it will dial.
// `reference-values.json` is whom a sandbox *admits*: measurement and
// policy_digest pairs, and no policy of its own. The digest a peer presents is
// over the policy, which names no digests at all, so A's set and B's set can
// each name the other's policy and the cycle is gone.
//
// # The same signature scheme, a different domain
//
// A policy is signed exactly as a reference value set is: a detached signature
// beside a plain JSON file, Ed25519, no algorithm field, the signature over a
// domain separation prefix and the document's exact bytes (ADR-0006). The
// prefix is the one thing that differs, and it is what stops the two documents
// being confused for one another — a signature over a set can never be
// presented as a signature over a policy, or the reverse, however similar the
// two files look.
//
// # What a verifier does with it
//
// Nothing directly. A verifier never sees a peer's policy document, only
// [PolicyDigestOf] it, which the peer folded into its evidence under ADR-0002's
// binding version 2 and which the verifier checks against
// [ReferenceValue.PolicyDigest]. The document itself is read only by the
// sandbox it belongs to: it is loaded off the config device beside the set, its
// digest becomes the sandbox's identity, and `forward_to` is enforced by that
// sandbox on the peers it dials. A peer learns a policy's contents by holding
// the same document, not by being sent one.

// PolicyFormat is the value of a policy document's format field. It names what
// the document is, so that a loader pointed at some other JSON — the reference
// value set beside it, most obviously — refuses it rather than interpreting
// whichever fields it happens to recognise.
const PolicyFormat = "gvisor.dev/gvisor/attest/policy"

// PolicyVersion is the policy version this package writes and the only one it
// reads. A document claiming any other version is refused rather than read on a
// best-effort basis: a reader that skips what it does not understand enforces
// the part of a policy that already existed and vouches for the whole of it.
const PolicyVersion = 1

// policySignaturePrefix is prepended to a policy document before signing and
// before verifying.
//
// It is [signaturePrefix]'s counterpart and its whole job is to be different
// from it. The reference value author's key signs both documents, and without
// distinct prefixes a signature over a set would verify as a signature over a
// policy: an attacker who could get one signed would have the other for free,
// and a loader would parse a guest list as a statement about behaviour. It is a
// constant, never negotiated and never read out of a file.
const policySignaturePrefix = "gvisor.dev/gvisor/attest policy signature v1\x00"

// A PolicyDigest names one signed policy: SHA-256 over exactly the bytes the
// author's signature covers.
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

// PolicyDigestOf is the digest of a policy document.
//
// It is defined over the signed bytes rather than over the file's own bytes, so
// that the digest names exactly the region the author's signature covers. A
// consequence worth stating out loud: sha256sum of policy.json is *not* this
// value, and a tool that wants a peer's digest must compute it here or read it
// from something that did.
//
// It takes a document rather than a loaded policy so that a tool can name a
// policy it is not going to load — a build emitting a peer's allow-list, a test
// computing what a peer will present — without holding the author's public key.
func PolicyDigestOf(document []byte) PolicyDigest {
	return sha256.Sum256(policySignedBytes(document))
}

// ErrPolicyRefused is what every failure to load a policy matches.
//
// There is exactly one outcome other than a loaded policy, and it is refusal —
// for the reason [ErrSetRefused] gives about a reference value set, and with
// more force. A sandbox that ran without its policy would present no digest, or
// a digest of nothing, and would be asking every peer to admit it on its
// measurement alone.
var ErrPolicyRefused = errors.New("attest: policy refused")

// refusePolicy builds a refusal with operator-facing text, as [refuseSet] does
// and for the same reason: a policy is loaded once at startup from a local
// file, and the only person who reads the failure is the operator who has to
// fix it.
func refusePolicy(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicyRefused, fmt.Sprintf(format, args...))
}

// A Policy is what a sandbox says about itself: what may leave it, and which
// images it will dial.
//
// It is the document a [PolicyDigest] names. A sandbox loads its own policy off
// the config device, presents its digest to every peer, and enforces
// `forward_to` itself; it never holds a peer's policy document, only the digest
// of one.
type Policy struct {
	// Version is the document's version, which is [PolicyVersion] and nothing
	// else. It is kept rather than discarded after the check so that a loaded
	// policy says which version it was written at.
	Version int

	// Egress is what the policy says about traffic leaving the sandbox.
	Egress Egress

	// ForwardTo is the images this sandbox will dial: launch measurements, or
	// predicted RTMR2 values for a TDX peer — whatever the vendor's verifier
	// reports as [Claims.LaunchMeasurement]. Never policy digests: this list
	// says which images may be talked to, and a policy that named policies
	// would be the cycle ticket 18 ran into, one document further out.
	//
	// Empty means the sandbox dials nobody, which is a legitimate thing to
	// write for a sandbox that only answers. Absent is not the same thing and
	// does not load: an author who did not say whom they forward to has not
	// said "nobody", and a loader supplying the answer would be deciding policy
	// on their behalf.
	ForwardTo [][]byte

	// Digest is the digest of the document this policy was loaded from:
	// SHA-256 over exactly the bytes the author's signature covers.
	// [LoadPolicy] and [LoadPolicyFile] fill it in; a policy built in memory
	// carries whatever its builder put here, which for a sandbox that is not
	// presenting one is the zero digest.
	Digest PolicyDigest
}

// Egress is what the policy says about traffic leaving the sandbox.
//
// It is what makes the policy a statement about behaviour and not only a list
// of peers: a digest is worth checking only if the document it covers says
// something a verifier cares about. Today it says one thing, and says it in the
// fail-closed direction.
//
// It versions separately from the document around it, because it is the section
// that grows and a document that gains a field elsewhere does not change what
// egress means.
type Egress struct {
	// Version is the egress section's own version, which is 1 and nothing else.
	Version int

	// Unattested says whether the sandbox may send traffic to a peer whose
	// evidence nothing judged. Nothing here implements permitting it, so a
	// loaded document claiming it is refused: a policy that claims a capability
	// no code enforces is weaker than it reads, and the digest a peer checks
	// would vouch for a promise nobody keeps.
	Unattested bool
}

// egressSectionVersion is the version of the egress section this loader reads,
// and the only one it writes.
const egressSectionVersion = 1

// Forwards reports whether this policy will dial a peer running the given
// measurement.
//
// A policy listing nothing forwards to nobody, which is why this is written as
// a search rather than as "empty means anything": the fail-open reading of an
// empty list is the one mistake this whole design is arranged to avoid.
func (p Policy) Forwards(measurement []byte) bool {
	for _, m := range p.ForwardTo {
		if bytes.Equal(m, measurement) {
			return true
		}
	}
	return false
}

// MarshalPolicy renders a policy as a document for an author to review and
// sign.
//
// Every field is written out, including those whose value is the zero value,
// because the document is reviewed by eye and a reviewer should not have to
// know which absent field means which default. A zero [Egress.Version] is
// written as the version this package reads, so a policy built by code that
// left it alone renders exactly as a policy that named it would.
//
// The bytes this returns are the bytes to sign and the bytes to ship. Rendering
// twice and signing one rendering to check the other is exactly the mistake
// this format is shaped to prevent, so do not do it: sign what you wrote, ship
// what you signed.
func MarshalPolicy(p Policy) ([]byte, error) {
	version := p.Version
	if version == 0 {
		version = PolicyVersion
	}
	if version != PolicyVersion {
		return nil, fmt.Errorf("attest: the policy is version %d; this package writes version %d", p.Version, PolicyVersion)
	}
	egress, err := egressSection(p.Egress)
	if err != nil {
		return nil, err
	}
	forward, err := forwardToList(p.ForwardTo)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(wirePolicyFileOut{
		Format:    PolicyFormat,
		Version:   version,
		Egress:    egress,
		ForwardTo: forward,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("attest: rendering the policy: %w", err)
	}
	return append(out, '\n'), nil
}

// egressSection renders a policy's egress section, refusing one this package's
// own loader would not read back.
//
// A set claiming unattested egress is refused here rather than rendered, so
// that "sign what you wrote, ship what you signed" cannot produce a document
// that does not load.
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

// forwardToList renders the measurements a policy forwards to, refusing a list
// its own loader would not read back. The empty list renders as [] rather than
// as null, because absent does not load and "dials nobody" has to be writable.
func forwardToList(measurements [][]byte) ([]string, error) {
	out := make([]string, 0, len(measurements))
	seen := map[string]bool{}
	for i, m := range measurements {
		if len(m) == 0 {
			return nil, fmt.Errorf("attest: forward_to[%d] is empty; a measurement of no bytes names no image", i)
		}
		s := hex.EncodeToString(m)
		if seen[s] {
			return nil, fmt.Errorf("attest: forward_to names %s twice", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// SignPolicy signs a policy document with the reference value author's key,
// returning the contents of the signature file that belongs beside it.
//
// It is the same key that signs a reference value set — one operator authorises
// both — and a different domain, so neither signature is ever the other's.
// document is signed exactly as given; there is no canonicalisation step here
// that could quietly make the bytes signed and the bytes shipped different.
func SignPolicy(document []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attest: reference value author key is %d bytes, want an Ed25519 private key of %d", len(key), ed25519.PrivateKeySize)
	}
	signature := ed25519.Sign(key, policySignedBytes(document))
	out := make([]byte, hex.EncodedLen(len(signature))+1)
	hex.Encode(out, signature)
	out[len(out)-1] = '\n'
	return out, nil
}

// LoadPolicy verifies a policy document against the reference value author's
// public key and, only if that holds, parses it.
//
// Every way this can fail is a refusal matching [ErrPolicyRefused], and there
// is no other outcome and no other entry point. In particular there is no way
// to load a document without a signature, and no way to ask for the document's
// contents when its signature did not hold.
func LoadPolicy(document, signature []byte, author ed25519.PublicKey) (Policy, error) {
	if len(author) != ed25519.PublicKeySize {
		return Policy{}, refusePolicy("the reference value author public key is %d bytes, want an Ed25519 public key of %d", len(author), ed25519.PublicKeySize)
	}
	sig, err := parseSignature(signature, refusePolicy, "policy")
	if err != nil {
		return Policy{}, err
	}
	if !ed25519.Verify(author, policySignedBytes(document), sig) {
		return Policy{}, refusePolicy(
			"the signature is not this reference value author's signature over these bytes; " +
				"either the document was modified in delivery, or it was signed by a different key, " +
				"or it is a signature over some other document this author signed — a reference value " +
				"set's signature is not a policy's, and each covers its own domain")
	}
	// Past this line, and not before it, the document is the author's.
	return parsePolicyDocument(document)
}

// LoadPolicyFile loads the policy at path, whose signature is the file at
// path+[SignatureFileSuffix].
//
// A missing signature file is a refusal like any other, not an absence. So is a
// missing document. Neither error matches [io/fs.ErrNotExist], so a caller
// cannot write the one branch this design cannot survive — the one that treats
// "there is no policy here" as permission to proceed without one.
func LoadPolicyFile(path string, author ed25519.PublicKey) (Policy, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, refusePolicy("reading the policy at %s: %v", path, err)
	}
	sigPath := path + SignatureFileSuffix
	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return Policy{}, refusePolicy("reading the signature at %s: %v", sigPath, err)
	}
	return LoadPolicy(document, signature, author)
}

// policySignedBytes is what the author's key actually signs: the policy domain
// separation prefix followed by the document's exact bytes. It is used by the
// signer, the verifier and [PolicyDigestOf], so the three cannot drift.
func policySignedBytes(document []byte) []byte {
	return signedBytesUnder(policySignaturePrefix, document)
}

// wirePolicyFileOut is the policy as it is written.
type wirePolicyFileOut struct {
	Format    string        `json:"format"`
	Version   int           `json:"version"`
	Egress    wireEgressOut `json:"egress"`
	ForwardTo []string      `json:"forward_to"`
}

// wirePolicy is the policy as it is read. Its required fields are pointers so
// that absent and zero are distinguishable: a document that forgot to say what
// version it is must not be read as version zero, and one that forgot to say
// whom it forwards to must not be read as one that says nobody by accident.
type wirePolicyFile struct {
	Format    *string     `json:"format"`
	Version   *int        `json:"version"`
	Egress    *wireEgress `json:"egress"`
	ForwardTo *[]string   `json:"forward_to"`
}

// wireEgress is the egress section as it is read. Both fields are pointers for
// the reason the fields above are: a section that forgot to say whether
// unattested egress is permitted must not be read as having permitted nothing
// by accident. The author of a policy says what the policy is.
type wireEgress struct {
	Version    *int  `json:"version"`
	Unattested *bool `json:"unattested"`
}

// wireEgressOut is the egress section as it is written.
type wireEgressOut struct {
	Version    int  `json:"version"`
	Unattested bool `json:"unattested"`
}

// parsePolicyDocument turns a document whose signature has already held into a
// policy.
//
// It is strict in the three ways [parseReferenceValueSetDocument] is, and for
// the same reason: a policy must not end up weaker than the author who signed
// it believed it to be. A field nobody recognises is refused rather than
// skipped, a field named twice is refused rather than resolved to the last one,
// and bytes after the document are refused rather than ignored.
func parsePolicyDocument(document []byte) (Policy, error) {
	if err := rejectRepeatedFields(document, refusePolicy); err != nil {
		return Policy{}, err
	}

	// What the document says it is, read first and with a decoder that
	// tolerates everything else in it. The two signed documents sit beside each
	// other on one config device under two names, so being handed the wrong one
	// is a provisioning mistake worth a sentence — and a strict decode would
	// spend that sentence on the first field it did not recognise.
	var kind struct {
		Format *string `json:"format"`
	}
	if err := json.Unmarshal(document, &kind); err != nil {
		return Policy{}, refusePolicy("the document does not parse: %v", err)
	}
	if kind.Format == nil {
		return Policy{}, refusePolicy("the document does not say what format it is; want %q", PolicyFormat)
	}
	if *kind.Format == ReferenceValueSetFormat {
		return Policy{}, refusePolicy(
			"the document is a reference value set, not a policy; since ticket 19 they are two " +
				"documents — reference-values.json says whom this sandbox admits, and policy.json " +
				"says what it is")
	}
	if *kind.Format != PolicyFormat {
		return Policy{}, refusePolicy("the document is in format %q, this loader reads %q", *kind.Format, PolicyFormat)
	}

	dec := json.NewDecoder(bytes.NewReader(document))
	dec.DisallowUnknownFields()
	var doc wirePolicyFile
	if err := dec.Decode(&doc); err != nil {
		return Policy{}, refusePolicy("the document does not parse: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Policy{}, refusePolicy("the document carries bytes after the policy")
	}

	if doc.Version == nil {
		return Policy{}, refusePolicy("the document does not say what version it is; want %d", PolicyVersion)
	}
	if *doc.Version != PolicyVersion {
		return Policy{}, refusePolicy(
			"the policy is version %d and this loader reads version %d; a policy read on a best-effort "+
				"basis is one a peer's digest vouches for and this sandbox only half enforces, "+
				"so re-emit it at version %d and sign it again",
			*doc.Version, PolicyVersion, PolicyVersion)
	}
	egress, err := doc.Egress.egress()
	if err != nil {
		return Policy{}, err
	}
	forward, err := doc.forwardTo()
	if err != nil {
		return Policy{}, err
	}
	// The digest of the document, taken here so that every loaded policy
	// carries the name a peer will present for it. It is over the signed bytes,
	// which is the region the signature just held over.
	return Policy{
		Version:   *doc.Version,
		Egress:    egress,
		ForwardTo: forward,
		Digest:    PolicyDigestOf(document),
	}, nil
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
		return Egress{}, refusePolicy(
			"the policy has no egress section; a policy says what leaves the sandbox as well as "+
				"whom it dials, and one that says nothing has not said no; "+
				"add \"egress\": {\"version\": %d, \"unattested\": false} and sign it again",
			egressSectionVersion)
	}
	if w.Version == nil {
		return Egress{}, refusePolicy("the egress section does not say what version it is; want %d", egressSectionVersion)
	}
	if *w.Version != egressSectionVersion {
		return Egress{}, refusePolicy("the egress section is version %d, this loader reads version %d", *w.Version, egressSectionVersion)
	}
	if w.Unattested == nil {
		return Egress{}, refusePolicy(
			"the egress section does not say whether unattested egress is permitted; the field is required rather " +
				"than defaulted, because a policy a verifier vouches for is one its author wrote down")
	}
	if *w.Unattested {
		return Egress{}, refusePolicy(
			"the egress section permits unattested egress and nothing here enforces that permission; " +
				"a policy claiming a capability no code implements is weaker than it reads, so it is refused rather " +
				"than admitted with the claim quietly dropped")
	}
	return Egress{Version: *w.Version, Unattested: *w.Unattested}, nil
}

// forwardTo reads the measurements the policy will dial.
//
// Absent is refused and empty is not, which is the whole distinction: "[]" is
// an author saying this sandbox dials nobody, and no field at all is an author
// who did not consider the question. A measurement of the wrong width is not
// refused here, for the reason [ReferenceValue.LaunchMeasurement] gives — how
// wide a measurement is belongs to the hardware vendor, and one that matches
// nothing fails closed.
func (w wirePolicyFile) forwardTo() ([][]byte, error) {
	if w.ForwardTo == nil {
		return nil, refusePolicy(
			"the policy does not say whom it forwards to; a sandbox that dials nobody says so with " +
				"\"forward_to\": [], and one that says nothing has not said it")
	}
	out := make([][]byte, 0, len(*w.ForwardTo))
	seen := map[string]bool{}
	for i, s := range *w.ForwardTo {
		m, err := hex.DecodeString(s)
		if err != nil {
			return nil, refusePolicy("forward_to[%d] is not hexadecimal: %v", i, err)
		}
		if len(m) == 0 {
			return nil, refusePolicy("forward_to[%d] is empty; a measurement of no bytes names no image", i)
		}
		if seen[s] {
			return nil, refusePolicy("forward_to names %s twice; a list a reviewer reads once should not say a thing twice", s)
		}
		seen[s] = true
		out = append(out, m)
	}
	return out, nil
}
