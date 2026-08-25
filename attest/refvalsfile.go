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
// # A detached signature, not an envelope
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
// key, which ADR-0004 already accepts as the one remaining cascade.
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
const ReferenceValueSetVersion = 1

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
	doc := wireSet{
		Format:  ptr(ReferenceValueSetFormat),
		Version: ptr(ReferenceValueSetVersion),
	}
	for _, rv := range set.Values {
		doc.ReferenceValues = append(doc.ReferenceValues, wireValue{
			LaunchMeasurement: ptr(hex.EncodeToString(rv.LaunchMeasurement)),
			MinimumTCB: &wireTCB{
				Bootloader: ptr(rv.MinimumTCB.Bootloader),
				TEE:        ptr(rv.MinimumTCB.TEE),
				SNP:        ptr(rv.MinimumTCB.SNP),
				Microcode:  ptr(rv.MinimumTCB.Microcode),
			},
			GuestPolicy: &wirePolicy{
				ABIMajor:            rv.GuestPolicy.ABIMajor,
				ABIMinor:            rv.GuestPolicy.ABIMinor,
				AllowSMT:            rv.GuestPolicy.AllowSMT,
				AllowMigrationAgent: rv.GuestPolicy.AllowMigrationAgent,
				AllowDebug:          rv.GuestPolicy.AllowDebug,
				RequireSingleSocket: rv.GuestPolicy.RequireSingleSocket,
			},
		})
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("attest: rendering the reference value set: %w", err)
	}
	return append(out, '\n'), nil
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
	if *doc.Version != ReferenceValueSetVersion {
		return ReferenceValueSet{}, refuseSet("the document is version %d, this loader reads version %d", *doc.Version, ReferenceValueSetVersion)
	}

	set := ReferenceValueSet{}
	for i, wv := range doc.ReferenceValues {
		rv, err := wv.referenceValue()
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

// wireSet is the document. Its required fields are pointers so that absent and
// zero are distinguishable: a document that forgot to say what version it is
// must not be read as version zero.
type wireSet struct {
	Format          *string     `json:"format"`
	Version         *int        `json:"version"`
	ReferenceValues []wireValue `json:"reference_values"`
}

// wireValue is one reference value.
//
// The set is always a list, even when it holds one value, because that is what
// makes an image rollout expressible: the old measurement and the new one sit
// in the file together while both are running, and neither deployment has to
// stop for the other. A format that allowed a bare single value would make the
// common case shorter and the case the design exists to support a special one.
type wireValue struct {
	// LaunchMeasurement is hexadecimal. Its width is not checked, deliberately:
	// how wide a launch measurement is belongs to the hardware vendor, and
	// baking one vendor's digest width into the format is exactly the seam that
	// makes a second vendor a day's work rather than a refactor. A measurement
	// of the wrong width matches nothing, which fails closed.
	LaunchMeasurement *string `json:"launch_measurement"`

	// MinimumTCB is required. An author writing a trust root has an opinion
	// about which firmware levels to admit, and a floor that defaults silently
	// to zero when the key is left out is a floor nobody chose.
	MinimumTCB *wireTCB `json:"minimum_tcb"`

	// GuestPolicy may be omitted, and omitting it permits nothing — the zero
	// value of [GuestPolicy] is the fail-closed direction, which is the right
	// default for a reference value whose author did not think about policy.
	// This asymmetry with MinimumTCB is deliberate: an absent field may make a
	// value stricter than intended, never weaker.
	GuestPolicy *wirePolicy `json:"guest_policy"`
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

func (w wireValue) referenceValue() (ReferenceValue, error) {
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
	tcb, err := w.MinimumTCB.tcb()
	if err != nil {
		return ReferenceValue{}, err
	}
	rv := ReferenceValue{LaunchMeasurement: measurement, MinimumTCB: tcb}
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

// repeatedField is the one thing the token walk below is looking for.
type repeatedField struct{ where string }

func (e *repeatedField) Error() string { return "repeated field " + e.where }

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

func ptr[T any](v T) *T { return &v }
