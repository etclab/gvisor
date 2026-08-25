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

// Tests for the signed reference value set: its on-disk format, its signature
// and its loader.
//
// These drive the same seam as the verification tests — this module's public
// surface, and the one a tunneld will call at ticket 09. A loaded set is never
// inspected field by field as though loading were the point; it is wired into a
// [attest.Verification] and shown to admit or refuse a fake platform, because
// what a reference value set is for is deciding who gets in. Nothing here
// reaches inside the loader or asserts on how a refusal was reached.
//
// The documents are written out as literals rather than rendered by
// [attest.MarshalReferenceValueSet]. That is the point of the format: a
// reference value author writes a file a human reads, so the tests read the
// same way. A test whose fixture was machine-generated would prove the loader
// can read its own output and nothing about whether a person can write one.
//
// Every refusal is paired with a control on the same wiring showing that a good
// set still loads and still admits its platform. Where a refusal is about the
// document rather than the signature, the mutated document is signed afresh, so
// that the refusal cannot be a signature failure wearing a disguise.
package attest_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
)

// documentFormat is the format string spelled out rather than taken from
// [attest.ReferenceValueSetFormat]. It is a wire constant: a document already
// signed and shipped does not change when a Go identifier is renamed, so the
// test hardcodes what is on disk and fails if the constant drifts from it.
const documentFormat = "gvisor.dev/gvisor/attest/reference-value-set"

// oneValueDocument is a reference value set as an author writes it: one image,
// a TCB floor as four separately named component versions, and a guest policy
// that permits SMT and nothing else. It admits the platform defaultConfig
// fakes.
//
// Read it. That is the criterion this format exists to satisfy, and the
// numbers below are the same ones platformTCB and permittedPolicy hold in Go.
const oneValueDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 1,
  "reference_values": [
    {
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {
        "bootloader": 9,
        "tee": 0,
        "snp": 23,
        "microcode": 72
      },
      "guest_policy": {
        "abi_major": 0,
        "abi_minor": 0,
        "allow_smt": true,
        "allow_migration_agent": false,
        "allow_debug": false,
        "require_single_socket": false
      }
    }
  ]
}
`

// twoValueDocument is the same file during an image rollout: the measurement
// that is running and the measurement that is being deployed, both named, so
// that neither deployment has to stop for the other.
const twoValueDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 1,
  "reference_values": [
    {
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    },
    {
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    }
  ]
}
`

// nonCanonicalDocument is the same set as oneValueDocument written by someone
// with different habits: no indentation, keys in another order, and the guest
// policy's fail-closed defaults left out rather than spelled out. There is no
// canonical form to be in, so it loads and admits the same platform.
const nonCanonicalDocument = `{"reference_values":[{"guest_policy":{"allow_smt":true},` +
	`"minimum_tcb":{"microcode":72,"snp":23,"tee":0,"bootloader":9},` +
	`"launch_measurement":"$MEASUREMENT"}],"version":1,` +
	`"format":"gvisor.dev/gvisor/attest/reference-value-set"}`

// measurementPlaceholder stands in for a hexadecimal launch measurement in the
// document templates above.
//
// It is a placeholder rather than a format verb because several tests below
// build a variant by deleting the launch_measurement line outright, and a
// Sprintf whose verb has just been deleted appends its argument as an error
// string — which would refuse the document as malformed JSON while the test
// claimed it was refused for naming no measurement.
const measurementPlaceholder = "$MEASUREMENT"

// documentFor fills a document template with hexadecimal measurements, in
// order, and tolerates a template a test has removed a placeholder from.
func documentFor(template string, measurements ...[]byte) string {
	for _, m := range measurements {
		template = strings.Replace(template, measurementPlaceholder, hex.EncodeToString(m), 1)
	}
	return template
}

// theDocument is the one-value document naming theMeasurement — the good set
// that every refusal below is paired against.
func theDocument() string { return documentFor(oneValueDocument, theMeasurement) }

// an author is a reference value author: the key pair whose public half a
// measured image carries and whose private half authorises a set.
type author struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newAuthor(t *testing.T) author {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a reference value author key: %v", err)
	}
	return author{public: pub, private: priv}
}

// sign authorises a document, returning the contents of the file that belongs
// beside it.
func (a author) sign(t *testing.T, document string) []byte {
	t.Helper()
	signature, err := attest.SignReferenceValueSet([]byte(document), a.private)
	if err != nil {
		t.Fatalf("signing a reference value set: %v", err)
	}
	return signature
}

// loads asserts that a document and signature load, and returns the set.
func loads(t *testing.T, a author, document string) attest.ReferenceValueSet {
	t.Helper()
	set, err := attest.LoadReferenceValueSet([]byte(document), a.sign(t, document), a.public)
	if err != nil {
		t.Fatalf("a well-formed signed set was refused: %v", err)
	}
	return set
}

// refusesToLoad asserts that a document and signature are refused, and that the
// refusal is the one outcome this package offers other than a loaded set.
func refusesToLoad(t *testing.T, document string, signature []byte, public ed25519.PublicKey) {
	t.Helper()
	set, err := attest.LoadReferenceValueSet([]byte(document), signature, public)
	if err == nil {
		t.Fatalf("the set loaded as %+v; want a refusal", set)
	}
	if !errors.Is(err, attest.ErrSetRefused) {
		t.Errorf("refusal does not match attest.ErrSetRefused: %v", err)
	}
	if len(set.Values) != 0 {
		t.Errorf("a refused load returned %d reference values; want none", len(set.Values))
	}
}

// admits wires a loaded set to a verifier that trusts f's platform and asserts
// the platform is admitted. This is what makes a loaded set evidence of
// anything: the file decides who gets in, so the test asks who gets in.
func admits(t *testing.T, f *fixture, set attest.ReferenceValueSet) attest.Attested {
	t.Helper()
	return accepts(t, verification(t, f, set), f)
}

// TestASignedSetLoadsAndDrivesVerification is the control the whole file rests
// on: a set an author wrote, signed and delivered admits the platform it names,
// with the TCB floor and guest policy it named intact on the far side.
func TestASignedSetLoadsAndDrivesVerification(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	set := loads(t, a, theDocument())
	attested := admits(t, f, set)

	if !bytes.Equal(attested.Satisfied.LaunchMeasurement, theMeasurement) {
		t.Errorf("admitted by the reference value for %x; want the one for %x",
			attested.Satisfied.LaunchMeasurement, theMeasurement)
	}
	if attested.Satisfied.MinimumTCB != floorTCB {
		t.Errorf("the loaded TCB floor is %+v; want %+v", attested.Satisfied.MinimumTCB, floorTCB)
	}
	if attested.Satisfied.GuestPolicy != permittedPolicy {
		t.Errorf("the loaded guest policy is %+v; want %+v", attested.Satisfied.GuestPolicy, permittedPolicy)
	}
}

// TestEachNamedTCBComponentIsLoadBearing is the evidence that a TCB floor is
// four separately named component versions rather than four words next to a
// number nobody reads.
//
// Raising each component by one, one at a time, must refuse a platform that
// meets the other three. A format that packed the floor into an integer, or a
// loader that read three of the four names and defaulted the fourth, would pass
// the control and fail here.
func TestEachNamedTCBComponentIsLoadBearing(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	// Control: the floor as written admits the platform.
	admits(t, f, loads(t, a, theDocument()))

	for _, component := range []struct{ name, was, raised string }{
		{"bootloader", `"bootloader": 9`, `"bootloader": 10`},
		{"tee", `"tee": 0`, `"tee": 1`},
		{"snp", `"snp": 23`, `"snp": 24`},
		{"microcode", `"microcode": 72`, `"microcode": 73`},
	} {
		t.Run(component.name, func(t *testing.T) {
			document := strings.Replace(theDocument(), component.was, component.raised, 1)
			if document == theDocument() {
				t.Fatalf("the document does not contain %s; the fixture has drifted", component.was)
			}
			set := loads(t, a, document)
			v := verification(t, f, set)
			refuses(t, v, f.evidence, f.binding, attest.ReasonTCBBelowFloor)
		})
	}
}

// TestASetHoldingSeveralValuesAdmitsEvidenceMatchingAnyOne re-verifies through
// the loader the property ticket 02 established in memory: a set is a list, so
// a new image rolls out while the old one is still running.
//
// The list is what makes that expressible. A format that allowed a bare single
// value would have made the common case shorter and this case a special one.
func TestASetHoldingSeveralValuesAdmitsEvidenceMatchingAnyOne(t *testing.T) {
	a := newAuthor(t)
	set := loads(t, a, documentFor(twoValueDocument, otherMeasurement, theMeasurement))

	// The image that is running.
	running := newFixture(t, withMeasurement(defaultConfig(), otherMeasurement))
	if got := admits(t, running, set); !bytes.Equal(got.Satisfied.LaunchMeasurement, otherMeasurement) {
		t.Errorf("admitted by the reference value for %x; want the one for %x",
			got.Satisfied.LaunchMeasurement, otherMeasurement)
	}

	// The image being deployed, from the same file, with neither redeployed.
	deploying := newFixture(t, defaultConfig())
	if got := admits(t, deploying, set); !bytes.Equal(got.Satisfied.LaunchMeasurement, theMeasurement) {
		t.Errorf("admitted by the reference value for %x; want the one for %x",
			got.Satisfied.LaunchMeasurement, theMeasurement)
	}
}

// TestASetWithAnInvalidSignatureIsRefused is the untrusted delivery channel
// doing its worst to the signature.
func TestASetWithAnInvalidSignatureIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control: the signature as the author produced it.
	admits(t, f, loads(t, a, document))

	good := a.sign(t, document)
	for _, tc := range []struct {
		name      string
		signature []byte
	}{
		{"one flipped byte", flipHexDigit(good)},
		{"truncated", good[:len(good)/2]},
		{"not hexadecimal", []byte("this is not a signature\n")},
		{"someone else's signature", newAuthor(t).sign(t, document)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusesToLoad(t, document, tc.signature, a.public)
		})
	}
}

// TestASignatureOverTheBareDocumentIsRefused is domain separation doing its
// job.
//
// What the author's key signs is a fixed prefix followed by the document, not
// the document alone. The reference value author's key is this system's trust
// root and is the most valuable signing key in the design; a signature it
// produces over some other artefact — a peer table, a manifest, a chain
// description — must not also be a valid signature over a reference value set
// that happens to be the same bytes. Without the prefix it would be.
//
// The test signs the document the naive way, with the same key, and requires
// the loader to refuse it.
func TestASignatureOverTheBareDocumentIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control: the same key, the same document, signed the way this format says
	// to sign it.
	admits(t, f, loads(t, a, document))

	bare := ed25519.Sign(a.private, []byte(document))
	hexBare := make([]byte, hex.EncodedLen(len(bare)))
	hex.Encode(hexBare, bare)
	refusesToLoad(t, document, hexBare, a.public)
}

// TestASetWithNoSignatureIsRefused is the case that must never be read as "this
// set is unsigned, so treat it as absent". There is no unsigned set: the loader
// offers no entry point that does not take a signature, and an empty one is a
// refusal like any other.
func TestASetWithNoSignatureIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct {
		name      string
		signature []byte
	}{
		{"no signature at all", nil},
		{"an empty signature file", []byte{}},
		{"a signature file holding only whitespace", []byte("\n  \n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusesToLoad(t, document, tc.signature, a.public)
		})
	}
}

// TestASetSignedByTheWrongKeyIsRefused is the substitution attack ADR-0004
// exists to prevent, in its most direct form: an untrusted host authors its own
// permissive set, signs it perfectly with its own key, and delivers it.
//
// The set it substitutes is one that would admit a platform the real author
// never authorised, so accepting it would be a real compromise and not a
// bookkeeping error.
func TestASetSignedByTheWrongKeyIsRefused(t *testing.T) {
	a := newAuthor(t)
	host := newAuthor(t)
	f := newFixture(t, withMeasurement(defaultConfig(), otherMeasurement))

	// Control: the author's own set does not admit this platform, so the host
	// has something to gain.
	authorised := loads(t, a, theDocument())
	refuses(t, verification(t, f, authorised), f.evidence, f.binding, attest.ReasonMeasurementNotInSet)

	// The host's set would admit it, and is signed — by the wrong key.
	permissive := documentFor(oneValueDocument, otherMeasurement)
	refusesToLoad(t, permissive, host.sign(t, permissive), a.public)

	// Nor can a document nominate the key that should authorise it. There is no
	// field for one, and a document that invents one is refused — here with the
	// real author's own signature over it, so that the refusal is the invented
	// field and nothing else. The key the loader trusts comes from inside the
	// launch measurement and from nowhere else.
	nominating := strings.Replace(permissive, `"version": 1,`,
		`"version": 1,
  "public_key": "`+hex.EncodeToString(host.public)+`",`, 1)
	refusesToLoad(t, nominating, a.sign(t, nominating), a.public)
}

// TestADocumentModifiedAfterSigningIsRefused is the delivery channel doing its
// worst to the document instead. The modification is a weakening a host would
// actually want: permit the debugging it can then use to read the guest.
func TestADocumentModifiedAfterSigningIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()
	signature := a.sign(t, document)

	// Control: the document as signed.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, modified string }{
		{"a policy bit relaxed", strings.Replace(document, `"allow_debug": false`, `"allow_debug": true`, 1)},
		{"the TCB floor lowered", strings.Replace(document, `"microcode": 72`, `"microcode": 0`, 1)},
		{"whitespace only", strings.Replace(document, `"version": 1,`, `"version":1,`, 1)},
		{"a byte appended", document + " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.modified == document {
				t.Fatal("the modification did not change the document; the fixture has drifted")
			}
			refusesToLoad(t, tc.modified, signature, a.public)
		})
	}
}

// TestAnUnknownFieldIsRefused is the checkbox that keeps a value from ending up
// weaker than its author intended. A loader that skipped what it did not
// understand would read a value the author wrote a constraint into and enforce
// only the part it recognised.
//
// Every document here is signed afresh, so each refusal is the unknown field
// and not a signature that no longer holds.
func TestAnUnknownFieldIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control: the same document without the extra field.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, from, to string }{
		{
			"at the top level",
			`"version": 1,`,
			`"version": 1,
  "allow_anything": true,`,
		},
		{
			"in a reference value",
			`"launch_measurement": "`,
			`"id_key_digest": "aabb",
      "launch_measurement": "`,
		},
		{
			"in the TCB floor",
			`"bootloader": 9,`,
			`"bootloader": 9,
        "reserved": 0,`,
		},
		{
			"in the guest policy",
			`"allow_smt": true,`,
			`"allow_smt": true,
        "allow_everything_else": true,`,
		},
		// A known field in the wrong case is, to the parser, the known
		// field; to a reviewer it is a field the format does not define.
		{
			"a known field in the wrong case",
			`"microcode": 72`,
			`"MICROCODE": 72`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, tc.from, tc.to, 1)
			if modified == document {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			refusesToLoad(t, modified, a.sign(t, modified), a.public)
		})
	}
}

// TestAFieldNamedTwiceIsRefused closes the other half of the same hole. An
// unknown field is a constraint the loader cannot see; a repeated field is a
// constraint the reviewer cannot see, because a person reads the first
// occurrence and a JSON parser takes the last.
//
// The author signed both occurrences, so the signature cannot help here. Only
// refusing can.
func TestAFieldNamedTwiceIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, from, to string }{
		{
			"a policy bit",
			`"allow_debug": false,`,
			`"allow_debug": false,
        "allow_debug": true,`,
		},
		{
			"a TCB component",
			`"microcode": 72`,
			`"microcode": 72,
        "microcode": 0`,
		},
		{
			"the list of values",
			`"reference_values": [`,
			`"reference_values": [],
  "reference_values": [`,
		},
		// encoding/json matches field names case-insensitively, so these
		// are repeats to the parser and distinct fields to a reviewer.
		{
			"a policy bit differing only in case",
			`"allow_debug": false,`,
			`"allow_debug": false,
        "ALLOW_DEBUG": true,`,
		},
		{
			"a TCB component differing only in case",
			`"microcode": 72`,
			`"microcode": 72,
        "Microcode": 0`,
		},
		{
			"a TCB component under Unicode folding",
			`"snp": 23,`,
			`"snp": 23,
        "\u017fnp": 0,`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, tc.from, tc.to, 1)
			if modified == document {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			refusesToLoad(t, modified, a.sign(t, modified), a.public)
		})
	}
}

// TestBytesAfterTheDocumentAreRefused: a second document appended to the first
// is not a comment. Ignoring it would let an author's file and a reviewer's
// reading of it disagree about where the set ends.
func TestBytesAfterTheDocumentAreRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, trailing string }{
		{"a second set", documentFor(oneValueDocument, otherMeasurement)},
		{"a stray token", "null\n"},
		{"prose", "and that is the set\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := document + tc.trailing
			refusesToLoad(t, modified, a.sign(t, modified), a.public)
		})
	}
}

// TestADocumentOfTheWrongFormatOrVersionIsRefused: a loader that reads whatever
// fields it recognises out of whatever JSON it is handed can be pointed at
// another file, and a loader that reads a future version on a best-effort basis
// enforces the part of it that already existed. Both are the failure ADR-0002
// describes for the binding context, in a different file.
func TestADocumentOfTheWrongFormatOrVersionIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, from, to string }{
		{"another format", `"format": "` + documentFormat + `"`, `"format": "example.com/some-other-file"`},
		{"no format", `"format": "` + documentFormat + `",`, ``},
		{"a later version", `"version": 1`, `"version": 2`},
		{"no version", `"version": 1,`, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, tc.from, tc.to, 1)
			if modified == document {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			refusesToLoad(t, modified, a.sign(t, modified), a.public)
		})
	}
}

// TestASetThatCannotMeanWhatItsAuthorIntendedDoesNotLoad covers the ways a
// document is refused for what it says rather than for how it was delivered.
//
// The empty list admits nobody, which is a mistake. A value with no launch
// measurement admits everybody, which is the mistake that does not announce
// itself. A TCB floor with a component left out is a floor of zero for that
// component, which a reviewer reading three lines does not notice.
//
// Each variant is the control document with exactly one thing cut out of it,
// written out in full rather than produced by renaming a key — a renamed key is
// an unknown field, and would be refused by a check other than the one under
// test.
func TestASetThatCannotMeanWhatItsAuthorIntendedDoesNotLoad(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	const (
		head   = `{"format": "` + documentFormat + `", "version": 1, "reference_values": [`
		policy = `"guest_policy": {"allow_smt": true}`
		floor  = `"minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72}`
		tail   = `]}`
	)
	complete := head + `{"launch_measurement": "` + measurementPlaceholder + `", ` + floor + `, ` + policy + `}` + tail

	// Control: complete, this document loads and admits its platform. Every
	// variant below is this document minus one thing.
	admits(t, f, loads(t, a, documentFor(complete, theMeasurement)))

	for _, tc := range []struct{ name, document string }{
		{
			"an empty list of values",
			head + tail,
		},
		{
			"no launch measurement",
			head + `{` + floor + `, ` + policy + `}` + tail,
		},
		{
			"an empty launch measurement",
			head + `{"launch_measurement": "", ` + floor + `, ` + policy + `}` + tail,
		},
		{
			"no TCB floor",
			head + `{"launch_measurement": "` + measurementPlaceholder + `", ` + policy + `}` + tail,
		},
		{
			"a TCB floor missing a component",
			head + `{"launch_measurement": "` + measurementPlaceholder + `", ` +
				`"minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23}, ` + policy + `}` + tail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.document == complete {
				t.Fatal("the variant is the control document; the fixture has drifted")
			}
			document := documentFor(tc.document, theMeasurement)
			refusesToLoad(t, document, a.sign(t, document), a.public)
		})
	}
}

// TestTheLoaderDoesNotJudgeALaunchMeasurementsWidth is a regression guard on a
// deliberate omission.
//
// How wide a launch measurement is belongs to the hardware vendor. A width
// check in this loader would put one vendor's digest size above the seam that
// exists to make a second vendor a day's work, and it would buy nothing: a
// measurement of the wrong width matches no platform, so the set already fails
// closed at verification rather than at load.
func TestTheLoaderDoesNotJudgeALaunchMeasurementsWidth(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	// Control: a measurement of this platform's width is admitted.
	admits(t, f, loads(t, a, theDocument()))

	narrow := bytes.Repeat([]byte{0x33}, 32)
	set := loads(t, a, documentFor(oneValueDocument, narrow))

	// It loaded. It simply matches nothing, which is the fail-closed direction
	// and is verification's answer to give, not the loader's.
	refuses(t, verification(t, f, set), f.evidence, f.binding, attest.ReasonMeasurementNotInSet)
}

// TestASetOnDiskLoadsFromItsDocumentAndSignature is the config device layout:
// the document, and its signature in a second file beside it.
func TestASetOnDiskLoadsFromItsDocumentAndSignature(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	dir := t.TempDir()
	path := filepath.Join(dir, "reference-values.json")
	document := theDocument()

	writeFile(t, path, []byte(document))
	writeFile(t, path+attest.SignatureFileSuffix, a.sign(t, document))

	set, err := attest.LoadReferenceValueSetFile(path, a.public)
	if err != nil {
		t.Fatalf("loading a well-formed set from disk: %v", err)
	}
	admits(t, f, set)
}

// TestARefusedSetIsNeverTreatedAsAbsent is the property ADR-0004 turns on.
//
// A caller that can tell "there is no set here" from "the set here does not
// verify" is a caller that can be tempted to treat the first as permission to
// carry on. So the loader does not offer that distinction: a missing file is a
// refusal, and the refusal does not carry io/fs.ErrNotExist for anyone to
// branch on. The operator still reads which file was missing, in the text.
func TestARefusedSetIsNeverTreatedAsAbsent(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	dir := t.TempDir()
	document := theDocument()

	// Control: both files present, and the set admits its platform.
	both := filepath.Join(dir, "both.json")
	writeFile(t, both, []byte(document))
	writeFile(t, both+attest.SignatureFileSuffix, a.sign(t, document))
	set, err := attest.LoadReferenceValueSetFile(both, a.public)
	if err != nil {
		t.Fatalf("loading a well-formed set from disk: %v", err)
	}
	admits(t, f, set)

	// A document with no signature beside it: the shape a host takes when it
	// strips the signature and hopes the set is used anyway.
	unsigned := filepath.Join(dir, "unsigned.json")
	writeFile(t, unsigned, []byte(document))

	for _, tc := range []struct{ name, path string }{
		{"no document and no signature", filepath.Join(dir, "absent.json")},
		{"a document with no signature beside it", unsigned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := attest.LoadReferenceValueSetFile(tc.path, a.public)
			if err == nil {
				t.Fatalf("the set loaded as %+v; want a refusal", set)
			}
			if !errors.Is(err, attest.ErrSetRefused) {
				t.Errorf("refusal does not match attest.ErrSetRefused: %v", err)
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the refusal is distinguishable as a missing file (%v); "+
					"a caller could branch on that and treat an unverifiable set as an absent one", err)
			}
			if len(set.Values) != 0 {
				t.Errorf("a refused load returned %d reference values; want none", len(set.Values))
			}
		})
	}
}

// TestARenderedSetIsSignableAndLoadable covers the path ticket 07 takes: the
// image build renders the set it just computed a measurement for, signs it, and
// ships both. Building and authorising are then one traceable step.
//
// The rendering is checked for the one property that makes it reviewable — the
// TCB floor written as four named components — and then put through the loader
// and the verifier like any other set.
func TestARenderedSetIsSignableAndLoadable(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	document, err := attest.MarshalReferenceValueSet(defaultSet())
	if err != nil {
		t.Fatalf("rendering a reference value set: %v", err)
	}
	for _, component := range []string{`"bootloader"`, `"tee"`, `"snp"`, `"microcode"`} {
		if !strings.Contains(string(document), component) {
			t.Errorf("the rendered document does not name %s; a TCB floor is four separately named "+
				"component versions, not a packed integer:\n%s", component, document)
		}
	}

	set, err := attest.LoadReferenceValueSet(document, a.sign(t, string(document)), a.public)
	if err != nil {
		t.Fatalf("a rendered set was refused by the loader: %v", err)
	}
	admits(t, f, set)
}

// TestTheSignatureCoversTheDeliveredBytesAndNotARendering is the trap this
// format is shaped to avoid, written down as a test so nobody reintroduces it.
//
// There is no canonical form. The signature covers the document's exact bytes
// as delivered, so a document whose keys are in another order, whose whitespace
// is its author's own and whose optional fields are left out loads exactly as
// well as a rendered one. A loader that parsed and re-rendered before checking
// the signature would accept whatever its own renderer produced, reject
// whatever anyone else's did, and quietly stop enforcing anything its parser
// dropped along the way.
func TestTheSignatureCoversTheDeliveredBytesAndNotARendering(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := documentFor(nonCanonicalDocument, theMeasurement)

	// It is nothing like a rendering, and it loads and admits its platform.
	set := loads(t, a, document)
	admits(t, f, set)

	rendered, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("rendering a loaded set: %v", err)
	}
	if bytes.Equal(rendered, []byte(document)) {
		t.Fatal("the rendering equals the delivered document; the fixture no longer tests anything")
	}

	// The author's signature is over what the author wrote. If a rendering ever
	// verifies against it, some canonicalisation has been introduced and the
	// signature has stopped covering the delivered bytes.
	if _, err := attest.LoadReferenceValueSet(rendered, a.sign(t, document), a.public); err == nil {
		t.Error("a rendering verified against the delivered document's signature; " +
			"the signature must cover the delivered bytes and nothing else")
	}

	// Signing what you ship works, which is the whole discipline the API
	// enforces: both entry points take the document as bytes, and there is no
	// path from a parsed set back to a signature check.
	if _, err := attest.LoadReferenceValueSet(rendered, a.sign(t, string(rendered)), a.public); err != nil {
		t.Errorf("a rendered set signed as rendered was refused: %v", err)
	}
}

// TestAnAuthorKeyThatIsNotAnEd25519KeyIsRefused: ed25519.Verify panics on a key
// of the wrong length, so a mis-provisioned author key must be a refusal rather
// than a crash — and must not be mistaken for a set that failed to verify.
func TestAnAuthorKeyThatIsNotAnEd25519KeyIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()
	signature := a.sign(t, document)

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct {
		name string
		key  ed25519.PublicKey
	}{
		{"no key at all", nil},
		{"a truncated key", a.public[:16]},
		{"an over-long key", append(append(ed25519.PublicKey{}, a.public...), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusesToLoad(t, document, signature, tc.key)
		})
	}
}

// flipHexDigit changes one character of a hexadecimal signature, leaving it
// well-formed and the right length.
func flipHexDigit(signature []byte) []byte {
	flipped := append([]byte(nil), signature...)
	if flipped[0] == '0' {
		flipped[0] = '1'
	} else {
		flipped[0] = '0'
	}
	return flipped
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o444); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
