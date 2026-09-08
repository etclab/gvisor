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
// surface, and the one a tunneld will call at ticket 09. A loaded set is not
// inspected field by field as though loading were the point; it is wired into a
// [attest.Verification] and shown to admit or refuse a fake platform, because
// what a reference value set is for is deciding who gets in. Nothing here
// reaches inside the loader or asserts on how a refusal was reached.
//
// The Intel TDX values are the exception, and are inspected. Their verifier and
// its fake platform live in other packages, so what a TDX document decides is
// tested where that verifier is; what is tested here is that the document says
// it.
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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
  "version": 3,
  "egress": {"version": 1, "unattested": false},
  "reference_values": [
    {
      "vendor": "amd-sev-snp",
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
  "version": 3,
  "egress": {"version": 1, "unattested": false},
  "reference_values": [
    {
      "vendor": "amd-sev-snp",
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    },
    {
      "vendor": "amd-sev-snp",
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
	`"vendor":"amd-sev-snp","launch_measurement":"$MEASUREMENT"}],"version":3,` +
	`"egress":{"unattested":false,"version":1},` +
	`"format":"gvisor.dev/gvisor/attest/reference-value-set"}`

// versionOneDocument is a set as it was authored and signed before this format
// carried a vendor: version 1, and a reference value that names a launch
// measurement without saying whose evidence it admits.
//
// Documents of this shape exist and are signed — every set recorded under
// docs/snp is one — which is exactly why the loader has to refuse them out
// loud rather than read them as SEV-SNP.
const versionOneDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 1,
  "reference_values": [
    {
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    }
  ]
}
`

// versionTwoDocument is a set as it was authored and signed after the format
// carried a vendor on every value and before it carried an egress section:
// version 2, and a file that says whom this sandbox may talk to without saying
// what may leave it.
//
// Documents of this shape exist and are signed — the ticket 14 harness shipped
// one — which is why the loader has to refuse them out loud and say what to add.
const versionTwoDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 2,
  "reference_values": [
    {
      "vendor": "amd-sev-snp",
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    }
  ]
}
`

// egressSection is the egress section written on one line, for the documents
// below that are assembled from constants rather than written out whole.
const egressSection = `"egress": {"version": 1, "unattested": false}`

// The registers an Intel TDX reference value names. Each is a distinct repeated
// byte, so a value read back out of a loaded set says which register it came
// from. Their roles are not interchangeable: theMRTD, theRTMR0 and the two
// values RTMR1 takes are the provider's, observed on real hardware and
// unpredictable from anything an author holds, while thePredictedRTMR2 is the
// image's, computed before anything boots.
//
// RTMR1 has two values because Google's VMs give it two: one on a VM's first
// boot and another on every boot after (docs/snp/evidence/tdx). A reference
// value naming one would refuse its own peer after a reboot.
var (
	theMRTD           = bytes.Repeat([]byte{0x33}, 48)
	theRTMR0          = bytes.Repeat([]byte{0x44}, 48)
	firstBootRTMR1    = bytes.Repeat([]byte{0x55}, 48)
	laterBootRTMR1    = bytes.Repeat([]byte{0x66}, 48)
	thePredictedRTMR2 = bytes.Repeat([]byte{0x77}, 48)
)

// tdxValueDocument is an Intel TDX reference value as an author writes it.
//
// Read it, and read the field names in particular. Three of them say observed
// and one says predicted, and that is the difference between a constant copied
// off the provider's running machines because nobody can compute it, and the
// one register computed from the image before it booted. A check built on a
// value read back off the machine it is checking cannot fail.
const tdxValueDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 3,
  "egress": {"version": 1, "unattested": false},
  "reference_values": [
    {
      "vendor": "intel-tdx",
      "observed_mrtd": ["$MRTD"],
      "observed_rtmr0": ["$RTMR0"],
      "observed_rtmr1": ["$RTMR1A", "$RTMR1B"],
      "predicted_rtmr2": "$RTMR2",
      "td_attributes_policy": {"allow_debug": false},
      "minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}
    }
  ]
}
`

// mixedDocument is one file holding both vendors: the same peer group reachable
// from an AMD guest and from an Intel one, which is the whole reason a value
// carries a vendor rather than a verifier carrying a file of its own.
const mixedDocument = `{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 3,
  "egress": {"version": 1, "unattested": false},
  "reference_values": [
    {
      "vendor": "amd-sev-snp",
      "launch_measurement": "$MEASUREMENT",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    },
    {
      "vendor": "intel-tdx",
      "observed_mrtd": ["$MRTD"],
      "observed_rtmr0": ["$RTMR0"],
      "observed_rtmr1": ["$RTMR1A", "$RTMR1B"],
      "predicted_rtmr2": "$RTMR2",
      "td_attributes_policy": {"allow_debug": false},
      "minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}
    }
  ]
}
`

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

// withRegisters fills a TDX template's register placeholders. They are named
// rather than positional because a document that named RTMR0 where it meant
// RTMR2 would still load, and the test would be checking the wrong register.
func withRegisters(template string) string {
	for _, r := range []struct {
		placeholder string
		value       []byte
	}{
		{"$MRTD", theMRTD},
		{"$RTMR0", theRTMR0},
		{"$RTMR1A", firstBootRTMR1},
		{"$RTMR1B", laterBootRTMR1},
		{"$RTMR2", thePredictedRTMR2},
	} {
		template = strings.ReplaceAll(template, r.placeholder, hex.EncodeToString(r.value))
	}
	return template
}

// theTDXDocument is the one-value TDX document, and theMixedDocument the file
// holding one value of each vendor.
func theTDXDocument() string   { return withRegisters(tdxValueDocument) }
func theMixedDocument() string { return withRegisters(documentFor(mixedDocument, theMeasurement)) }

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
	nominating := strings.Replace(permissive, `"version": 3,`,
		`"version": 3,
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
		{"whitespace only", strings.Replace(document, `"version": 3,`, `"version":3,`, 1)},
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
			`"version": 3,`,
			`"version": 3,
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
		{"a later version", `"version": 3`, `"version": 4`},
		{"no version", `"version": 3,`, ``},
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
		head   = `{"format": "` + documentFormat + `", "version": 3, ` + egressSection + `, "reference_values": [`
		vendor = `"vendor": "amd-sev-snp"`
		policy = `"guest_policy": {"allow_smt": true}`
		floor  = `"minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72}`
		tail   = `]}`
	)
	complete := head + `{` + vendor + `, "launch_measurement": "` + measurementPlaceholder + `", ` + floor + `, ` + policy + `}` + tail

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
			head + `{` + vendor + `, ` + floor + `, ` + policy + `}` + tail,
		},
		{
			"an empty launch measurement",
			head + `{` + vendor + `, "launch_measurement": "", ` + floor + `, ` + policy + `}` + tail,
		},
		{
			"no TCB floor",
			head + `{` + vendor + `, "launch_measurement": "` + measurementPlaceholder + `", ` + policy + `}` + tail,
		},
		{
			"a TCB floor missing a component",
			head + `{` + vendor + `, "launch_measurement": "` + measurementPlaceholder + `", ` +
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
	if !strings.Contains(string(document), `"vendor": "amd-sev-snp"`) {
		t.Errorf("the rendered document does not name the vendor its value is about:\n%s", document)
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

// TestAVersionOneDocumentIsRefusedAsCarryingNoVendorTag is the format change
// this ticket priced, enforced.
//
// A version 1 value names a launch measurement and nothing about whose
// hardware produced it. Reading it as SEV-SNP would be defensible and is still
// wrong: it is this loader deciding what an author did not write down, in the
// one file where nothing may be inferred. So the document is refused, and —
// because a refused set is a guest that will not boot — the refusal says what
// to do about it.
func TestAVersionOneDocumentIsRefusedAsCarryingNoVendorTag(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	// Control: the same values, re-emitted at the version this loader reads,
	// still admit the platform. The refusal below is the version and the
	// missing vendor, not anything about these values.
	admits(t, f, loads(t, a, theDocument()))

	document := documentFor(versionOneDocument, theMeasurement)
	refusesToLoad(t, document, a.sign(t, document), a.public)

	_, err := attest.LoadReferenceValueSet([]byte(document), a.sign(t, document), a.public)
	for _, want := range []string{"version 1", "vendor", "re-emit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so an operator reading it does not learn "+
				"that the fix is to re-emit and re-sign the set: %v", want, err)
		}
	}
}

// TestAVersionTwoDocumentIsRefusedAsCarryingNoEgressSection is the same change
// again, one version later.
//
// A version 2 document says whom a sandbox will talk to and nothing about what
// leaves it. Its digest would therefore vouch for a policy that was never
// written, which is worse than no digest at all: a peer checking an allow-list
// entry would believe it had pinned a behaviour nobody stated. The document is
// refused, and the refusal says what to add and that it must be signed again.
func TestAVersionTwoDocumentIsRefusedAsCarryingNoEgressSection(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	// Control: the same values with an egress section still admit the platform.
	admits(t, f, loads(t, a, theDocument()))

	document := documentFor(versionTwoDocument, theMeasurement)
	refusesToLoad(t, document, a.sign(t, document), a.public)

	_, err := attest.LoadReferenceValueSet([]byte(document), a.sign(t, document), a.public)
	for _, want := range []string{"version 2", "egress", "unattested", "sign it again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so an operator reading it does not learn that the "+
				"fix is to add the egress section and re-sign the set: %v", want, err)
		}
	}
}

// TestAnEgressSectionThatIsNotAPolicyIsRefused covers every way the section can
// fail to say what it exists to say.
//
// The permissive case is the one worth reading twice. "unattested": true is
// well-formed, deliberate, and refused, because nothing in this build enforces
// it: a document claiming a capability no code implements is weaker than it
// reads, and the whole value of a policy digest is that what it names is what
// is enforced. Ticket 19 is what grows this section; until then a policy that
// permits is a policy that does not load.
func TestAnEgressSectionThatIsNotAPolicyIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, from, to string }{
		{"no egress section at all", `  "egress": {"version": 1, "unattested": false},` + "\n", ``},
		{"an egress section of another version", `"egress": {"version": 1,`, `"egress": {"version": 2,`},
		{"an egress section with no version", `"egress": {"version": 1, `, `"egress": {`},
		{"nothing said about unattested egress", `, "unattested": false}`, `}`},
		{"unattested egress permitted", `"unattested": false`, `"unattested": true`},
		{"a field the section does not define", `"unattested": false`, `"unattested": false, "allow_anything": true`},
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

// TestAPolicyDigestOnAValueSurvivesTheDocument is the allow-list entry made
// writable: a reference value is a measurement and a policy, and both have to
// come back out of the file the way they went in.
//
// It is checked for both vendors in one document, because policy_digest is the
// only field of this format that belongs to both, and a loader that read it out
// of the amd-sev-snp branch alone would leave the Intel half unconstrained
// while looking correct.
func TestAPolicyDigestOnAValueSurvivesTheDocument(t *testing.T) {
	a := newAuthor(t)
	document := strings.NewReplacer(
		`"vendor": "amd-sev-snp",`, `"vendor": "amd-sev-snp",
      "policy_digest": "`+theListedPolicy.String()+`",`,
		`"vendor": "intel-tdx",`, `"vendor": "intel-tdx",
      "policy_digest": "`+theOtherListedPolicy.String()+`",`,
	).Replace(theMixedDocument())

	set := loads(t, a, document)
	if len(set.Values) != 2 {
		t.Fatalf("the document holds two values; %d loaded", len(set.Values))
	}
	for i, want := range []attest.PolicyDigest{theListedPolicy, theOtherListedPolicy} {
		got := set.Values[i].PolicyDigest
		if got == nil {
			t.Errorf("value %d (%s) loaded unconstrained; the document lists %s", i, set.Values[i].Vendor, want)
			continue
		}
		if *got != want {
			t.Errorf("value %d (%s) lists policy %s; the document lists %s", i, set.Values[i].Vendor, got, want)
		}
	}
	if got := set.Unconstrained(); len(got) != 0 {
		t.Errorf("a set whose every value lists a policy reports %+v as unconstrained", got)
	}

	// It renders back out, and back in, unchanged. An author can therefore read
	// a set out of the loader, hand it to the signer, and get the same
	// allow-list rather than a weaker one.
	rendered, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("rendering the set: %v", err)
	}
	back := loads(t, a, string(rendered))
	if !reflect.DeepEqual(back.Values, set.Values) {
		t.Errorf("the policy digests did not survive a round trip:\n%s", rendered)
	}
	if strings.Count(string(rendered), "policy_digest") != 2 {
		t.Errorf("the rendered document names policy_digest %d times; want one per value:\n%s",
			strings.Count(string(rendered), "policy_digest"), rendered)
	}

	// And a value that lists none renders without the field rather than with an
	// empty one, because "" is a policy nobody has and absent is any policy.
	unconstrained, err := attest.MarshalReferenceValueSet(loads(t, a, theDocument()))
	if err != nil {
		t.Fatalf("rendering an unconstrained set: %v", err)
	}
	if strings.Contains(string(unconstrained), "policy_digest") {
		t.Errorf("a value listing no policy rendered a policy_digest field:\n%s", unconstrained)
	}
}

// TestAPolicyDigestOfTheWrongShapeIsRefused: a digest that is not 32 bytes of
// hexadecimal names no policy any peer can present.
//
// It would match nothing, which fails closed — and that is exactly why it is
// refused out loud instead. An allow-list entry that silently matches nothing
// is an entry that does not do its job while looking as though it does, and the
// author who typed it will be reading a refusal about a peer rather than about
// their file.
func TestAPolicyDigestOfTheWrongShapeIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, digest string }{
		{"too short", theListedPolicy.String()[:62]},
		{"too long", theListedPolicy.String() + "00"},
		{"empty", ""},
		{"not hexadecimal", strings.Repeat("g", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, `"vendor": "amd-sev-snp",`,
				`"vendor": "amd-sev-snp",
      "policy_digest": "`+tc.digest+`",`, 1)
			if modified == document {
				t.Fatal("the document has no vendor line; the fixture has drifted")
			}
			refusesToLoad(t, modified, a.sign(t, modified), a.public)
		})
	}
}

// theListedPolicy and theOtherListedPolicy are policy digests as a document
// lists them. What they are digests of does not matter here — the loader never
// computes one — only that they are 32 bytes and tell each other apart.
var (
	theListedPolicy      = attest.PolicyDigest{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8}
	theOtherListedPolicy = attest.PolicyDigest{0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8}
)

// TestALoadedSetCarriesTheDigestOfTheBytesItsAuthorSigned is what makes the
// digest nameable by two parties who never meet.
//
// It is SHA-256 over the signed bytes — the domain separation prefix and the
// document — and not over the file, so an operator running sha256sum on
// reference-values.json gets a different number. That is stated here as a test
// rather than only as a comment, because it is the mistake a harness makes
// once.
func TestALoadedSetCarriesTheDigestOfTheBytesItsAuthorSigned(t *testing.T) {
	a := newAuthor(t)
	document := theDocument()
	set := loads(t, a, document)

	want := attest.PolicyDigestOf([]byte(document))
	if set.PolicyDigest != want {
		t.Errorf("the loaded set names policy digest %s; the document's is %s", set.PolicyDigest, want)
	}
	if set.PolicyDigest == (attest.PolicyDigest{}) {
		t.Error("the loaded set names the zero digest, which is what a set nobody loaded carries")
	}
	if got := sha256.Sum256([]byte(document)); attest.PolicyDigest(got) == set.PolicyDigest {
		t.Error("the digest is over the file's bytes; it must be over the bytes the signature covers, " +
			"or a peer and a verifier computing it from different sides get different numbers")
	}

	// Two documents that differ anywhere have different digests, including two
	// that mean the same thing: the digest names bytes, not meaning.
	same := loads(t, a, nonCanonicalDocumentFor(theMeasurement))
	if same.PolicyDigest == set.PolicyDigest {
		t.Error("two documents with different bytes have the same policy digest")
	}
	if len(same.Values) != len(set.Values) {
		t.Fatal("the two documents do not hold the same set; the fixture has drifted")
	}

	// And the egress section survives loading, so what the digest names is
	// inspectable rather than only hashed.
	if set.Egress.Version != 1 || set.Egress.Unattested {
		t.Errorf("the loaded egress section is %+v; want version 1 refusing unattested egress", set.Egress)
	}
}

// nonCanonicalDocumentFor is nonCanonicalDocument with a measurement in it.
func nonCanonicalDocumentFor(measurement []byte) string {
	return documentFor(nonCanonicalDocument, measurement)
}

// TestAReferenceValueThatNamesNoVendorIsRefused: version 2 is not version 1
// with an optional field. A value that does not say whose evidence it admits is
// refused inside a version 2 document too, and so is one naming hardware no
// verifier here implements — which is refused at load rather than at the first
// peer, because a set nobody can enforce is a configuration mistake and not a
// verdict.
func TestAReferenceValueThatNamesNoVendorIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())
	document := theDocument()

	// Control.
	admits(t, f, loads(t, a, document))

	for _, tc := range []struct{ name, from, to string }{
		{"no vendor at all", `"vendor": "amd-sev-snp",` + "\n      ", ``},
		{"an empty vendor", `"vendor": "amd-sev-snp"`, `"vendor": ""`},
		{"hardware nobody here verifies", `"vendor": "amd-sev-snp"`, `"vendor": "example-corp-tee"`},
		{"a vendor spelled as something else", `"vendor": "amd-sev-snp"`, `"vendor": "sev-snp"`},
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

// TestATDXReferenceValueLoadsAndSurvivesARoundTrip is the control for the
// second vendor: the document an author writes for an Intel TDX peer loads, and
// every field arrives where it was written.
//
// Unlike every other set in this file, this one is inspected rather than wired
// to a verifier and shown to admit a platform. The TDX verifier and its fake
// platform are in other packages; what is under test here is the document, and
// whether these fields decide a verdict is that verifier's test to make.
func TestATDXReferenceValueLoadsAndSurvivesARoundTrip(t *testing.T) {
	a := newAuthor(t)
	set := loads(t, a, theTDXDocument())

	if len(set.Values) != 1 {
		t.Fatalf("the document holds one value; %d loaded", len(set.Values))
	}
	rv := set.Values[0]
	if rv.Vendor != attest.VendorIntelTDX {
		t.Fatalf("loaded as vendor %q; want %q", rv.Vendor, attest.VendorIntelTDX)
	}
	if rv.TDX == nil {
		t.Fatal("an intel-tdx value loaded with no TDX fields")
	}
	if len(rv.LaunchMeasurement) != 0 {
		t.Errorf("a TDX value loaded carrying an SEV-SNP launch measurement %x", rv.LaunchMeasurement)
	}
	// Each register where the document put it. A loader that filled RTMR0 from
	// the RTMR2 line would still produce a set that loads, and every check
	// built on it would then be checking the wrong register.
	for _, r := range []struct {
		name string
		got  [][]byte
		want [][]byte
	}{
		{"observed_mrtd", rv.TDX.ObservedMRTD, [][]byte{theMRTD}},
		{"observed_rtmr0", rv.TDX.ObservedRTMR0, [][]byte{theRTMR0}},
		{"observed_rtmr1", rv.TDX.ObservedRTMR1, [][]byte{firstBootRTMR1, laterBootRTMR1}},
		{"predicted_rtmr2", [][]byte{rv.TDX.PredictedRTMR2}, [][]byte{thePredictedRTMR2}},
	} {
		if !reflect.DeepEqual(r.got, r.want) {
			t.Errorf("%s loaded as %x; the document names %x", r.name, r.got, r.want)
		}
	}
	if want := (attest.TDXTCBFloor{Status: attest.TDXTCBUpToDate, EvaluationDataNumber: 20}); rv.TDX.MinimumTCB != want {
		t.Errorf("the loaded Intel TCB floor is %+v; want %+v", rv.TDX.MinimumTCB, want)
	}
	if rv.TDX.TDPolicy.AllowDebug {
		t.Error("the loaded TD attributes policy permits debugging; the document does not")
	}

	// A set that loaded renders back to a document that loads to the same set,
	// so an author can read one out of the loader and hand it to the signer.
	// The bytes are not expected to match: there is no canonical form, and the
	// signature covers what was delivered rather than what a renderer produces.
	// The policy digest is therefore not expected to match either — it names
	// bytes — and it is compared separately below.
	rendered, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("rendering a loaded TDX set: %v", err)
	}
	back := loads(t, a, string(rendered))
	if !reflect.DeepEqual(back.Values, set.Values) || back.Egress != set.Egress {
		t.Errorf("the set does not survive a round trip through the document:\n got %+v\nwant %+v\n%s",
			back.Values[0].TDX, set.Values[0].TDX, rendered)
	}
	if back.PolicyDigest == set.PolicyDigest {
		t.Error("the re-rendered document has the same policy digest as the one that was delivered; " +
			"the digest names bytes, and these are different bytes")
	}
}

// TestATDAttributesPolicyLeftOutPermitsNothing is the asymmetry the format
// keeps in both vendors: a floor left out is refused, a permission left out is
// the fail-closed answer. An absent field may make a value stricter than its
// author intended, never weaker.
func TestATDAttributesPolicyLeftOutPermitsNothing(t *testing.T) {
	a := newAuthor(t)
	document := strings.Replace(theTDXDocument(),
		`      "td_attributes_policy": {"allow_debug": false},`+"\n", ``, 1)
	if document == theTDXDocument() {
		t.Fatal("the fixture has drifted; nothing was removed")
	}
	set := loads(t, a, document)
	if set.Values[0].TDX.TDPolicy.AllowDebug {
		t.Error("a value with no td_attributes_policy permits debugging; " +
			"an omitted permission must permit nothing")
	}
}

// TestEachRequiredTDXFieldIsLoadBearing is
// TestEachNamedTCBComponentIsLoadBearing's sibling for the other vendor.
//
// Every field a TDX value must name is cut out, one at a time, and the document
// must not load without it. Each default a loader could reach for instead is a
// permission it would be granting on the author's behalf: no observed_rtmr0 is
// a register not checked, no predicted_rtmr2 is every image the provider boots,
// no status is a platform Intel has already called out of date, and no
// evaluation number is a TCB info from before the recovery that named the
// vulnerability.
func TestEachRequiredTDXFieldIsLoadBearing(t *testing.T) {
	a := newAuthor(t)

	const (
		head     = `{"format": "` + documentFormat + `", "version": 3, ` + egressSection + `, "reference_values": [{"vendor": "intel-tdx", `
		tail     = `}]}`
		mrtd     = `"observed_mrtd": ["$MRTD"]`
		rtmr0    = `"observed_rtmr0": ["$RTMR0"]`
		rtmr1    = `"observed_rtmr1": ["$RTMR1A", "$RTMR1B"]`
		rtmr2    = `"predicted_rtmr2": "$RTMR2"`
		tdPolicy = `"td_attributes_policy": {"allow_debug": false}`
		floor    = `"minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}`
	)
	complete := head + strings.Join([]string{mrtd, rtmr0, rtmr1, rtmr2, tdPolicy, floor}, ", ") + tail

	// Control: complete, this document loads. Every variant below is this
	// document minus one thing.
	loads(t, a, withRegisters(complete))

	for _, tc := range []struct{ name, document string }{
		{"no observed MRTD", head + strings.Join([]string{rtmr0, rtmr1, rtmr2, tdPolicy, floor}, ", ") + tail},
		{"no observed RTMR0", head + strings.Join([]string{mrtd, rtmr1, rtmr2, tdPolicy, floor}, ", ") + tail},
		{"no observed RTMR1", head + strings.Join([]string{mrtd, rtmr0, rtmr2, tdPolicy, floor}, ", ") + tail},
		{"no predicted RTMR2", head + strings.Join([]string{mrtd, rtmr0, rtmr1, tdPolicy, floor}, ", ") + tail},
		{"no TCB floor", head + strings.Join([]string{mrtd, rtmr0, rtmr1, rtmr2, tdPolicy}, ", ") + tail},
		{
			"a TCB floor naming no status",
			head + strings.Join([]string{mrtd, rtmr0, rtmr1, rtmr2, tdPolicy,
				`"minimum_tcb": {"tcb_evaluation_data_number": 20}`}, ", ") + tail,
		},
		{
			"a TCB floor naming no evaluation number",
			head + strings.Join([]string{mrtd, rtmr0, rtmr1, rtmr2, tdPolicy,
				`"minimum_tcb": {"status": "UpToDate"}`}, ", ") + tail,
		},
		{"an empty predicted RTMR2", strings.Replace(complete, rtmr2, `"predicted_rtmr2": ""`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.document == complete {
				t.Fatal("the variant is the control document; the fixture has drifted")
			}
			document := withRegisters(tc.document)
			refusesToLoad(t, document, a.sign(t, document), a.public)
		})
	}
}

// TestAnObservedRegisterListThatChecksNothingIsRefused: the lists say "any of
// these", never "ignore". An empty list, or a list holding an empty value, is a
// register the author has stopped checking without saying so — and a TDX peer
// is admitted on its registers, so a list that matches anything is the same
// mistake as a reference value naming no launch measurement.
func TestAnObservedRegisterListThatChecksNothingIsRefused(t *testing.T) {
	a := newAuthor(t)

	// Control.
	loads(t, a, theTDXDocument())

	for _, tc := range []struct{ name, from, to string }{
		{"an empty MRTD list", `"observed_mrtd": ["$MRTD"]`, `"observed_mrtd": []`},
		{"an empty RTMR0 list", `"observed_rtmr0": ["$RTMR0"]`, `"observed_rtmr0": []`},
		{"an empty RTMR1 list", `"observed_rtmr1": ["$RTMR1A", "$RTMR1B"]`, `"observed_rtmr1": []`},
		{"an empty value in a list", `"observed_mrtd": ["$MRTD"]`, `"observed_mrtd": [""]`},
		{"a value that is not hexadecimal", `"observed_rtmr0": ["$RTMR0"]`, `"observed_rtmr0": ["not a register"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(tdxValueDocument, tc.from, tc.to, 1)
			if modified == tdxValueDocument {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			document := withRegisters(modified)
			refusesToLoad(t, document, a.sign(t, document), a.public)
		})
	}
}

// TestATCBStatusIntelDoesNotVouchForIsRefused: a floor is one of the two
// statuses that mean the platform is at Intel's current level. Everything else
// Intel can say — ConfigurationNeeded, OutOfDate, Revoked and their
// combinations — is below either floor, and a document naming one as its floor
// is refused rather than treated as a floor of "whatever Intel says".
func TestATCBStatusIntelDoesNotVouchForIsRefused(t *testing.T) {
	a := newAuthor(t)

	// Control: both admissible floors load.
	for _, status := range []string{"UpToDate", "SWHardeningNeeded"} {
		document := withRegisters(strings.Replace(tdxValueDocument, `"status": "UpToDate"`,
			`"status": "`+status+`"`, 1))
		loads(t, a, document)
	}

	for _, status := range []string{"OutOfDate", "Revoked", "ConfigurationNeeded", "uptodate", ""} {
		t.Run("a floor of "+status, func(t *testing.T) {
			document := withRegisters(strings.Replace(tdxValueDocument, `"status": "UpToDate"`,
				`"status": "`+status+`"`, 1))
			refusesToLoad(t, document, a.sign(t, document), a.public)
		})
	}
}

// TestAValueCarryingTheOtherVendorsFieldsIsRefused closes the hole the vendor
// tag would otherwise open.
//
// An entry naming one vendor and carrying the other's field is not an entry
// with a stray key: its author was thinking about a constraint this value
// cannot express, and a loader that enforced only the half it recognised would
// admit more than they wrote down. That is the same failure as ignoring an
// unknown field, arrived at from a direction that looks like a valid document.
func TestAValueCarryingTheOtherVendorsFieldsIsRefused(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	// Controls: each vendor's own document, unmixed.
	admits(t, f, loads(t, a, theDocument()))
	loads(t, a, theTDXDocument())

	for _, tc := range []struct{ name, document string }{
		{
			"an SEV-SNP value naming a predicted RTMR2",
			strings.Replace(theDocument(), `"launch_measurement": "`,
				`"predicted_rtmr2": "`+hex.EncodeToString(thePredictedRTMR2)+`",
      "launch_measurement": "`, 1),
		},
		{
			"an SEV-SNP value naming an observed register",
			strings.Replace(theDocument(), `"launch_measurement": "`,
				`"observed_rtmr1": ["`+hex.EncodeToString(firstBootRTMR1)+`"],
      "launch_measurement": "`, 1),
		},
		{
			"an SEV-SNP value naming a TD attributes policy",
			strings.Replace(theDocument(), `"launch_measurement": "`,
				`"td_attributes_policy": {"allow_debug": true},
      "launch_measurement": "`, 1),
		},
		{
			"a TDX value naming a launch measurement",
			strings.Replace(theTDXDocument(), `"observed_mrtd": [`,
				`"launch_measurement": "`+hex.EncodeToString(theMeasurement)+`",
      "observed_mrtd": [`, 1),
		},
		{
			"a TDX value naming a guest policy",
			strings.Replace(theTDXDocument(), `"observed_mrtd": [`,
				`"guest_policy": {"allow_debug": true},
      "observed_mrtd": [`, 1),
		},
		{
			"a TDX value carrying an SEV-SNP TCB floor",
			strings.Replace(theTDXDocument(),
				`"minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}`,
				`"minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72}`, 1),
		},
		{
			"an SEV-SNP value carrying an Intel TCB floor",
			strings.Replace(theDocument(),
				`"minimum_tcb": {
        "bootloader": 9,
        "tee": 0,
        "snp": 23,
        "microcode": 72
      }`,
				`"minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}`, 1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.document == theDocument() || tc.document == theTDXDocument() {
				t.Fatal("the variant is a control document; the fixture has drifted")
			}
			refusesToLoad(t, tc.document, a.sign(t, tc.document), a.public)
		})
	}
}

// TestOneFileHoldsBothVendors is what the vendor tag is for. A peer group can
// span hardware, so a set holds an SEV-SNP value and an Intel TDX value at
// once, and each verifier reads the values that are its own. A format that
// carried the vendor once at the top of the document, or a deployment that
// shipped one file per vendor, would make the mixed group the special case.
func TestOneFileHoldsBothVendors(t *testing.T) {
	a := newAuthor(t)
	f := newFixture(t, defaultConfig())

	set := loads(t, a, theMixedDocument())
	if len(set.Values) != 2 {
		t.Fatalf("the mixed document holds two values; %d loaded", len(set.Values))
	}
	if got := []attest.Vendor{set.Values[0].Vendor, set.Values[1].Vendor}; got[0] != attest.VendorAMDSEVSNP || got[1] != attest.VendorIntelTDX {
		t.Fatalf("the values loaded as %v; want the SEV-SNP one and then the TDX one", got)
	}
	if !bytes.Equal(set.Values[0].LaunchMeasurement, theMeasurement) {
		t.Errorf("the SEV-SNP value names %x; the document names %x",
			set.Values[0].LaunchMeasurement, theMeasurement)
	}
	if set.Values[0].TDX != nil {
		t.Error("the SEV-SNP value loaded carrying TDX fields")
	}
	if set.Values[1].TDX == nil || !bytes.Equal(set.Values[1].TDX.PredictedRTMR2, thePredictedRTMR2) {
		t.Errorf("the TDX value did not load its predicted RTMR2")
	}

	// It is a trust root a Verification will hold: New copies it and refuses at
	// startup anything that could not mean what its author intended, and both
	// vendors' values have to survive that.
	if _, err := attest.New(verifierTrusting(t, f.platform), set); err != nil {
		t.Fatalf("a mixed set was refused at construction: %v", err)
	}

	// And it renders back to a document that loads to the same set.
	rendered, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		t.Fatalf("rendering a mixed set: %v", err)
	}
	back := loads(t, a, string(rendered))
	if !reflect.DeepEqual(back.Values, set.Values) || back.Egress != set.Egress {
		t.Errorf("a mixed set does not survive a round trip through the document:\n%s", rendered)
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
