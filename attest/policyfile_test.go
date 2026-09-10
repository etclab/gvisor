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

// Tests for the signed policy: its on-disk format, its signature, its digest
// and its loader.
//
// The documents are written out as literals for the reason refvalsfile_test.go
// gives about reference value sets: a policy is a file a person writes and
// reviews, and a fixture rendered by the marshaller would prove only that the
// loader can read its own output.
//
// What the policy is *for* — a peer presenting its digest, and a dialer
// enforcing forward_to — is tested where those happen, in verification_test.go
// and in package tunneld. What is tested here is that the document says what
// its author wrote and refuses everything else.
package attest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
)

// policyFormat is the format string spelled out rather than taken from
// [attest.PolicyFormat], for the reason documentFormat is: a document already
// signed and shipped does not change when a Go identifier is renamed.
const policyFormat = "gvisor.dev/gvisor/attest/policy"

// aPolicyDocument is a policy as an author writes it: unattested egress
// refused, and one image this sandbox will dial.
//
// Read it. There are no digests in it, and that absence is the whole of ticket
// 19: a policy that named policies could not be pinned in both directions.
const aPolicyDocument = `{
  "format": "gvisor.dev/gvisor/attest/policy",
  "version": 1,
  "egress": {"version": 1, "unattested": false},
  "forward_to": ["$MEASUREMENT"]
}
`

// aSilentPolicyDocument is the same policy for a sandbox that answers and never
// calls. The empty list is written out; a policy that left the field out would
// not load, because an author who said nothing has not said "nobody".
const aSilentPolicyDocument = `{
  "format": "gvisor.dev/gvisor/attest/policy",
  "version": 1,
  "egress": {"version": 1, "unattested": false},
  "forward_to": []
}
`

// signPolicy authorises a policy document, returning the contents of the file
// that belongs beside it.
func (a author) signPolicy(t *testing.T, document string) []byte {
	t.Helper()
	signature, err := attest.SignPolicy([]byte(document), a.private)
	if err != nil {
		t.Fatalf("signing a policy: %v", err)
	}
	return signature
}

// loadsPolicy asserts that a document and signature load, and returns the
// policy.
func loadsPolicy(t *testing.T, a author, document string) attest.Policy {
	t.Helper()
	policy, err := attest.LoadPolicy([]byte(document), a.signPolicy(t, document), a.public)
	if err != nil {
		t.Fatalf("a well-formed signed policy was refused: %v", err)
	}
	return policy
}

// refusesToLoadPolicy asserts that a document and signature are refused, and
// that the refusal is the one outcome this package offers other than a loaded
// policy.
func refusesToLoadPolicy(t *testing.T, document string, signature []byte, public []byte) {
	t.Helper()
	policy, err := attest.LoadPolicy([]byte(document), signature, public)
	if err == nil {
		t.Fatalf("the policy loaded as %+v; want a refusal", policy)
	}
	if !errors.Is(err, attest.ErrPolicyRefused) {
		t.Errorf("refusal does not match attest.ErrPolicyRefused: %v", err)
	}
	if len(policy.ForwardTo) != 0 || policy.Digest != (attest.PolicyDigest{}) {
		t.Errorf("a refused load returned %+v; want the zero policy", policy)
	}
}

// thePolicyDocument is the one-image policy naming theMeasurement — the good
// document every refusal below is paired against.
func thePolicyDocument() string { return documentFor(aPolicyDocument, theMeasurement) }

// TestASignedPolicyLoadsAndSaysWhatItsAuthorWrote is the control the whole file
// rests on.
func TestASignedPolicyLoadsAndSaysWhatItsAuthorWrote(t *testing.T) {
	a := newAuthor(t)
	policy := loadsPolicy(t, a, thePolicyDocument())

	if policy.Version != attest.PolicyVersion {
		t.Errorf("the loaded policy is version %d; want %d", policy.Version, attest.PolicyVersion)
	}
	if policy.Egress.Version != 1 || policy.Egress.Unattested {
		t.Errorf("the loaded egress section is %+v; want version 1 refusing unattested egress", policy.Egress)
	}
	if want := [][]byte{theMeasurement}; !reflect.DeepEqual(policy.ForwardTo, want) {
		t.Errorf("the policy forwards to %x; the document names %x", policy.ForwardTo, want)
	}
	if !policy.Forwards(theMeasurement) {
		t.Error("the policy does not forward to the image its own document names")
	}
	if policy.Forwards(otherMeasurement) {
		t.Error("the policy forwards to an image its document does not name")
	}
}

// TestAPolicyForwardingToNobodyLoadsAndForwardsToNobody: the empty list is a
// deployment, not a mistake. A sandbox that answers and never calls says so,
// and what it says is enforced rather than read as "anything".
func TestAPolicyForwardingToNobodyLoadsAndForwardsToNobody(t *testing.T) {
	a := newAuthor(t)
	policy := loadsPolicy(t, a, aSilentPolicyDocument)

	if len(policy.ForwardTo) != 0 {
		t.Errorf("the policy forwards to %x; the document names nobody", policy.ForwardTo)
	}
	for _, m := range [][]byte{theMeasurement, otherMeasurement, nil} {
		if policy.Forwards(m) {
			t.Errorf("a policy listing nothing forwards to %x; an empty list is nobody, not anybody", m)
		}
	}
}

// TestAPolicyThatDoesNotSayWhomItForwardsToIsRefused is the distinction between
// absent and empty, made a test.
//
// "forward_to": [] is an author saying this sandbox dials nobody. No field at
// all is an author who did not consider the question, and a loader that read
// the second as the first would be deciding policy on their behalf — in the
// safe direction today, and in whichever direction the field's default happened
// to be tomorrow.
func TestAPolicyThatDoesNotSayWhomItForwardsToIsRefused(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()

	// Control.
	loadsPolicy(t, a, document)

	for _, tc := range []struct{ name, from, to string }{
		{"no forward_to at all", `,
  "forward_to": ["` + hex.EncodeToString(theMeasurement) + `"]`, ``},
		{"forward_to is null", `["` + hex.EncodeToString(theMeasurement) + `"]`, `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, tc.from, tc.to, 1)
			if modified == document {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			refusesToLoadPolicy(t, modified, a.signPolicy(t, modified), a.public)
		})
	}

	// And the refusal says what to write instead.
	modified := strings.Replace(document, `,
  "forward_to": ["`+hex.EncodeToString(theMeasurement)+`"]`, ``, 1)
	_, err := attest.LoadPolicy([]byte(modified), a.signPolicy(t, modified), a.public)
	if !strings.Contains(err.Error(), `"forward_to": []`) {
		t.Errorf("the refusal does not say how to write a sandbox that dials nobody: %v", err)
	}
}

// TestAForwardToEntryThatNamesNoImageIsRefused: a list is read once by a
// reviewer, so an entry that is not a measurement is a mistake said out loud
// rather than an entry that matches nothing.
//
// A width is deliberately not among the refusals. How wide a launch measurement
// is belongs to the hardware vendor, and one of the wrong width matches no peer,
// which fails closed — the same omission the reference value loader makes.
func TestAForwardToEntryThatNamesNoImageIsRefused(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()
	measurement := hex.EncodeToString(theMeasurement)

	// Control.
	loadsPolicy(t, a, document)

	for _, tc := range []struct{ name, list string }{
		{"not hexadecimal", `["` + strings.Repeat("g", 96) + `"]`},
		{"an empty entry", `["", "` + measurement + `"]`},
		{"the same image twice", `["` + measurement + `", "` + measurement + `"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, `["`+measurement+`"]`, tc.list, 1)
			if modified == document {
				t.Fatal("the document has no forward_to list; the fixture has drifted")
			}
			refusesToLoadPolicy(t, modified, a.signPolicy(t, modified), a.public)
		})
	}

	// A measurement of another width loads, because the loader does not judge
	// one. It simply names an image no peer here is running.
	narrow := strings.Replace(document, `["`+measurement+`"]`, `["aabbcc"]`, 1)
	policy := loadsPolicy(t, a, narrow)
	if policy.Forwards(theMeasurement) {
		t.Error("a policy naming a measurement of the wrong width forwards to this image anyway")
	}
}

// TestAPolicyOfAnUnknownVersionIsRefused: a reader that skips what it does not
// understand enforces the part of a policy that already existed while a peer's
// digest vouches for the whole of it. That is the failure ADR-0002 describes for
// the binding context, in the document the binding context now carries.
func TestAPolicyOfAnUnknownVersionIsRefused(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()

	// Control.
	loadsPolicy(t, a, document)

	for _, tc := range []struct{ name, from, to string }{
		{"a later version", `"version": 1,
  "egress"`, `"version": 2,
  "egress"`},
		{"a version from before this one", `"version": 1,
  "egress"`, `"version": 0,
  "egress"`},
		{"no version at all", `  "version": 1,
`, ``},
		{"another format", `"format": "` + policyFormat + `"`, `"format": "example.com/some-other-file"`},
		{"no format", `"format": "` + policyFormat + `",
`, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(document, tc.from, tc.to, 1)
			if modified == document {
				t.Fatalf("the document does not contain %q; the fixture has drifted", tc.from)
			}
			refusesToLoadPolicy(t, modified, a.signPolicy(t, modified), a.public)
		})
	}

	// The version refusal says what to do about it, because the operator with
	// an old document has a build to redo rather than a file to debug.
	modified := strings.Replace(document, `"version": 1,
  "egress"`, `"version": 2,
  "egress"`, 1)
	_, err := attest.LoadPolicy([]byte(modified), a.signPolicy(t, modified), a.public)
	for _, want := range []string{"version 2", "re-emit", "sign it again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestAReferenceValueSetPresentedAsAPolicyIsRefusedByName: the two documents
// live beside each other on one device under two names, and swapping them is
// the provisioning mistake this format should say something useful about.
func TestAReferenceValueSetPresentedAsAPolicyIsRefusedByName(t *testing.T) {
	a := newAuthor(t)
	set := theDocument()

	// Signed as a policy, so the refusal is the document's format and not a
	// signature that did not hold.
	refusesToLoadPolicy(t, set, a.signPolicy(t, set), a.public)

	_, err := attest.LoadPolicy([]byte(set), a.signPolicy(t, set), a.public)
	if !strings.Contains(err.Error(), "reference value set") {
		t.Errorf("the refusal does not say the document is a set: %v", err)
	}
}

// TestAnEgressSectionThatIsNotAPolicyIsRefused covers every way the section can
// fail to say what it exists to say. It was the reference value set's section
// until ticket 19 and the checks came with it unchanged.
//
// The permissive case is the one worth reading twice. "unattested": true is
// well-formed, deliberate, and refused, because nothing in this build enforces
// it: a document claiming a capability no code implements is weaker than it
// reads, and the whole value of a policy digest is that what it names is what is
// enforced.
func TestAnEgressSectionThatIsNotAPolicyIsRefused(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()

	// Control.
	loadsPolicy(t, a, document)

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
			refusesToLoadPolicy(t, modified, a.signPolicy(t, modified), a.public)
		})
	}
}

// TestAPolicyIsAsStrictlyParsedAsASet: the strictness of the reference value
// loader is not a property of that file, it is a property of every document this
// author's key signs. A field nobody recognises, a field named twice and bytes
// after the document are each refused here too.
func TestAPolicyIsAsStrictlyParsedAsASet(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()

	// Control.
	loadsPolicy(t, a, document)

	for _, tc := range []struct{ name, modified string }{
		{"an unknown field", strings.Replace(document, `"version": 1,`, `"version": 1,
  "allow_anything": true,`, 1)},
		{"a field named twice", strings.Replace(document, `"version": 1,`, `"version": 1,
  "version": 1,`, 1)},
		{"a field name outside the alphabet", strings.Replace(document, `"forward_to"`, `"forwardTo"`, 1)},
		{"bytes after the document", document + "null\n"},
		{"a second policy after it", document + document},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.modified == document {
				t.Fatal("the modification did not change the document; the fixture has drifted")
			}
			refusesToLoadPolicy(t, tc.modified, a.signPolicy(t, tc.modified), a.public)
		})
	}
}

// TestALoadedPolicyCarriesTheDigestOfTheBytesItsAuthorSigned is what makes the
// digest nameable by two parties who never meet.
//
// It is SHA-256 over the signed bytes — the policy's domain separation prefix
// and the document — and not over the file, so an operator running sha256sum on
// policy.json gets a different number. That is stated here as a test rather than
// only as a comment, because it is the mistake a harness makes once.
func TestALoadedPolicyCarriesTheDigestOfTheBytesItsAuthorSigned(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()
	policy := loadsPolicy(t, a, document)

	want := attest.PolicyDigestOf([]byte(document))
	if policy.Digest != want {
		t.Errorf("the loaded policy names digest %s; the document's is %s", policy.Digest, want)
	}
	if policy.Digest == (attest.PolicyDigest{}) {
		t.Error("the loaded policy names the zero digest, which is what a policy nobody loaded carries")
	}
	if got := sha256.Sum256([]byte(document)); attest.PolicyDigest(got) == policy.Digest {
		t.Error("the digest is over the file's bytes; it must be over the bytes the signature covers, " +
			"or a peer and a verifier computing it from different sides get different numbers")
	}

	// Two documents that differ anywhere have different digests, including two
	// that mean the same thing: the digest names bytes, not meaning.
	same := loadsPolicy(t, a, strings.Replace(document, "\n  ", "\n    ", 1))
	if same.Digest == policy.Digest {
		t.Error("two documents with different bytes have the same policy digest")
	}
	if !reflect.DeepEqual(same.ForwardTo, policy.ForwardTo) {
		t.Fatal("the two documents do not say the same thing; the fixture has drifted")
	}
}

// TestAPolicyDigestIsNotASetDigestOverTheSameBytes is the domain separation
// stated as a number rather than as a comment.
//
// The two prefixes exist so that one author key signing both documents cannot
// have either signature replayed as the other's. The digest inherits the
// property for free, and it matters: a harness that computed a policy digest
// with the set's prefix would produce a number every peer refuses.
func TestAPolicyDigestIsNotASetDigestOverTheSameBytes(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()

	// A signature over the policy does not verify as one over a set, and the
	// reverse.
	refusesToLoadPolicy(t, document, a.sign(t, document), a.public)
	if _, err := attest.LoadReferenceValueSet([]byte(theDocument()), a.signPolicy(t, theDocument()), a.public); err == nil {
		t.Error("a policy signature verified over a reference value set")
	}

	// And the digest of the same bytes differs between the two domains, so no
	// tool can arrive at a policy digest by hashing under the wrong prefix.
	if attest.PolicyDigestOf([]byte(document)) == sha256.Sum256([]byte("gvisor.dev/gvisor/attest reference-value-set signature v1\x00"+document)) {
		t.Error("the policy digest is the reference value set's digest over the same bytes; " +
			"the two domains are not separated")
	}
}

// TestAPolicyRendersBackToADocumentThatLoads: an author can build a policy in
// code, render it, sign it and ship it, and the loader gets what they built.
func TestAPolicyRendersBackToADocumentThatLoads(t *testing.T) {
	a := newAuthor(t)
	built := attest.Policy{ForwardTo: [][]byte{theMeasurement, otherMeasurement}}

	rendered, err := attest.MarshalPolicy(built)
	if err != nil {
		t.Fatalf("rendering a policy: %v", err)
	}
	loaded := loadsPolicy(t, a, string(rendered))
	if !reflect.DeepEqual(loaded.ForwardTo, built.ForwardTo) {
		t.Errorf("the rendered policy forwards to %x; it was built forwarding to %x\n%s",
			loaded.ForwardTo, built.ForwardTo, rendered)
	}
	if loaded.Egress.Version != 1 || loaded.Egress.Unattested {
		t.Errorf("a policy built with a zero egress section rendered as %+v", loaded.Egress)
	}
	if loaded.Digest != attest.PolicyDigestOf(rendered) {
		t.Error("the loaded policy's digest is not the digest of the bytes it was loaded from")
	}

	// A policy this package would refuse to load is refused at rendering
	// instead, so "sign what you wrote, ship what you signed" cannot produce a
	// document that does not load.
	for _, tc := range []struct {
		name   string
		policy attest.Policy
	}{
		{"unattested egress permitted", attest.Policy{Egress: attest.Egress{Unattested: true}}},
		{"an egress section of another version", attest.Policy{Egress: attest.Egress{Version: 2}}},
		{"a version this package does not write", attest.Policy{Version: 2}},
		{"an empty measurement", attest.Policy{ForwardTo: [][]byte{{}}}},
		{"the same image twice", attest.Policy{ForwardTo: [][]byte{theMeasurement, theMeasurement}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if doc, err := attest.MarshalPolicy(tc.policy); err == nil {
				t.Errorf("a policy that would not load rendered as:\n%s", doc)
			}
		})
	}

	// An empty forward_to renders as a list rather than as null, because absent
	// does not load and "dials nobody" has to be writable.
	silent, err := attest.MarshalPolicy(attest.Policy{})
	if err != nil {
		t.Fatalf("rendering a policy that forwards to nobody: %v", err)
	}
	if !strings.Contains(string(silent), `"forward_to": []`) {
		t.Errorf("a policy forwarding to nobody rendered as:\n%s", silent)
	}
	loadsPolicy(t, a, string(silent))
}

// TestAPolicyOnDiskLoadsFromItsDocumentAndSignature, and a refused one is never
// treated as absent.
//
// The suffix is the reference value set's, and the loader finds the signature
// beside the document rather than being told where it is. A missing document
// and a missing signature are refusals like any other: nothing here matches
// fs.ErrNotExist, so no caller can write the branch that treats "there is no
// policy" as permission to run without one.
func TestAPolicyOnDiskLoadsFromItsDocumentAndSignature(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeFile(t, path, []byte(document))
	writeFile(t, path+attest.SignatureFileSuffix, a.signPolicy(t, document))

	policy, err := attest.LoadPolicyFile(path, a.public)
	if err != nil {
		t.Fatalf("a policy on disk was refused: %v", err)
	}
	if policy.Digest != attest.PolicyDigestOf([]byte(document)) {
		t.Error("the policy loaded off disk names a different digest from the document on it")
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"a document that is not there", filepath.Join(dir, "absent.json")},
		{"a document with no signature beside it", func() string {
			p := filepath.Join(dir, "unsigned.json")
			writeFile(t, p, []byte(document))
			return p
		}()},
		{"a signature by another key", func() string {
			p := filepath.Join(dir, "stranger.json")
			writeFile(t, p, []byte(document))
			writeFile(t, p+attest.SignatureFileSuffix, newAuthor(t).signPolicy(t, document))
			return p
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := attest.LoadPolicyFile(tc.path, a.public)
			if err == nil {
				t.Fatalf("the policy loaded as %+v; want a refusal", policy)
			}
			if !errors.Is(err, attest.ErrPolicyRefused) {
				t.Errorf("refusal does not match attest.ErrPolicyRefused: %v", err)
			}
			if errors.Is(err, os.ErrNotExist) {
				t.Error("the refusal matches fs.ErrNotExist, so a caller can tell a missing policy " +
					"from an invalid one and be tempted to carry on without either")
			}
		})
	}
}

// TestAPolicySignatureOfTheWrongShapeIsRefused: the signature file is parsed
// before anything else, and an absent one is its own sentence because it is a
// provisioning mistake with a different fix from a signature that did not hold.
func TestAPolicySignatureOfTheWrongShapeIsRefused(t *testing.T) {
	a := newAuthor(t)
	document := thePolicyDocument()
	good := a.signPolicy(t, document)

	// Control.
	loadsPolicy(t, a, document)

	for _, tc := range []struct {
		name      string
		signature []byte
	}{
		{"absent", nil},
		{"whitespace only", []byte("  \n")},
		{"not hexadecimal", []byte(strings.Repeat("z", 128))},
		{"too short", good[:len(good)-3]},
		{"one digit changed", flipHexDigit(good)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusesToLoadPolicy(t, document, tc.signature, a.public)
		})
	}
}
