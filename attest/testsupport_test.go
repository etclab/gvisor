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

// Tests for the verification core.
//
// Every test drives [attest.Verification.Verify] — the module's public
// verification entry point, and the same one a tunneld will call in ticket 09.
// Nothing here reaches inside the verify package, constructs a report by hand,
// or asserts on how a verdict was reached; a test that did would couple to the
// shape ADR-0003 says a dependency will impose, and those internals are
// supposed to stay free to change.
//
// The platform is fake and the certificate chain is test-signed, but the
// verification path is the real one: real report parsing, real X.509 chain
// validation, real TCB and policy predicates. No confidential VM and no network
// is involved — the verifier disables certificate fetching and is handed a
// getter that refuses, so an accepted verdict here is also evidence that
// nothing was fetched.
//
// Every refusal is paired with a control on the same wiring showing that
// legitimate evidence is still accepted. A refusal test that would also pass
// with verification entirely broken is not evidence.
package attest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/verify"
)

// chainCreatedAt is when the fake platform's certificate chain is created, and
// whenChainsAreValid is an instant at which it is valid. Both are fixed so that
// a test's outcome does not depend on the day it runs.
var (
	chainCreatedAt     = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	whenChainsAreValid = chainCreatedAt.Add(30 * 24 * time.Hour)
)

// theMeasurement is the launch measurement the fake platform attests in these
// tests, standing in for the one ticket 07 will compute offline from the image
// build inputs.
var theMeasurement = bytes.Repeat([]byte{0x11}, 48)

// otherMeasurement is a different image: same everything else, different bytes.
var otherMeasurement = bytes.Repeat([]byte{0x22}, 48)

// platformTCB is the TCB the fake platform reports, and floorTCB is a floor it
// meets. aboveTCB is a floor it does not.
var (
	platformTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	floorTCB    = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	aboveTCB    = attest.TCB{Bootloader: 9, TEE: 0, SNP: 24, Microcode: 72}
)

// launchedPolicy is what the fake platform launched with: SMT allowed, no
// debugging. permittedPolicy is a reference value that permits it.
var (
	launchedPolicy  = snpfake.Policy{SMT: true}
	permittedPolicy = attest.GuestPolicy{AllowSMT: true}
)

// fixture is one fake platform and one verifier that trusts it, wired together
// the way a tunneld will wire the real ones.
type fixture struct {
	platform *snpfake.Platform
	binding  attest.Binding
	evidence attest.Evidence
}

// thePolicy is the policy digest the fixture's platform presents: what a
// sandbox that loaded its own signed reference value set would fold into its
// evidence under binding context v2. otherPolicy is a different sandbox's.
//
// They are arbitrary bytes rather than digests of real documents, because what
// a policy digest is a digest *of* is settled where the document is, in
// refvalsfile_test.go. Neither is the zero digest, so a test that asserted a
// digest travelled cannot pass on a field nobody set.
var (
	thePolicy   = attest.PolicyDigest{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	otherPolicy = attest.PolicyDigest{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8}
)

// newFixture builds a fake platform, generates a key the way a tunneld does at
// startup, and acquires evidence bound to it and to [thePolicy].
func newFixture(t *testing.T, cfg snpfake.Config) *fixture {
	return newFixturePresenting(t, cfg, thePolicy)
}

// newFixturePresenting is [newFixture] with the policy the platform binds its
// evidence to stated rather than assumed. The binding is v2 throughout: v1 is
// the version this verifier no longer admits, and a fixture speaking it would
// be refused before any of these tests reached what they are about.
func newFixturePresenting(t *testing.T, cfg snpfake.Config, policy attest.PolicyDigest) *fixture {
	t.Helper()
	platform, err := snpfake.New(cfg)
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	binding := attest.Binding{PublicKey: pub, Context: attest.BindingContextV2, PolicyDigest: policy}
	evidence, err := platform.Acquire(context.Background(), binding.CallerSuppliedBytes())
	if err != nil {
		t.Fatalf("acquiring evidence: %v", err)
	}
	return &fixture{platform: platform, binding: binding, evidence: evidence}
}

// defaultConfig is a platform that a defaultSet reference value admits.
func defaultConfig() snpfake.Config {
	return snpfake.Config{
		LaunchMeasurement: theMeasurement,
		TCB:               platformTCB,
		Policy:            launchedPolicy,
		Now:               chainCreatedAt,
	}
}

// defaultSet is a reference value set that admits defaultConfig's platform.
func defaultSet() attest.ReferenceValueSet {
	return attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: theMeasurement,
		MinimumTCB:        floorTCB,
		GuestPolicy:       permittedPolicy,
	}}}
}

// verifierTrusting returns a verifier configured with the fake platform's root,
// as a tunneld would be configured with the root provisioned onto its config
// device.
func verifierTrusting(t *testing.T, p *snpfake.Platform) attest.Verifier {
	t.Helper()
	v, err := verify.New(verify.Options{
		VendorRootPEM: p.VendorRootPEM(),
		ProductLine:   p.ProductLine(),
		Now:           whenChainsAreValid,
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
}

// verification wires a verifier that trusts f's platform to a reference value
// set.
func verification(t *testing.T, f *fixture, set attest.ReferenceValueSet) *attest.Verification {
	t.Helper()
	v, err := attest.New(verifierTrusting(t, f.platform), set)
	if err != nil {
		t.Fatalf("attest.New: %v", err)
	}
	return v
}

// accepts is the control every refusal test is paired with: on this wiring,
// legitimate evidence is still accepted.
func accepts(t *testing.T, v *attest.Verification, f *fixture) attest.Attested {
	t.Helper()
	attested, err := v.Verify(context.Background(), f.evidence, f.binding)
	if err != nil {
		t.Fatalf("control: legitimate evidence was refused: %s", detail(err))
	}
	return attested
}

// A verdictSource is what [refuses] drives: an [attest.Verification], or the
// stand-in in hardwareevidence_test.go that judges a recording made before
// binding context v2 existed.
type verdictSource interface {
	Verify(ctx context.Context, ev attest.Evidence, binding attest.Binding) (attest.Attested, error)
}

// refuses asserts that verification refused for exactly the given reason, and
// that a caller learns nothing beyond the fact of refusal.
func refuses(t *testing.T, v verdictSource, ev attest.Evidence, b attest.Binding, want attest.Reason) {
	t.Helper()
	attested, err := v.Verify(context.Background(), ev, b)
	if err == nil {
		t.Fatalf("evidence was accepted as %+v; want refusal with %v", attested, want)
	}
	if got := attest.ReasonOf(err); got != want {
		t.Errorf("refused with %v; want %v (detail: %s)", got, want, detail(err))
	}
	if !errors.Is(err, attest.ErrRefused) {
		t.Errorf("refusal does not match attest.ErrRefused: %v", err)
	}
	if got, want := err.Error(), attest.ErrRefused.Error(); got != want {
		t.Errorf("refusal Error() = %q; want the undifferentiated %q", got, want)
	}
}

// detail returns the operator-facing text behind a refusal, for test output
// only. A caller in production reads this from the log, never from an error.
func detail(err error) string {
	var r *attest.Refusal
	if errors.As(err, &r) {
		return r.LogString()
	}
	return err.Error()
}
