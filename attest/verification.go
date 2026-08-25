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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
)

// A Verification is this module's verification entry point: one verifier and
// one reference value set, held for the lifetime of the process that verifies
// against them.
//
// This is the surface a tunneld calls for every peer it meets, and the surface
// tests drive. Nothing below it — which library parses a report, how a chain is
// validated, in what order the checks run — is a caller's concern or a test's.
type Verification struct {
	verifier Verifier
	set      ReferenceValueSet
}

// New builds a Verification from a verifier and the reference value set it
// should admit peers against.
//
// The set is checked here for the two ways it can be wrong in the dangerous
// direction, and both are refused at startup rather than at the first peer.
//
// An empty set admits nobody, which is a configuration mistake every time.
//
// A reference value with no launch measurement admits *everybody*: it names no
// image, so every authentic platform matches it, and a set holding one is
// strictly weaker than its author can have intended. That is the failure worth
// catching loudly, because it does not announce itself — every handshake
// succeeds and nothing looks wrong.
//
// The width of a launch measurement is the vendor's business and is not checked
// here; a value of the wrong width matches nothing, which fails closed. That
// asymmetry is deliberate: anything that could weaken the set is a startup
// error, and anything that could only over-refuse is left to the loader that
// knows the vendor (ticket 03).
func New(verifier Verifier, set ReferenceValueSet) (*Verification, error) {
	if verifier == nil {
		return nil, errors.New("attest: no verifier")
	}
	if len(set.Values) == 0 {
		return nil, errors.New("attest: reference value set is empty; it would admit nobody")
	}
	// The set is copied rather than referenced. It is this design's trust root
	// and it was just checked; holding a caller's slice would let it be
	// weakened afterwards, at a distance, by code that has no idea it is
	// touching a trust root.
	held := ReferenceValueSet{Values: make([]ReferenceValue, len(set.Values))}
	for i, rv := range set.Values {
		if len(rv.LaunchMeasurement) == 0 {
			return nil, fmt.Errorf("attest: reference value %d has no launch measurement; it would admit every authentic platform", i)
		}
		held.Values[i] = rv
		held.Values[i].LaunchMeasurement = append([]byte(nil), rv.LaunchMeasurement...)
	}
	return &Verification{verifier: verifier, set: held}, nil
}

// Verify produces a verdict on ev: an [Attested] describing the platform, or a
// refusal.
//
// binding is what the peer claims its evidence commits to — the public key it
// presented at the handshake and the binding context it carries. Verify does
// not take the peer's word for either; it recomputes the caller-supplied bytes
// from them and requires the evidence to have come back with exactly those.
//
// The checks run in this order, and the first failure is the verdict:
//
//  1. Evidence was presented at all, and so was a public key to bind it to.
//  2. The binding context is one this verifier understands (ADR-0002). This
//     comes before authenticity because it asks which version of this protocol
//     the peer is speaking, and a verifier that cannot answer that has no
//     business interpreting what follows.
//  3. The evidence is authentic and satisfies a reference value — the vendor's
//     questions, answered behind the seam.
//  4. The caller-supplied bytes match the presented key. This comes last
//     because it is the one check that reads a value out of the evidence, and
//     reading values out of evidence whose signature has not been checked is
//     how a verifier gets used as an oracle.
//
// Only the first failure is reported, and a caller cannot tell the failures
// apart in any case: every error returned here matches [ErrRefused] and every
// Error string is identical. Tests read the reason with [ReasonOf]; operators
// read it with [Refusal.LogString].
func (v *Verification) Verify(ctx context.Context, ev Evidence, binding Binding) (Attested, error) {
	if !ev.Present() {
		return Attested{}, Refuse(ReasonNoEvidence, "peer presented no evidence")
	}
	if len(binding.PublicKey) == 0 {
		// A binding with no key still hashes to something definite, and
		// something definite is something an attacker can acquire genuine
		// evidence over. Refusing here is what stops a peer being admitted as
		// attested while presenting no identity at all.
		return Attested{}, Refuse(ReasonBindingMismatch, "peer presented no public key to bind the evidence to")
	}
	if !binding.Context.Recognised() {
		return Attested{}, Refuse(ReasonUnknownBindingContext,
			"peer claims binding context version %d (%x); this verifier understands only v1, which is every byte zero",
			binding.Context.Version(), binding.Context[:])
	}

	attested, err := v.verifier.Verify(ctx, ev, v.set)
	if err != nil {
		// A Verifier that returns a bare error is a bug in that verifier, but
		// it must not become an acceptance, and it must not become a reason
		// that claims more than is known.
		if ReasonOf(err) == ReasonNone {
			return Attested{}, Refuse(ReasonMalformedEvidence, "verifier returned an untyped error: %v", err)
		}
		return Attested{}, err
	}

	want := binding.CallerSuppliedBytes()
	got := attested.Claims.CallerSuppliedBytes
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return Attested{}, Refuse(ReasonBindingMismatch,
			"evidence is bound to different caller-supplied bytes than the presented public key produces")
	}
	return attested, nil
}
