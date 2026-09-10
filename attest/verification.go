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
// The set is checked by [ReferenceValueSet.validate] for the two ways it can be
// wrong in the dangerous direction, and both are refused at startup rather than
// at the first peer. A set read off the config device has already been checked
// the same way by [LoadReferenceValueSet]; it is checked again here because a
// set can also be built in memory, and a trust root is worth refusing twice.
//
// The width of a launch measurement is the vendor's business and is not checked
// here or in the loader; a value of the wrong width matches nothing, which
// fails closed. That asymmetry is deliberate: anything that could weaken the
// set is a startup error, and anything that could only over-refuse is left
// alone, because a digest width baked into this module is the seam a second
// vendor would have to break.
func New(verifier Verifier, set ReferenceValueSet) (*Verification, error) {
	if verifier == nil {
		return nil, errors.New("attest: no verifier")
	}
	if err := set.validate(); err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	// The set is copied rather than referenced. It is this design's trust root
	// and it was just checked; holding a caller's slice would let it be
	// weakened afterwards, at a distance, by code that has no idea it is
	// touching a trust root.
	held := ReferenceValueSet{Values: make([]ReferenceValue, len(set.Values))}
	for i, rv := range set.Values {
		held.Values[i] = rv.clone()
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
//  4. The policy the peer presents is one a reference value for its measurement
//     lists. This comes after the vendor's questions because it is a claim
//     about a peer whose evidence has been found authentic, and before the
//     binding because the binding is the expensive half of the same statement:
//     if the digest is not one this side admits, what it is bound to does not
//     matter.
//  5. The caller-supplied bytes match the presented key and the policy digest.
//     This comes last because it is the one check that reads a value out of the
//     evidence, and reading values out of evidence whose signature has not been
//     checked is how a verifier gets used as an oracle. It is also what makes
//     the check above worth anything: step 4 asks whether the digest is
//     allowed, and this asks whether the peer really acquired its evidence over
//     it.
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
			"peer claims binding context version %d (%x); this verifier understands only v2 (%x), "+
				"and v1 carried no policy digest, so a peer speaking it commits to no policy at all",
			binding.Context.Version(), binding.Context[:], BindingContextV2[:])
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

	satisfied, err := v.permits(attested, binding.PolicyDigest)
	if err != nil {
		return Attested{}, err
	}
	// The value that admitted this peer is the one that satisfied the vendor's
	// questions *and* lists its policy, which need not be the one the vendor
	// picked: a set naming an image twice under two policies has two of them.
	attested.Satisfied = satisfied

	want := binding.CallerSuppliedBytes()
	got := attested.Claims.CallerSuppliedBytes
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return Attested{}, Refuse(ReasonBindingMismatch,
			"evidence is bound to different caller-supplied bytes than the presented public key produces")
	}
	return attested, nil
}

// permits decides whether the policy a peer presents is one the set admits for
// the image it is running, and returns the reference value that admits it.
//
// The value the vendor's verifier satisfied is tried first, since that is
// usually the whole answer. If it lists another policy, the candidates are
// every value for this peer's vendor naming its launch measurement — not only
// the one the vendor picked, because a set may name one image twice under two
// policies while a deployment moves from one to the other, and the vendor's
// verifier has no idea which of the two is the peer's. One candidate that
// lists the presented digest is enough, and so is one that lists none.
//
// The comparison is plain equality. A policy digest is the digest of a document
// delivered on an untrusted device and printed in operator logs; there is no
// secret here for a timing difference to leak, and saying so is cheaper than a
// constant-time call that would imply there is.
func (v *Verification) permits(attested Attested, presented PolicyDigest) (ReferenceValue, error) {
	if attested.Satisfied.permits(presented) {
		return attested.Satisfied, nil
	}
	candidates := 0
	for _, rv := range v.set.Values {
		if rv.vendor() != attested.Vendor || !rv.matchesMeasurement(attested.Claims) {
			continue
		}
		candidates++
		if rv.permits(presented) {
			return rv.clone(), nil
		}
	}
	if candidates == 0 {
		// Unreachable: the value that just admitted this peer names its
		// measurement, so it is one of the candidates. Written down anyway,
		// because the alternative to a refusal here is an acceptance decided by
		// a loop that found nothing.
		return ReferenceValue{}, Refuse(ReasonPolicyMismatch,
			"peer presents policy digest %s, and no reference value in this set names the measurement its evidence carries",
			presented)
	}
	return ReferenceValue{}, Refuse(ReasonPolicyMismatch,
		"peer presents policy digest %s; no reference value for the measurement it is running lists that policy",
		presented)
}
