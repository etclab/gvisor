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

import "crypto/sha512"

// CallerSuppliedBytesSize is the width of the field a platform copies verbatim
// from the guest's request into the evidence it produces. SEV-SNP's REPORT_DATA
// and TDX's REPORTDATA are both this wide, which is why the constant lives
// above the vendor seam.
const CallerSuppliedBytesSize = 64

// BindingContextSize is the width of the versioned binding context ADR-0002
// reserves. It is fixed, and it stayed fixed when v2 arrived: the policy digest
// travels beside the context rather than inside it, so no byte a v1 verifier
// reads has moved.
const BindingContextSize = 16

// A BindingContext is the fixed-width versioned field concatenated with the
// public key before hashing, per ADR-0002.
//
// v1 is every byte zero: the field reserved space and carried nothing. v2 is
// version byte 2 and the rest zero, and it means the hash covers a third input
// — the digest of the sandbox's policy. The reservation was made because
// binding a sandbox's configuration into the evidence was deferred rather than
// rejected, and retrofitting it onto H(pubkey) would have meant re-attesting
// every deployed platform. Ticket 18 cashed it in, and the cliff was a version
// bump.
type BindingContext [BindingContextSize]byte

// BindingContextV1 is the context this verifier no longer admits: all zero, and
// carrying no policy digest.
//
// It is still exported and still hashes the way it always did, because
// evidence recorded under it exists — every bundle under docs/snp was acquired
// before v2 — and a recording whose report data can no longer be recomputed is
// a recording nobody can check again.
var BindingContextV1 = BindingContext{}

// BindingContextV2 is the only context this verifier understands: version byte
// 2, every reserved byte zero. A peer claiming it commits to a policy digest
// as well as to its public key.
var BindingContextV2 = BindingContext{0x02}

// Version reports the context's version byte. v1 is version zero, with every
// reserved byte zero as well; Version alone is therefore not enough to decide
// whether a context is understood, and [BindingContext.Recognised] is what
// callers should ask. Version is for saying which version was refused.
func (c BindingContext) Version() uint8 { return c[0] }

// Recognised reports whether this verifier understands c.
//
// Only v2 is recognised, and a verifier meeting anything else must refuse
// rather than ignore it. That cuts both ways now. A v1 peer is refused because
// its evidence commits to no policy at all, and admitting it would let a peer
// opt out of the policy check by claiming the older version — which is the
// deployment ADR-0002 was written to prevent, arrived at from the other
// direction. A later version is refused because it may bind something this
// verifier cannot see.
func (c BindingContext) Recognised() bool { return c == BindingContextV2 }

// A Binding is what a peer's evidence must commit to: the public key it
// presents at the handshake, and the binding context it claims.
//
// The context travels alongside the evidence rather than inside it. Evidence
// carries only the digest, so a verifier cannot recover the context from the
// evidence and must be told which context to recompute against — which is
// precisely why an unrecognised one has to be a refusal rather than a shrug.
type Binding struct {
	// PublicKey is the peer's public key exactly as presented at the handshake.
	// Whatever encoding the presenter used, the same bytes must be hashed on
	// both sides.
	PublicKey []byte

	// Context is the versioned binding context the peer claims.
	Context BindingContext

	// PolicyDigest names the signed reference value set the peer presents as
	// its policy: the digest of the document, not the document. It is hashed
	// into the caller-supplied bytes under a v2 context and ignored under v1,
	// which carried no such field.
	//
	// It travels beside the context rather than inside it because the context
	// is 16 bytes wide and a digest is 32, and widening the context would move
	// a byte a v1 verifier already reads. A verifier does not take the peer's
	// word for it any more than for the key: the digest is checked against the
	// allow-list and then recomputed into the binding, so a peer presenting a
	// policy digest it did not acquire evidence over is refused.
	PolicyDigest PolicyDigest
}

// CallerSuppliedBytes returns the bytes a guest must hand its platform for this
// binding: SHA-512 of the public key, the context and — under v2 — the policy
// digest, per ADR-0002 and its amendment.
//
// SHA-512 rather than the SNP-native SHA-384 because its output is exactly
// [CallerSuppliedBytesSize] wide. A shorter digest would need a padding
// convention, and a padding convention is a thing two implementations can
// disagree about.
//
// A v1 context hashes two inputs, exactly as it did before the policy digest
// existed, so evidence recorded under v1 still recomputes byte for byte. Every
// other context hashes three. The rule is written as "v1, or everything else"
// rather than "v2 and later" so that no unrecognised context can quietly borrow
// v1's shorter formula: a context this verifier does not admit is refused
// before these bytes are compared anyway, and the arithmetic should not be the
// thing standing between the two.
//
// An [Acquirer] calls this to obtain the bytes it writes to the platform, and
// [Verification.Verify] calls it to recompute what the evidence should have
// come back with. Producer and consumer therefore agree by construction rather
// than by comment.
func (b Binding) CallerSuppliedBytes() [CallerSuppliedBytesSize]byte {
	h := sha512.New()
	h.Write(b.PublicKey)
	h.Write(b.Context[:])
	if b.Context != BindingContextV1 {
		h.Write(b.PolicyDigest[:])
	}
	var out [CallerSuppliedBytesSize]byte
	copy(out[:], h.Sum(nil))
	return out
}
