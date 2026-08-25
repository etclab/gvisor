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
// reserves. It is fixed so that a later version can carry a policy digest
// without moving a byte that a v1 verifier already reads.
const BindingContextSize = 16

// A BindingContext is the fixed-width versioned field concatenated with the
// public key before hashing, per ADR-0002.
//
// v1 is every byte zero: the field reserves space and carries nothing. The
// reservation exists because binding runsc's configuration into the evidence is
// deferred rather than rejected, and retrofitting it onto H(pubkey) would mean
// re-attesting every deployed platform. Reserving it here turns that cliff into
// a version bump.
type BindingContext [BindingContextSize]byte

// BindingContextV1 is the only context this verifier understands: all zero.
var BindingContextV1 = BindingContext{}

// Version reports the context's version byte. v1 is version zero, with every
// reserved byte zero as well; Version alone is therefore not enough to decide
// whether a context is understood, and [BindingContext.Recognised] is what
// callers should ask. Version is for saying which version was refused.
func (c BindingContext) Version() uint8 { return c[0] }

// Recognised reports whether this verifier understands c.
//
// Only v1 is recognised, and a verifier meeting anything else must refuse
// rather than ignore it. That is the whole value of the reservation: a reserved
// field that verifiers skip over reserves nothing, because a v2 peer carrying a
// policy digest would be admitted by a v1 verifier that never looked at the
// digest — which is exactly the deployment ADR-0002 exists to prevent.
func (c BindingContext) Recognised() bool { return c == BindingContextV1 }

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
}

// CallerSuppliedBytes returns the bytes a guest must hand its platform for this
// binding: SHA-512 of the public key concatenated with the context, per
// ADR-0002.
//
// SHA-512 rather than the SNP-native SHA-384 because its output is exactly
// [CallerSuppliedBytesSize] wide. A shorter digest would need a padding
// convention, and a padding convention is a thing two implementations can
// disagree about.
//
// An [Acquirer] calls this to obtain the bytes it writes to the platform, and
// [Verification.Verify] calls it to recompute what the evidence should have
// come back with. Producer and consumer therefore agree by construction rather
// than by comment.
func (b Binding) CallerSuppliedBytes() [CallerSuppliedBytesSize]byte {
	h := sha512.New()
	h.Write(b.PublicKey)
	h.Write(b.Context[:])
	var out [CallerSuppliedBytesSize]byte
	copy(out[:], h.Sum(nil))
	return out
}
