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

import "context"

// A Vendor is a confidential-computing hardware vendor whose evidence this
// module can be taught to verify.
type Vendor string

// VendorAMDSEVSNP is AMD SEV-SNP, the only vendor implemented. A second vendor
// adds a constant here and an implementation of [Acquirer] and [Verifier], and
// touches nothing else in this package.
const VendorAMDSEVSNP Vendor = "amd-sev-snp"

// Evidence is the vendor-specific attestation blob obtained from the platform,
// bundled with the certificate chain a verifier needs in order to check it.
//
// Above the vendor seam Evidence is opaque: nothing outside a [Verifier]
// interprets Bytes or Chain. That opacity is the whole point of the seam — the
// transport carries Evidence, the certificate carries Evidence, and neither
// knows what an SEV-SNP report is.
type Evidence struct {
	// Vendor names the hardware that produced Bytes. A [Verifier] refuses
	// evidence from a vendor it does not implement rather than guessing at the
	// format.
	Vendor Vendor

	// Bytes is the evidence itself — an SEV-SNP attestation report for
	// [VendorAMDSEVSNP].
	Bytes []byte

	// Chain is the certificate chain Bytes is verified against. It is
	// provisioned onto the config device ahead of use and shipped with the
	// evidence rather than obtained from the platform or fetched from the
	// vendor at handshake time (ADR-0005); the platform's own certificate table
	// is empty on the host this was built against and cannot be filled. The
	// chain is per chip, so each side presents its own.
	Chain []byte
}

// Present reports whether any evidence was presented at all. A peer that
// presents none is refused with [ReasonNoEvidence] rather than treated as
// unknown: a non-confidential VM has nothing to say and must not benefit from
// saying nothing.
func (e Evidence) Present() bool { return len(e.Bytes) > 0 }

// Claims are the platform facts a [Verifier] read out of evidence it found
// authentic. They are claims and not conclusions: they are what the evidence
// says, before any reference value has been applied to it.
type Claims struct {
	// LaunchMeasurement is the digest of initial guest memory the evidence
	// attests.
	LaunchMeasurement []byte

	// TCB is the trusted computing base level the platform reports.
	TCB TCB

	// CallerSuppliedBytes are the bytes the guest handed the platform when it
	// asked for this evidence, returned verbatim. ADR-0002 governs what they
	// must contain; the check itself lives above the seam, in
	// [Verification.Verify], because the binding is this design's invention
	// rather than any vendor's.
	CallerSuppliedBytes [CallerSuppliedBytesSize]byte
}

// Attested describes a platform whose evidence satisfied the reference value
// set. Per the vocabulary in CONTEXT.md this is a property of a platform, never
// of an agent and never of a message.
type Attested struct {
	// Vendor is the hardware that produced the evidence.
	Vendor Vendor

	// Claims is what the evidence said.
	Claims Claims

	// Satisfied is the reference value that admitted this platform. A set holds
	// more than one so that an image can be rolled out without downtime, and an
	// operator reading a log wants to know which of them let a peer in.
	Satisfied ReferenceValue
}

// An Acquirer obtains evidence from the platform it is running on. It is the
// producer half of the vendor seam.
//
// The implementation that talks to real hardware through the platform's
// vendor-neutral report interface is ticket 04; the implementation available
// now is the fake SEV-SNP platform in gvisor.dev/gvisor/attest/snpfake, which
// mints test-signed evidence with arbitrary contents so that the verification
// path can be exercised without a confidential VM.
type Acquirer interface {
	// Vendor names the hardware this acquirer speaks for.
	Vendor() Vendor

	// Acquire asks the platform for evidence over the given caller-supplied
	// bytes, which the platform copies verbatim into the evidence it returns.
	// The caller computes those bytes with [Binding.CallerSuppliedBytes], so
	// that producer and consumer agree on ADR-0002's binding by construction
	// rather than by comment.
	Acquire(ctx context.Context, callerSupplied [CallerSuppliedBytesSize]byte) (Evidence, error)
}

// A Verifier decides whether evidence is authentic and whether it satisfies a
// reference value set. It is the consumer half of the vendor seam.
//
// A Verifier owns exactly the questions that are the vendor's: does this parse,
// does its signature chain to the vendor's root, does its launch measurement
// appear in the set, is its platform at or above the TCB floor, are its guest
// policy bits within what the reference value permits. It does not own the
// binding of ADR-0002 and does not own the precedence between its own failures
// and that one; [Verification] does.
//
// Every refusal must be a [*Refusal] carrying the [Reason] that names it. A
// Verifier returning a bare error is a bug, because the caller has no way to
// report it and no way to log it usefully.
type Verifier interface {
	// Vendor names the hardware whose evidence this verifier understands.
	Vendor() Vendor

	// Verify checks evidence against every reference value in set, and accepts
	// it if it satisfies any one of them.
	Verify(ctx context.Context, ev Evidence, set ReferenceValueSet) (Attested, error)
}
