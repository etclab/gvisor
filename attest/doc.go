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

// Package attest is the public surface of the attested-tunnel module: the
// vendor seam, the reference value vocabulary, and the verification entry
// point a tunneld calls for every peer it meets.
//
// # The verdict
//
// [Verification.Verify] takes evidence and the binding a peer claims, and
// produces a verdict against the reference value set the Verification holds.
// Evidence that satisfies a reference value yields an [Attested] describing the
// platform. Everything else is refused, and every distinct way of being wrong
// carries its own [Reason].
//
// A caller learns only that verification failed. Every refusal's Error is the
// same sentence, so an attacker who can observe a refusal cannot learn which
// reference value to target next. The reason is reachable through [ReasonOf]
// and [Refusal.Detail] for tests and for the operator log, and travels no
// further.
//
// # The vendor seam
//
// [Acquirer] and [Verifier] are the two halves of the seam, at one package
// boundary. A second hardware vendor implements those two interfaces and
// nothing else: the reference value vocabulary, the binding of ADR-0002, the
// refusal taxonomy and the precedence between checks all live above the seam
// and are not restated per vendor.
//
// Today there is one implementation of each. The verifier is
// gvisor.dev/gvisor/attest/verify, which wraps github.com/google/go-sev-guest
// for SEV-SNP (ADR-0003) and keeps that library's API shape from reaching any
// other package. The acquirer is gvisor.dev/gvisor/attest/snpfake, a fake
// SEV-SNP platform built on go-sev-guest's test signing; the acquirer that
// talks to real hardware through the platform's vendor-neutral report
// interface arrives with ticket 04.
//
// # The reference value set
//
// A [ReferenceValueSet] is what [Verification] admits peers against. It is
// authored as a JSON document a human reads and reviews, signed by the
// reference value author with a detached Ed25519 signature, and delivered from
// outside the launch measurement — only the author's public key lives inside it
// (ADR-0004). [LoadReferenceValueSet] and [LoadReferenceValueSetFile] verify
// before they parse, and a set whose signature is absent, invalid, or by
// another key is refused outright: there is no unsigned set to fall back to and
// no way to tell a missing set from an unverifiable one.
//
// # What this package does not do
//
// It reaches no network. The certificate chain a verifier needs is an input,
// provisioned ahead of use and carried in the [Evidence] (ADR-0005), never
// fetched during a handshake.
package attest
