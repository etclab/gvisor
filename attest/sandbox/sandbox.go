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

// Package sandbox is the local contract between tunneld and whatever sandbox
// sits beside it: three verbs, and an invariant about what crosses them.
//
// # The invariant
//
// A sandbox sees no evidence, no key and no trust decision. It gets a stream
// or an error, and a policy or nothing.
//
// Everything this package exports is chosen to make that sentence checkable
// rather than aspirational. [Stream] is a byte stream and carries nothing
// else. [Attested] is four strings — no evidence bytes, no certificate, no
// refusal reason. An error from [Sandbox.Open] says the stream did not happen
// and not why the peer was refused, because the reason is the operator's and
// reaches the console through tunneld's refusal log (spec, Error surface).
// Nothing here can verify anything, and nothing here holds a key.
//
// # Why the contract is this shape
//
// Ticket 22 makes tunneld the network boundary for any sandbox, not only for
// the one that happens to be in its process. The sandbox that matters later is
// gVisor's runsc, in a sibling process, which consumes a stream as a file
// descriptor — and spike E1 (docs/snp/evidence/ticket22/spikes/E1) settled
// what that costs: a QUIC stream is not a kernel object and cannot be handed
// over as one, so the descriptor a sandbox receives is one end of a socketpair
// and tunneld pumps bytes between it and the stream. That is why [Stream] is
// an interface over an [io.ReadWriteCloser] with a half-close rather than
// anything QUIC-shaped: one end of a socketpair satisfies it as it stands
// (*net.UnixConn already has CloseWrite), and so does package tunnel's raw
// stream, and neither had to learn about the other.
//
// # The two halves
//
// [Network] is tunneld's half: streams to and from attested peers. Package
// tunneld implements it, and this package never imports it — nothing here
// depends on gvisor.dev/gvisor/attest at all, which is the import-graph form
// of the invariant above.
//
// [Sandbox] is the whole contract: [Network] plus Apply, the pushed policy.
// [Null] implements it in process; [Client] speaks it to a sandbox in another
// process, over the unix socket [Host] listens on.
package sandbox

import (
	"context"
	"io"
)

// A Stream is one byte stream to or from an attested peer: bytes in both
// directions and an end in each, and nothing else.
//
// CloseWrite is the half that makes this more than an io.ReadWriteCloser, and
// it is not decoration. Every protocol a sandbox is likely to run over a
// stream ends a request by saying it has finished sending — the echo the
// exercise runs does exactly this — and a stream that could only be closed
// whole would force the reader on each side to be told the length in advance
// or to wait for a timeout.
//
// What a Stream cannot express is a reset. A QUIC reset arrives on an
// AF_UNIX SOCK_STREAM socketpair as a close and nothing more (spike E1, "What
// this decides for the contract"), so an abnormal end and a clean one look
// alike to a sandbox in another process. The contract does not pretend
// otherwise: it carries the end of the stream in each direction and leaves
// "why it ended" out, rather than inventing a signal in process that cannot be
// delivered out of it.
type Stream interface {
	io.ReadWriteCloser

	// CloseWrite ends this side's half of the stream. The peer reads
	// end-of-file; this side may still read what the peer has yet to send.
	CloseWrite() error
}

// Attested is everything a sandbox may know about the peer on the other end of
// a stream. Four strings, and the reason for each is the reason none of its
// neighbours are here.
//
// Peer names it, Vendor says whose hardware vouched for it, Measurement says
// which image it is running and PolicyDigest which policy it presented. Those
// four are what a sandbox could legitimately act on: they are the identity the
// peer was admitted under, and every one of them is public — the measurement
// and the digest are in the reference value sets on both sides' config
// devices, which are untrusted media by construction (ADR-0004).
//
// What is deliberately absent:
//
//   - the evidence, which is the vendor's signed blob and belongs below the
//     vendor seam; a sandbox holding it could neither check it nor be trusted
//     to have checked it, and a sandbox that forwarded it would have turned a
//     platform's attestation into a bearer token;
//   - any key — tunneld's identity key never leaves ratls, and a sandbox that
//     held one could speak as this sandbox;
//   - any refusal reason, because a sandbox never sees a refused peer at all.
//     A refusal is an aborted handshake and an operator's log line; there is no
//     stream for it to arrive on;
//   - the reference value that admitted the peer, which is a fact about this
//     side's allow-list rather than about the peer.
//
// It is all strings because it crosses a process boundary as JSON (see [Host])
// and because a sandbox has no business computing with any of it. Measurement
// and PolicyDigest are lowercase hexadecimal, at full width: the measurement
// is 48 bytes on both vendors implemented here (SEV-SNP's launch digest,
// TDX's RTMR2) and the policy digest is a 32-byte SHA-256. They are not
// abbreviated, because the whole use of either is comparing it with a number
// an operator has written down somewhere else, and a truncated identity is one
// an attacker gets to choose collisions in.
type Attested struct {
	// Peer is the name the peer table gives this peer, or "" when it names it
	// no longer or never did.
	//
	// Empty is a normal state and not an error. Naming binds to nothing (spec,
	// Reference values and naming): a peer is admitted on its measurement and
	// its policy digest, and the name is a local convenience that an incoming
	// connection may not even carry — it arrives from an ephemeral source port,
	// so the table can identify it by address only, and only when exactly one
	// entry matches.
	Peer string `json:"peer,omitempty"`

	// Vendor is the hardware that produced the peer's evidence:
	// "amd-sev-snp" or "intel-tdx".
	Vendor string `json:"vendor"`

	// Measurement is the peer's launch measurement in lowercase hexadecimal —
	// the SEV-SNP launch digest, or RTMR2 for TDX — which is to say which image
	// the peer booted.
	Measurement string `json:"measurement"`

	// PolicyDigest is the digest of the signed policy the peer presented, in
	// lowercase hexadecimal. It is what the peer committed to at the handshake
	// and what this side's reference value set admitted it under.
	PolicyDigest string `json:"policy_digest"`
}

// Network is tunneld's half of the contract: streams to and from peers it has
// attested. It is what a sandbox is given, and the only thing it is given.
//
// Both methods hand back a [Stream] that is already established — Open returns
// after the peer has been admitted and admitted this side, so a sandbox never
// holds a stream to a peer that is about to be refused, which is the state this
// design refuses everywhere else.
type Network interface {
	// Open gives back a stream to the named peer, dialing and attesting one
	// first if there is no tunnel to it. The error says the stream did not
	// happen; it never says why a peer was refused.
	Open(ctx context.Context, peer string) (Stream, error)

	// Accept gives back the next stream a peer opened to this sandbox, with the
	// identity that peer was admitted under.
	Accept(ctx context.Context) (Stream, Attested, error)
}

// A Sandbox is whatever sits beside tunneld: the whole contract, which is
// [Network] plus the policy a delegator pushes.
//
// [Null] is the first implementation and the one Milestone 3's exercise runs
// inside. A sandbox in another process is this same interface with a unix
// socket in the middle: [Host] serves Open and Accept to it and sends it
// Apply, and [Client] is its side.
type Sandbox interface {
	Network

	// Apply hands the sandbox a policy that a peer pushed to this one. A nil
	// error is the acknowledgement the pushing peer waits for; any error is a
	// refusal.
	//
	// The bytes are opaque and versioned (see [ReadEnvelope]). Tunneld reads
	// two fields of them — the format and the version — before the sandbox sees
	// them at all, and a sandbox is free to read no more than that: [Null]
	// reads nothing and enforces nothing.
	Apply(ctx context.Context, policy []byte) error
}
