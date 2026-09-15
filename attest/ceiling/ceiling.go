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

// Package ceiling is the egress ceiling: the one rule set a guest built from
// this image installs before it touches the network, and the name that rule set
// goes by.
//
// # Why it is a constant and not a document
//
// Until ticket 22 the rule set was generated from `policy.json` on the config
// device: the peer addresses, the listen port and the sandbox identifier all
// came off a disk the host supplies, and the guest's init could not install
// anything until it had found, mounted and read that disk. Everything about
// that was the wrong way round. The device is outside the launch measurement,
// so a verifier reading the image could not say what the guest would enforce;
// and the window between "this guest is running" and "this guest is
// constrained" was however long finding a disk takes.
//
// The ceiling is therefore two values compiled in — [Interface] and [Port] —
// and a text that is inside the launch measurement with them. Nothing on the
// config device contributes a byte of it, so nothing on the config device can
// widen it, and it goes in before the link is up (docs/snp/cloud/tdx/init.tdx).
// Changing either value produces a different image with a different
// measurement, which is the property wanted: a verifier can tell a guest built
// for eth0/4433 from one built for anything else, and the reference value set
// names which.
//
// # What the digest is for
//
// [Digest] is SHA-256 over [Text], and it is the number this sandbox binds into
// its evidence under ADR-0002's amendment — the slot that carried the digest of
// the config device's policy.json until ticket 22. A peer's allow-list entry
// naming it therefore still means something, and means something narrower than
// it did: this enforcer, this ceiling. It is not what decides delegation any
// more; that is the contract pushed over the tunnel after attestation
// (docs/policy-binding.md).
//
// The text is the whole file, commentary included, because the commentary is
// the justification for every rule under it and a silent edit to a
// justification should show up as a different number.
package ceiling

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

const (
	// Interface is the VPC link, as the kernel names it when no udev runs.
	//
	// It is an image constant and not a boot-time discovery: a name discovered
	// at boot is a name something outside the measurement chose. It fails
	// closed — a rule naming an interface that never appears grants nothing —
	// so the worst a wrong value can do is leave the guest unable to reach its
	// peer, loudly, at the first dial.
	Interface = "eth0"

	// Port is the tunnel's UDP port, and the only port anything may leave or
	// enter this guest on.
	//
	// Until ticket 22 it was read from tunneld.json's `listen` on the config
	// device. Now the ceiling names it and tunneld.json may only agree with it:
	// a run configuration asking for any other port is refused at load, because
	// a listener the ceiling silently drops looks like a network fault and is a
	// configuration error.
	Port uint16 = 4433
)

// text is the ceiling, as a reader of the guest's console compares it. It is
// checked in beside this file and compiled into the binary the image measures,
// and docs/snp/evidence/ticket22/spikes/E3/ceiling.nft is the same bytes: the
// test beside this file is what keeps the two from drifting.
//
//go:embed ceiling.nft
var text string

// digest is computed once. It is a value, so a caller holding it cannot reach
// anything this package would rather keep.
var digest = sha256.Sum256([]byte(text))

// Text is the ceiling's canonical description, in nft's own syntax with the
// reasoning above each rule.
//
// It is nft syntax and not this package's own because the reader of a guest
// console is an operator who knows nft, and a rendering nobody can paste into
// `nft -f` to compare is a rendering nobody checks.
func Text() string { return text }

// Digest is SHA-256 over exactly the bytes [Text] returns: the ceiling's name.
func Digest() [sha256.Size]byte { return digest }

// DigestHex is [Digest] in the form a console line, a reference value set's
// policy_digest and an operator's clipboard all carry it in.
func DigestHex() string { return hex.EncodeToString(digest[:]) }
