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
	"errors"
	"fmt"
)

// A ReferenceValue is an expected launch measurement plus the TCB floor and the
// guest policy a peer must satisfy to be admitted.
//
// Nothing here is a key or a name. Membership is "runs the measured image":
// anyone who launches it joins, adding a host needs no human step, and
// revocation is a TCB floor or a measurement change rather than a file edit.
type ReferenceValue struct {
	// LaunchMeasurement is the expected digest of initial guest memory. It is a
	// prediction computed offline from the image build inputs, not a value read
	// off a booted guest — a measurement learned by asking the machine is not a
	// prediction, and a check built on one cannot fail.
	//
	// It must not be empty. A reference value naming no measurement matches
	// every authentic platform, so both [New] and [LoadReferenceValueSet]
	// refuse a set containing one.
	//
	// Its width is deliberately checked nowhere. How wide a launch measurement
	// is belongs to the hardware vendor, and a width baked in here would be a
	// vendor's digest sitting above the seam that exists to make a second
	// vendor a day's work. A measurement of the wrong width matches nothing,
	// which fails closed.
	LaunchMeasurement []byte

	// MinimumTCB is the lowest platform trusted computing base level this value
	// admits. A platform below it is refused, which is how a known-vulnerable
	// firmware level is kept out.
	MinimumTCB TCB

	// GuestPolicy is what the peer's guest policy may claim.
	GuestPolicy GuestPolicy
}

// A ReferenceValueSet is the collection of reference values one verifier will
// accept. Evidence satisfying any one of them is accepted, which is what lets a
// new image roll out while the old one is still running.
//
// Here the set is an in-memory value. The signed document a reference value
// author writes, its detached signature and its loader are in refvalsfile.go,
// and produce exactly this type: nothing that consumes a set can tell whether
// it was read off the config device or built in a test.
type ReferenceValueSet struct {
	Values []ReferenceValue
}

// TCB is a platform trusted computing base level, expressed as four separately
// named component versions rather than the packed integer the hardware reports.
//
// The packing is the vendor's business. A reference value set is this design's
// trust root and has to be reviewable by eye, and nobody reviews a decimal
// integer for whether it means "microcode 72".
type TCB struct {
	// Bootloader is the bootloader security patch level.
	Bootloader uint8

	// TEE is the trusted execution environment security patch level.
	TEE uint8

	// SNP is the SNP firmware security patch level.
	SNP uint8

	// Microcode is the microcode security patch level.
	Microcode uint8
}

// GuestPolicy states which guest capabilities a reference value permits. It is
// a ceiling, not a description: a peer whose evidence claims a capability this
// value does not permit is refused.
//
// Every field is named for its polarity, because a trust root that a reviewer
// can misread by one negation is not reviewable. A capability this type does
// not name is not permitted — the type fails closed as it grows, and a peer
// launched with a capability nobody has considered does not slip through on the
// grounds that nobody considered it.
//
// The zero value permits nothing and requires nothing beyond that, which is the
// right default for a reference value whose author did not think about policy.
type GuestPolicy struct {
	// ABIMajor and ABIMinor are the lowest SNP ABI version the guest may have
	// demanded at launch. Zero imposes no floor.
	ABIMajor uint8
	ABIMinor uint8

	// AllowSMT permits a guest launched on a platform with symmetric
	// multithreading enabled.
	AllowSMT bool

	// AllowMigrationAgent permits a guest that may have a migration agent.
	AllowMigrationAgent bool

	// AllowDebug permits a guest the host may decrypt for debugging. Leaving it
	// false is what stops a debug-enabled guest from attesting.
	AllowDebug bool

	// RequireSingleSocket refuses a guest that may be active on more than one
	// socket. Unlike the fields above this one is a requirement rather than a
	// permission, which is why it is not named Allow.
	RequireSingleSocket bool
}

// validate reports the two ways a reference value set can be wrong in the
// direction that matters, and is the single place either is decided.
//
// An empty set admits nobody, which is a configuration mistake every time.
//
// A reference value with no launch measurement admits *everybody*: it names no
// image, so every authentic platform matches it, and a set holding one is
// strictly weaker than its author can have intended. That is the failure worth
// catching loudly, because it does not announce itself — every handshake
// succeeds and nothing looks wrong.
//
// Both [New] and the loader in refvalsfile.go call this, so a set that would
// admit everybody is refused whether it was built in memory or read off the
// config device. The width of a launch measurement is deliberately not checked:
// see [ReferenceValue.LaunchMeasurement].
func (set ReferenceValueSet) validate() error {
	if len(set.Values) == 0 {
		return errors.New("the reference value set is empty; it would admit nobody")
	}
	for i, rv := range set.Values {
		if len(rv.LaunchMeasurement) == 0 {
			return fmt.Errorf("reference value %d has no launch measurement; it would admit every authentic platform", i)
		}
	}
	return nil
}
