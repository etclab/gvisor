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

// A Reason names one distinct way evidence can fail to satisfy a reference
// value set.
//
// Reasons are typed so that a test can assert on which check refused a peer and
// an operator can read it in a log. They are not a caller-facing vocabulary:
// see [Refusal] for why a caller learns none of this.
type Reason int

// The refusal taxonomy. Each constant is a distinct way of being wrong, and no
// two failures share one.
const (
	// ReasonNone is the zero value: not a refusal. [ReasonOf] returns it for a
	// nil error and for an error that is not a refusal.
	ReasonNone Reason = iota

	// ReasonNoEvidence is a peer that presented no evidence at all. It is its
	// own reason rather than a parse failure because a non-confidential VM must
	// be refused, not treated as unknown.
	ReasonNoEvidence

	// ReasonUnsupportedVendor is evidence from hardware no verifier here
	// implements. Guessing at the format of evidence whose vendor is unknown is
	// how a parser becomes an attack surface.
	ReasonUnsupportedVendor

	// ReasonMalformedEvidence is evidence that does not parse, or that
	// contradicts itself — a report whose committed and current TCB disagree,
	// or whose reported TCB is not the one its endorsement key was issued for.
	ReasonMalformedEvidence

	// ReasonChainNotRooted is evidence whose signature does not chain to the
	// vendor's root. A bad signature and a chain that does not root are one
	// reason because they answer one question: is this evidence authentic. A
	// peer that fails it has forged something, and which byte it forged is not
	// a distinction worth drawing. It also covers a chain or collateral that is
	// not valid at the time verification runs — an expired VCEK, or Intel
	// collateral past its nextUpdate — since neither can be judged rooted now;
	// the detail says which.
	ReasonChainNotRooted

	// ReasonMeasurementNotInSet is authentic evidence whose launch measurement
	// appears in no reference value in the set. This is the refusal that keeps
	// a modified image out.
	ReasonMeasurementNotInSet

	// ReasonTCBBelowFloor is a platform below the reference value's TCB floor.
	// This is the refusal that keeps a known-vulnerable firmware level out.
	ReasonTCBBelowFloor

	// ReasonPolicyMismatch is a guest whose policy claims a capability the
	// reference value does not permit. This is the refusal that keeps a
	// debug-enabled guest out.
	ReasonPolicyMismatch

	// ReasonBindingMismatch is evidence whose caller-supplied bytes are not the
	// digest of the public key the peer presented. This is the refusal that
	// stops a genuine report being replayed against a different key.
	ReasonBindingMismatch

	// ReasonUnknownBindingContext is a peer claiming a binding context this
	// verifier does not understand (ADR-0002).
	ReasonUnknownBindingContext
)

// reasonNames are the strings that appear in operator logs. They are not
// stable identifiers and nothing parses them.
var reasonNames = map[Reason]string{
	ReasonNone:                  "none",
	ReasonNoEvidence:            "no evidence presented",
	ReasonUnsupportedVendor:     "unsupported vendor",
	ReasonMalformedEvidence:     "malformed evidence",
	ReasonChainNotRooted:        "evidence does not chain to the vendor root",
	ReasonMeasurementNotInSet:   "launch measurement not in the reference value set",
	ReasonTCBBelowFloor:         "platform below the TCB floor",
	ReasonPolicyMismatch:        "guest policy not permitted by the reference value",
	ReasonBindingMismatch:       "caller-supplied bytes do not match the presented public key",
	ReasonUnknownBindingContext: "unrecognised binding context",
}

// String returns an operator-facing description of r.
func (r Reason) String() string {
	if s, ok := reasonNames[r]; ok {
		return s
	}
	return fmt.Sprintf("Reason(%d)", int(r))
}

// ErrRefused is what a caller learns when verification fails, and all a caller
// learns. Every [Refusal] matches it under [errors.Is].
var ErrRefused = errors.New("attest: verification failed")

// A Refusal is a verdict of refused, carrying the [Reason] that produced it.
//
// Its Error is deliberately the same sentence for every reason. A peer that can
// tell a measurement mismatch from a TCB floor can walk the reference value set
// one field at a time and learn what to target next; a peer that can only tell
// that it was refused learns nothing it did not already know. The reason
// therefore reaches tests through [ReasonOf] and operators through
// [Refusal.Detail], and reaches the wire through nothing at all.
//
// Refusal deliberately does not implement Unwrap. Wrapping would put the
// underlying library's error text one %w away from a log line that goes to a
// peer, and the undifferentiated surface would then hold only by everyone
// remembering it does.
type Refusal struct {
	reason Reason
	detail string
}

// Refuse builds a refusal with an operator-facing detail. A [Verifier]
// implementation calls it for every failure it reports; it is exported for that
// reason and for no other.
func Refuse(reason Reason, format string, args ...any) *Refusal {
	return &Refusal{reason: reason, detail: fmt.Sprintf(format, args...)}
}

// Error returns the undifferentiated failure, identical for every reason.
func (r *Refusal) Error() string { return ErrRefused.Error() }

// Is reports that every refusal matches [ErrRefused], so that a caller with no
// interest in the reason can write errors.Is(err, attest.ErrRefused).
func (r *Refusal) Is(target error) bool { return target == ErrRefused }

// Reason returns the check that refused.
func (r *Refusal) Reason() Reason { return r.reason }

// Detail returns operator-facing context for the log: which value did not
// match, which floor was not met. It is never returned by Error, never sent to
// a peer, and never shown to an agent.
func (r *Refusal) Detail() string { return r.detail }

// LogString is the line an operator reads on the serial console. That console
// is visible to the host by construction — the host already sees the traffic
// and controls the platform, so this leaks nothing it does not have, but it is
// said out loud here rather than left as an accident someone later mistakes for
// a confidential channel.
func (r *Refusal) LogString() string {
	if r.detail == "" {
		return fmt.Sprintf("verification refused: %s", r.reason)
	}
	return fmt.Sprintf("verification refused: %s: %s", r.reason, r.detail)
}

// ReasonOf returns the reason err was refused, or [ReasonNone] if err is nil or
// is not a refusal. Tests assert on this; nothing on the wire depends on it.
func ReasonOf(err error) Reason {
	var r *Refusal
	if errors.As(err, &r) {
		return r.reason
	}
	return ReasonNone
}
