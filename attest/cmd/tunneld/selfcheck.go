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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"gvisor.dev/gvisor/attest"
)

// The self-check: this guest asking its own platform for evidence and judging
// it with its own reference value set, out loud, before any peer arrives.
//
// # Why a guest should judge itself
//
// A reference value set is a prediction. Until some peer dials in and is
// admitted or refused, nothing has compared that prediction against the machine
// it was written for, and the first thing that does compare them is a handshake
// whose failure looks like a dozen other failures. Two guests that both refuse
// each other tell an operator that something is wrong and nothing about what.
//
// This makes the comparison first, locally, where exactly one thing is under
// test: does the set this guest was handed admit the platform this guest is on?
// A MATCH means the predicted RTMR2 is the register the hardware reports and
// the provider's constants are the ones the set pins, so any later refusal is
// about the peer. A refusal here names which register differed, on the console,
// which is the only diagnostic surface a measured guest has (spec, user story
// 48).
//
// # It proves nothing to a peer, and is not meant to
//
// A guest verifying its own evidence is a machine agreeing with itself: the
// evidence, the set and the verdict are all on one side of the trust boundary,
// and an adversary who could forge the first could forge the third. The value
// is diagnostic, not evidential. What *is* evidential is the quote it prints:
// a verifier on a workstation can take those bytes, judge them against the same
// signed set with attest/cmd/verify-evidence, and reach the verdict
// independently. That is why the evidence is written to the console in base64
// — a measured guest has no other channel, and this is the one the record
// keeps (docs/snp/cloud/tdx/guest-evidence-tdx.sh does the same thing by hand).
//
// # The key it binds to is thrown away
//
// The binding covers a public key so that evidence cannot be replayed against
// somebody else's key (ADR-0002). This check has no key of its own — the one
// the tunnel uses lives inside ratls and is not for lending — so it generates
// one, uses it for this single acquisition, and drops it. The consequence is
// worth stating: the printed quote is bound to a key nobody holds, so it can
// establish no tunnel and authenticate no channel. It is a statement about a
// platform and only that.

// performSelfCheck acquires evidence from this platform and judges it against
// the reference value set at setPath.
func performSelfCheck(ctx context.Context, acquirer attest.Acquirer, verifier attest.Verifier, setPath string, author ed25519.PublicKey, policyDigest attest.PolicyDigest, logf func(string, ...any)) error {
	set, err := attest.LoadReferenceValueSetFile(setPath, author)
	if err != nil {
		return fmt.Errorf("loading %s for the self-check: %w", setPath, err)
	}
	verification, err := attest.New(verifier, set)
	if err != nil {
		return fmt.Errorf("building the self-check verification: %w", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating the throwaway key the evidence binds to: %w", err)
	}
	binding := attest.Binding{PublicKey: pub, Context: attest.BindingContextV2, PolicyDigest: policyDigest}

	acquireCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	started := time.Now()
	evidence, err := acquirer.Acquire(acquireCtx, binding.CallerSuppliedBytes())
	if err != nil {
		return fmt.Errorf("asking this platform for evidence: %w", err)
	}
	logf("SELFCHECK acquired %d bytes of %s evidence in %s, bound to a throwaway key and to policy digest %s",
		len(evidence.Bytes), evidence.Vendor, time.Since(started).Round(time.Millisecond), policyDigest)

	attested, verr := verification.Verify(acquireCtx, evidence, binding)
	if verr == nil {
		logf("SELFCHECK VERDICT ADMITTED: this platform satisfies this sandbox's own reference value set")
		logf("SELFCHECK measurement %s", hex.EncodeToString(attested.Claims.LaunchMeasurement))
		if c := attested.Claims.TDX; c != nil {
			logf("SELFCHECK mrtd  %s", hex.EncodeToString(c.MRTD))
			logf("SELFCHECK rtmr0 %s", hex.EncodeToString(c.RTMR0))
			logf("SELFCHECK rtmr1 %s", hex.EncodeToString(c.RTMR1))
			logf("SELFCHECK rtmr2 %s", hex.EncodeToString(c.RTMR2))
			logf("SELFCHECK tcb   status=%s evaluation=%d fmspc=%s attributes=%x",
				c.TCBStatus, c.TCBEvaluationDataNumber, c.FMSPC, c.TDAttributes)
		}
	} else {
		// Not a fatal error for the process: a guest that cannot admit itself
		// can still be dialled by a peer whose set is right, and refusing to
		// serve here would turn a diagnostic into an outage. It is said as
		// loudly as a console can say anything.
		logf("SELFCHECK VERDICT REFUSED reason=%s: %v", attest.ReasonOf(verr), verr)
		logUnverifiedRegisters(evidence, logf)
	}

	// The bytes themselves, so the verdict above can be reached again by
	// somebody who trusts none of the machinery that printed it.
	logf("SELFCHECK EVIDENCE BEGIN (base64 of %d bytes; feed it to attest/cmd/verify-evidence)", len(evidence.Bytes))
	encoded := base64.StdEncoding.EncodeToString(evidence.Bytes)
	for len(encoded) > 0 {
		n := selfCheckBase64Width
		if n > len(encoded) {
			n = len(encoded)
		}
		logf("SELFCHECK EVIDENCE %s", encoded[:n])
		encoded = encoded[n:]
	}
	logf("SELFCHECK EVIDENCE END")
	logf("SELFCHECK PUBLIC KEY %s (throwaway; the evidence is bound to it and to nothing else)", hex.EncodeToString(pub))
	return verr
}

const (
	// selfCheckTimeout bounds the whole check. Acquisition on TDX is a TDCALL
	// and a quoting round trip: milliseconds normally, and this is only here so
	// that a platform that never answers does not hold the start open.
	selfCheckTimeout = 30 * time.Second

	// selfCheckBase64Width keeps each console line short enough that a serial
	// capture with a line limit does not truncate one in the middle.
	selfCheckBase64Width = 100
)

// The TDX quote's own layout, so that a refused self-check can still say which
// register differed.
//
// This reads the registers out of the raw bytes rather than out of
// [attest.Claims], and it does so only on the refusal path, because on that
// path there are no claims: a verifier that refused evidence returns a refusal
// and nothing else, which is the right shape — claims a verifier would not
// stand behind are not claims. The bytes are still bytes, though, and an
// operator staring at a console needs the number. These are the same offsets
// docs/snp/cloud/tdx/parse-tdx-quote.py reads, and they are unauthenticated
// here by construction: what makes them trustworthy is the signature the
// verifier checked, and on this path it did not hold.
const (
	tdxQuoteHeader = 48
	tdxQuoteBody   = 584
	tdxMRTDAt      = 136
	tdxRTMR0At     = 328
	tdxRTMR1At     = 376
	tdxRTMR2At     = 424
	tdxRegisterLen = 48
)

// logUnverifiedRegisters prints the measurement registers a TDX quote carries,
// saying plainly that nothing checked them.
func logUnverifiedRegisters(evidence attest.Evidence, logf func(string, ...any)) {
	if evidence.Vendor != attest.VendorIntelTDX || len(evidence.Bytes) < tdxQuoteHeader+tdxQuoteBody {
		return
	}
	body := evidence.Bytes[tdxQuoteHeader : tdxQuoteHeader+tdxQuoteBody]
	at := func(off int) string { return hex.EncodeToString(body[off : off+tdxRegisterLen]) }
	logf("SELFCHECK (unverified, read straight out of the quote's bytes) mrtd  %s", at(tdxMRTDAt))
	logf("SELFCHECK (unverified) rtmr0 %s", at(tdxRTMR0At))
	logf("SELFCHECK (unverified) rtmr1 %s", at(tdxRTMR1At))
	logf("SELFCHECK (unverified) rtmr2 %s", at(tdxRTMR2At))
}
