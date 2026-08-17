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

package ladder

import (
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// This file is the ladder rung-4 chain label: the two fields rung 3's stamp does
// not carry, and the accumulation rule that keeps them true across an arbitrary
// number of hops. Gated entirely on --ladder-chain.
//
// Rung 3's stamp describes the IMMEDIATE sender: its name, its taint bit, its
// declared grants. That is enough for one hop and not enough for three. A receiver
// three hops down learns that its caller is clean and appropriately capable, and
// learns nothing about where the instruction it is being handed actually came
// from. Rung 4 adds:
//
//	chain=reader>orchestrator   the hops the message has passed through, in order
//	origin=/untrusted/page.txt  the first untrusted source anywhere upstream
//
// Both accumulate in the SENTRY, on the receive path, from the stamp of the
// message that arrived. An application cannot contribute to either: the fields it
// reads are in bytes its own kernel wrote, and the fields it writes are appended
// below the syscall boundary by Stamp.
//
// Two properties, and the second is the one worth arguing about:
//
//   - Monotonic, like the taint bit. A hop only ever appends; there is no call
//     that shortens a chain or clears an origin. A sandbox that accepts messages
//     from two upstreams accumulates the union of their chains, in arrival order.
//     Over-approximation is sound here for the same reason it is sound for taint:
//     a chain that names a hop the instruction did not actually traverse costs
//     precision, while a chain that omits one is a false clean.
//
//   - NOT load-bearing for rung 4's denials, and the README says so. The
//     capability arithmetic that refuses an out-of-scope write lives in the
//     broker, and the broker could assemble this same hop list from the relay it
//     already mediates. What the runtime uniquely provides is that the chain is
//     visible INSIDE the receiving sandbox without a central relay's cooperation,
//     and readable from the HOST over the control socket. Rung 4's flag row in
//     specs/00-conventions.md is corrected on exactly this point.

// chainSep separates hops in the stamp's chain field. A single byte, not a comma:
// the grants field is already comma-separated and a reader splitting a stamp on
// commas should not be able to confuse a hop for a tool.
const chainSep = ">"

// chainMu protects chainHops and chainOrigin. Unlike policy, which is written
// once before the application starts, these are written on the receive path and
// read on the send path, so they need a lock. Kept as package-level vars rather
// than fields of a struct to match ladder.go's sourceMu.
var chainMu sync.Mutex

// chainHops are the upstream hops, in the order they were first seen, NOT
// including this sandbox. ChainHops appends the local identity.
var chainHops []string

// chainOrigin is the first untrusted source anywhere upstream. Empty until an
// inbound stamp carries one; the local taint source is consulted separately, by
// Origin.
var chainOrigin string

// ConfigureChain installs the sandbox's rung-4 chain policy. Like Configure and
// ConfigureAttest it must be called once, on the boot goroutine, before any
// application task exists.
func ConfigureChain(enabled bool) {
	policy.chain = enabled
	if !enabled {
		return
	}
	log.Warningf("LADDER chain enabled: outbound stamps carry chain and origin; inbound chains accumulate")
	if !policy.attest {
		// Without rung 3 there is no stamp to carry the chain in and no receive
		// hook to accumulate one from. Say so rather than appearing to enforce.
		log.Warningf("LADDER CHAIN: --ladder-chain without --ladder-attest; nothing is stamped, " +
			"so no chain is written and none is read")
	}
}

// ChainEnabled reports whether --ladder-chain was set.
func ChainEnabled() bool {
	return policy.chain
}

// Extend accumulates the chain and origin of an inbound stamped message. Called
// from Ingest, on the receive path, before recv() returns.
//
// sender is the stamp's sender field; it is appended after the inbound chain
// because a sender that omitted itself from its own chain must not be able to
// disappear from the record. In practice the two agree -- the sending sentry
// appends its own identity in Stamp -- and a disagreement is logged rather than
// resolved, because the honest reading of one is "the peer's runtime is not
// running this rung".
func Extend(inChain []string, inOrigin, sender string) {
	if !policy.chain {
		return
	}
	chainMu.Lock()
	defer chainMu.Unlock()

	before := strings.Join(chainHops, chainSep)
	for _, hop := range append(inChain, sender) {
		hop = strings.TrimSpace(hop)
		if hop == "" {
			continue
		}
		known := false
		for _, seen := range chainHops {
			if seen == hop {
				known = true
				break
			}
		}
		if !known {
			chainHops = append(chainHops, hop)
		}
	}
	if chainOrigin == "" && inOrigin != "" && inOrigin != "-" {
		chainOrigin = inOrigin
	}
	after := strings.Join(chainHops, chainSep)
	if after != before {
		log.Warningf("LADDER CHAIN extend sender=%s inbound=%q origin=%q chain=%s",
			sender, strings.Join(inChain, chainSep), chainOrigin, after)
	}
}

// ChainHops returns the hop list this sandbox stamps on an outbound message: the
// accumulated upstream hops followed by this sandbox's own identity.
func ChainHops() []string {
	chainMu.Lock()
	defer chainMu.Unlock()
	out := make([]string, 0, len(chainHops)+1)
	out = append(out, chainHops...)
	for _, hop := range out {
		if hop == policy.identity {
			// Already in the chain: a cycle, or a second message from a peer that
			// had already named us. Appending again would grow the field without
			// adding information.
			return out
		}
	}
	return append(out, policy.identity)
}

// Origin returns the first untrusted source anywhere upstream of this sandbox,
// or the local path that tainted it, or "-" if neither has happened.
//
// The local taint source is consulted second and not first: a sandbox that both
// received tainted content and read its own labeled file reports the upstream
// origin, because that is the one its peer could not have told it about.
func Origin() string {
	chainMu.Lock()
	origin := chainOrigin
	chainMu.Unlock()
	if origin != "" {
		return origin
	}
	if local := Source(); local != "" {
		return local
	}
	return "-"
}

// chainFields returns the stamp fragment rung 4 appends, or "" when the rung is
// off. Appended AFTER rung 3's fields so that a rung-3 stamp is byte-identical to
// what it was, and so that truncation of an over-long stamp eats rung 4's fields
// before it eats the sender or the taint bit.
func chainFields() string {
	if !policy.chain {
		return ""
	}
	return " chain=" + strings.Join(ChainHops(), chainSep) + " origin=" + Origin()
}

// ChainStatus describes the sandbox's rung-4 provenance state for the host-side
// control call.
type ChainStatus struct {
	// Enabled mirrors --ladder-chain.
	Enabled bool

	// Hops is what this sandbox would stamp: upstream hops plus its identity.
	Hops []string

	// Origin is the first untrusted source anywhere upstream, or "-".
	Origin string
}

// CurrentChainStatus returns the sandbox's rung-4 provenance state.
func CurrentChainStatus() ChainStatus {
	return ChainStatus{
		Enabled: policy.chain,
		Hops:    ChainHops(),
		Origin:  Origin(),
	}
}
