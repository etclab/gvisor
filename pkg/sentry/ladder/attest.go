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
)

// This file is the ladder rung-3 attested label: the stamp the sentry writes on
// every message leaving a peer channel, and the stamp it applies to every message
// arriving on one. Gated entirely on --ladder-attest.
//
// What the runtime is doing here, and why it is the runtime doing it. The stamp
// carries three fields. Two of them -- identity and grants -- are launcher
// assertions: the runtime learns them from the container's OCI spec and it is the
// launcher, not the sandbox, that fixes them. The third, the taint bit, is a fact
// only the runtime holds. All three become unforgeable for the same reason, which
// is not that they are signed: it is that the agent's bytes never touch them. The
// stamp is prepended to the iovec below the syscall boundary, so the "message" the
// application composed is only ever the tail of what the peer receives.
//
// That argument depends on rung 0 and rung 2, and the dependency is the point:
//
//   - rung 0's topology (one --internal docker network per task, no shared mount)
//     is why the peer channel is the ONLY route to a peer. A stamp on one path
//     means nothing if a second path exists.
//   - rung 2's monotonic taint bit is what the taint field reads, and rung 2's
//     write gate is what the receiver does about it. Rung 3 adds no new denial:
//     inheriting the sender's taint is the whole acceptance policy, and rung 2's
//     existing gate on /broker refuses what follows.
//
// Deliberately absent: signatures, keys, nonces, replay protection. Identity here
// means "the runtime on this host says so", which is exactly as strong as the host
// and no stronger. Across hosts it would mean nothing. See rung3/README.md.

// StampLen is the fixed width of a stamp, in bytes. Fixed rather than
// delimiter-terminated so that both halves of the hook are stateless: the sender
// prepends exactly this many bytes, and the receiver reads exactly this many. A
// delimiter would need the receiver to buffer across a partial read, and a partial
// read is precisely where a parser gets confused.
//
// THIS CONSTANT IS A WIRE CONTRACT. Three implementations must agree on it, and
// nothing at runtime detects a disagreement -- a receiver reading the wrong width
// silently sees a stamp as body or a body as stamp:
//
//	pkg/sentry/ladder/attest.go             StampLen  (this file, the writer)
//	ladder/common/postbox/postbox.py        STAMP_LEN (the relay)
//	ladder/common/fake_agent/fake_agent.py  STAMP_LEN (the reader, and the forger)
//
// Widened from 128 to 256 by rung 4: the chain and origin fields do not fit in
// 128 bytes once a chain is three hops long and an origin is an absolute path.
const StampLen = 256

// stampPrefix begins every stamp. A message that does not start with it carries no
// stamp; a message that does may still be a forgery written by an application, and
// the reason it cannot be mistaken for the real one is position, not content -- the
// runtime's stamp occupies the first StampLen bytes of the message, and on a
// SOCK_SEQPACKET channel an application cannot create a message boundary.
const stampPrefix = "LADDER-STAMP "

// ConfigureAttest installs the sandbox's rung-3 message-labeling policy. Like
// Configure it must be called once, on the boot goroutine, before any application
// task exists; policy is unsynchronized and immutable thereafter.
func ConfigureAttest(enabled bool, peers []string, identity, grants string) {
	policy.attest = enabled
	policy.peers = normalize(peers)
	policy.identity = strings.TrimSpace(identity)
	policy.grants = strings.TrimSpace(grants)
	if !enabled {
		return
	}
	if policy.identity == "" {
		// A stamp with no sender is worse than no stamp: it looks authoritative and
		// says nothing. Refusing to boot would be the honest alternative, but this
		// is a research prototype and a loud sandbox beats a dead one.
		policy.identity = "unnamed"
		log.Warningf("LADDER ATTEST: --ladder-attest with no --ladder-identity; stamping as %q", policy.identity)
	}
	log.Warningf("LADDER attest enabled: identity=%s grants=%s peers=%s",
		policy.identity, policy.grants, strings.Join(policy.peers, ","))
	if !policy.enabled {
		// Rung 3's acceptance policy IS rung 2's gate. Without --ladder-taint the
		// stamp is still written and still true, but a receiver that inherits taint
		// has nothing that acts on it, so the confused deputy is described and not
		// prevented. Say so rather than appearing to enforce.
		log.Warningf("LADDER ATTEST: --ladder-attest without --ladder-taint; messages are stamped, " +
			"but an inherited taint gates nothing because no sink is privileged")
	}
}

// AttestEnabled reports whether --ladder-attest was set.
func AttestEnabled() bool {
	return policy.attest
}

// Active reports whether any ladder rung needs a socket path resolved. The path
// resolver in pkg/sentry/socket/unix is shared by rung 2's sink labeling and rung
// 3's peer labeling, and either flag alone must be enough to run it.
func Active() bool {
	return policy.enabled || policy.attest
}

// PeerChannel reports whether path names a mediated agent-to-agent channel.
func PeerChannel(path string) bool {
	if !policy.attest {
		return false
	}
	for _, prefix := range policy.peers {
		if under(prefix, path) {
			return true
		}
	}
	return false
}

// Identity returns the name this sandbox stamps on its messages.
func Identity() string {
	return policy.identity
}

// Grants returns the capability set this sandbox stamps on its messages.
func Grants() string {
	return policy.grants
}

// Stamp returns the StampLen-byte label to prepend to an outbound message on a
// peer channel, or nil if there is nothing to stamp.
//
// It reads the taint bit at send time rather than at connect time on purpose: a
// sandbox that connects to its peer, then reads the untrusted page, then sends,
// must send taint=1. A connect-time stamp would say taint=0 and be a lie the
// runtime told itself.
func Stamp(channel string) []byte {
	if !policy.attest {
		return nil
	}
	bit := 0
	if Tainted() {
		bit = 1
	}
	// v=2 when rung 4 is on, and the two extra fields come last. A rung-3 stamp is
	// then byte-for-byte what it was, and a receiver that only knows v=1 reads the
	// fields it knows and ignores the rest -- parseStamp is keyed on field names,
	// not positions.
	version := "v=1"
	if policy.chain {
		version = "v=2"
	}
	text := stampPrefix + version + " sender=" + policy.identity +
		" taint=" + itoa(bit) + " grants=" + policy.grants + chainFields()
	if len(text) > StampLen {
		// Truncation loses rung 4's chain and origin first, then grant names, and
		// never the sender or the taint bit, because those come first. Every one of
		// those losses is a label that under-claims, which is the safe direction.
		text = text[:StampLen]
	}
	out := make([]byte, StampLen)
	for i := range out {
		out[i] = ' '
	}
	copy(out, text)
	log.Warningf("LADDER STAMP channel=%s sender=%s taint=%d grants=%s%s",
		channel, policy.identity, bit, policy.grants, chainFields())
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return "1"
}

// Ingest applies the stamp on an inbound message received on a peer channel.
//
// bufs are the destination buffers the endpoint just filled and n is how many
// bytes it wrote across them; only the first StampLen bytes are examined. Nothing
// is stripped -- the application receives the stamp along with the body, which is
// how the demo can print what the receiver was actually handed. The security
// effect happens here, before recv() returns: if the sender was tainted, this
// sandbox is tainted, and rung 2's gate applies to it from now on.
//
// This is the ONLY way a sandbox's taint bit can be set by something other than
// its own read, and it is still monotonic and still one-way. There is no Untaint
// here either.
func Ingest(bufs [][]byte, n int64, channel string) {
	if !policy.attest || n < StampLen {
		return
	}
	head := make([]byte, 0, StampLen)
	remaining := n
	for _, b := range bufs {
		if len(head) >= StampLen || remaining <= 0 {
			break
		}
		if int64(len(b)) > remaining {
			b = b[:remaining]
		}
		if need := StampLen - len(head); len(b) > need {
			b = b[:need]
		}
		head = append(head, b...)
		remaining -= int64(len(b))
	}
	if len(head) < StampLen || !strings.HasPrefix(string(head), stampPrefix) {
		// No stamp. Either the peer is the postbox answering a control message, or
		// --ladder-attest was off when the message was sent. Rung 3 does not refuse
		// it here: "unstamped is undeliverable" is enforced by the relay and by
		// rung 0's topology, not by this hook. See rung3/README.md, claim 5.
		return
	}
	sender, taint, chain, origin := parseStamp(string(head))
	// Rung 4, and it happens before the taint check on purpose: a message extends
	// the chain whether or not it is tainted. A clean hop is still a hop, and a
	// receiver that only recorded the tainted ones would report a chain with holes
	// in it.
	Extend(chain, origin, sender)
	if taint != "1" {
		return
	}
	log.Warningf("LADDER INHERIT sender=%s channel=%s: accepting a message stamped tainted taints this sandbox",
		sender, channel)
	Taint("peer:"+sender, "recv")
}

// parseStamp pulls the fields this sandbox acts on out of a stamp: rung 3's
// sender and taint, and rung 4's chain and origin. Keyed on field names rather
// than positions, so a v=1 stamp from a peer whose runtime does not have rung 4
// parses fine and simply yields no chain.
func parseStamp(stamp string) (sender, taint string, chain []string, origin string) {
	for _, token := range strings.Fields(stamp) {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		switch key {
		case "sender":
			sender = value
		case "taint":
			taint = value
		case "chain":
			chain = strings.Split(value, chainSep)
		case "origin":
			origin = value
		}
	}
	if sender == "" {
		sender = "unnamed"
	}
	return sender, taint, chain, origin
}

// AttestStatus describes the sandbox's rung-3 labeling state for the host-side
// control call.
type AttestStatus struct {
	// Enabled mirrors --ladder-attest.
	Enabled bool

	// Identity and Grants are what this sandbox stamps on its messages.
	Identity string
	Grants   string

	// PeerChannels are the configured mediated channels.
	PeerChannels []string
}

// CurrentAttestStatus returns the sandbox's rung-3 labeling state.
func CurrentAttestStatus() AttestStatus {
	return AttestStatus{
		Enabled:      policy.attest,
		Identity:     policy.identity,
		Grants:       policy.grants,
		PeerChannels: policy.peers,
	}
}
