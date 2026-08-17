// replay.go - the sequence window, and the honest account of what it is worth.
//
// Rung 5a, spec section 2 ("Converse"): every stream begins with a stamped envelope
// carrying a "per-(sender, peer) monotonic sequence number", and "replayed stamps are
// rejected before any payload is processed".
//
// # What actually stops a replay
//
// Two independent things do, and they stop different attacks. Saying which is which
// matters, because the weaker one is the one that looks like the answer:
//
//	the channel binding (envelope.go)  stops a replay onto a DIFFERENT connection. The
//	                                   binding is exported keying material, so a captured
//	                                   envelope is worthless anywhere else the moment the
//	                                   handshake differs. This is the load-bearing check.
//
//	this file                          stops a replay onto the SAME connection -- a
//	                                   sender's own bytes fed back to the receiver over a
//	                                   channel that is still up. Narrower, and still worth
//	                                   having, because "the same connection" includes the
//	                                   sending proxy retrying and an enrolled-but-buggy
//	                                   peer looping.
//
// The demo runs both cases and asserts them separately, because collapsing them would
// let a reader believe the sequence number is doing work the exporter is doing.
//
// # Why 0-RTT is off
//
// Not implemented here, but this is where it belongs in the reader's mind: QUIC 0-RTT's
// known weakness is exactly replay of the first flight, and the privileged requests this
// substrate carries are precisely what must not be replayable. Section 2 turns it off and
// says the stream design gets the latency back without it -- which CONTROL measures
// rather than asserts.
//
// # The bound
//
// Sliding window, `WindowSize` slots, highest sequence seen plus a bitmap of the ones
// below it that have already arrived. Memory is O(peers), not O(messages), which is the
// property that matters: a replay cache that grows with traffic is a denial-of-service
// waiting for a sender that never stops. Anything more than WindowSize below the highest
// is rejected outright -- there is no state to consult, so the answer is "too old",
// which fails closed.
package main

import (
	"fmt"
	"sync"
	"time"
)

// WindowSize is how far out of order an exchange may arrive and still be accepted. QUIC
// streams on one connection have no cross-stream ordering guarantee, so some slack is
// needed; 1024 is far more than any burst this demo fires and is one 128-byte bitmap per
// peer pair.
const WindowSize = 1024

type window struct {
	highest int64
	seen    []uint64 // bitmap of the WindowSize sequences at or below highest
}

// NextSeq returns the next sequence number a sender should claim for one peer pair.
//
// Wall-clock milliseconds rather than a counter from 1, and the reason is a collision
// that is easy to hit and confusing to debug: several PROCESSES send under the same
// (host, peer) identity -- a proxy, the bench, the attack harness -- and a counter that
// restarts at 1 in each of them puts the second process's traffic below the first's
// window, where it is rejected as "too old" rather than for the reason under test. Both
// halves are needed: max(prev+1, now) keeps it strictly monotonic within a process and
// keeps every process in the same regime as every other.
func NextSeq(prev int64) int64 {
	now := time.Now().UnixMilli()
	if prev >= now {
		return prev + 1
	}
	return now
}

// ReplayCache tracks sequence freshness per (from_host, from_peer).
type ReplayCache struct {
	mu       sync.Mutex
	byPeer   map[string]*window
	rejected int
	accepted int
}

// NewReplayCache returns an empty cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{byPeer: map[string]*window{}}
}

func key(host, peer string) string { return host + "/" + peer }

// Accept records a sequence number and reports whether it is fresh. The error carries
// the rejection code so the caller can log it as evidence.
func (c *ReplayCache) Accept(host, peer string, seq int64) error {
	if seq <= 0 {
		return reject(CodeReplayed, "envelope carries no sequence number")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	k := key(host, peer)
	w := c.byPeer[k]
	if w == nil {
		w = &window{highest: 0, seen: make([]uint64, WindowSize/64)}
		c.byPeer[k] = w
	}

	switch {
	case seq > w.highest:
		// Advance. Everything that scrolls off the bottom of the window becomes
		// permanently "too old", which is the fail-closed direction.
		shift := seq - w.highest
		if shift >= WindowSize {
			for i := range w.seen {
				w.seen[i] = 0
			}
		} else {
			shiftBitmap(w.seen, int(shift))
		}
		w.highest = seq
		setBit(w.seen, 0)
		c.accepted++
		return nil

	case w.highest-seq >= WindowSize:
		c.rejected++
		return reject(CodeReplayed,
			"sequence %d is more than %d behind the highest seen (%d) from %s/%s",
			seq, WindowSize, w.highest, host, peer)

	default:
		off := int(w.highest - seq)
		if getBit(w.seen, off) {
			c.rejected++
			return reject(CodeReplayed,
				"sequence %d from %s/%s has already been delivered on this channel", seq, host, peer)
		}
		setBit(w.seen, off)
		c.accepted++
		return nil
	}
}

// Stats is what the demo prints to show the cache is bounded.
func (c *ReplayCache) Stats() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("peers=%d window=%d accepted=%d rejected=%d bytes~%d",
		len(c.byPeer), WindowSize, c.accepted, c.rejected, len(c.byPeer)*(WindowSize/8+16))
}

func setBit(bits []uint64, i int) {
	if i < 0 || i >= len(bits)*64 {
		return
	}
	bits[i/64] |= 1 << uint(i%64)
}

func getBit(bits []uint64, i int) bool {
	if i < 0 || i >= len(bits)*64 {
		return false
	}
	return bits[i/64]&(1<<uint(i%64)) != 0
}

// shiftBitmap moves every recorded sequence n slots further into the past.
func shiftBitmap(bits []uint64, n int) {
	words, rem := n/64, uint(n%64)
	for i := len(bits) - 1; i >= 0; i-- {
		var v uint64
		if i-words >= 0 {
			v = bits[i-words] << rem
			if rem > 0 && i-words-1 >= 0 {
				v |= bits[i-words-1] >> (64 - rem)
			}
		}
		bits[i] = v
	}
}
