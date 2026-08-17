// stamp.go - reading the sentry's stamp, and the line this file must not cross.
//
// The 256-byte stamp is written by the SENDING SANDBOX'S KERNEL
// (pkg/sentry/ladder/attest.go). This proxy carries it verbatim inside the federation
// envelope and hands it out verbatim on the far side. It never writes one, never
// rewrites one, and never invents a field -- if a host-side process could manufacture a
// stamp, every claim rungs 3 and 4 make would be circular, which is exactly the argument
// that put the stamping in the sentry instead of in a host-side proxy in the first place
// (rung3/README.md, and the verdict in ladder/README.md).
//
// READING one is a different act, and it is what a policy layer is for. The recycle
// policy needs to know whether the standing service it fronts has become tainted, and
// the runtime is the only thing that can answer that. Rung 3 rejected the host-side
// stamping design partly because the alternative was polling `runsc ladder-status` per
// message, which is root-only and live-sandbox-only; here the answer arrives for free,
// on a message that was going to pass through this process anyway.
//
// The distinction to hold on to: this file may believe the stamp. It may not produce one.
package main

import (
	"strings"
)

// StampLen is a WIRE CONTRACT shared by four implementations now, and nothing detects a
// disagreement at runtime -- a reader using the wrong width silently sees a stamp as
// body or a body as stamp. All four move together or none do:
//
//	pkg/sentry/ladder/attest.go       StampLen   (the writer)
//	common/postbox/postbox.py         STAMP_LEN  (the relay)
//	common/fake_agent/fake_agent.py   STAMP_LEN  (the reader, and the forger)
//	common/fed/stamp.go               StampLen   (this file, the federation carrier)
const StampLen = 256

// StampPrefix is how a stamp is recognised.
const StampPrefix = "LADDER-STAMP "

// StampField pulls one space-separated key=value field out of a stamp, or "" if absent.
// Keyed on names rather than positions, like attest.go's parseStamp, so a stamp written
// by a peer whose runtime predates a field simply yields nothing for it.
func StampField(stamp []byte, name string) string {
	if len(stamp) == 0 {
		return ""
	}
	for _, token := range strings.Fields(string(stamp)) {
		key, value, found := strings.Cut(token, "=")
		if found && key == name {
			return value
		}
	}
	return ""
}

// StampTainted is the recycle policy's only question of the runtime.
func StampTainted(stamp []byte) bool { return StampField(stamp, "taint") == "1" }

// StampSender is the sandbox identity the runtime wrote. Used only to log it next to the
// identity the proxy already knew from which gateway the message came in on -- the same
// cross-check the postbox does, one layer up.
func StampSender(stamp []byte) string { return StampField(stamp, "sender") }

// StampSummary is a short form for a log line.
func StampSummary(stamp []byte) string {
	if len(stamp) == 0 {
		return "(none)"
	}
	return strings.TrimSpace(string(stamp))
}
