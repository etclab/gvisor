// Copyright 2025 The gVisor Authors.
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

// Package ladder implements the rung-2 taint bit of the agent-sandbox ladder.
// It is a research prototype, gated entirely on --ladder-taint; with that flag
// off every function here is a predictable no-op and no caller changes
// behavior.
//
// The property: if bytes enter the sandbox from a source the operator labeled
// untrusted, the sandbox is tainted, and a tainted sandbox may not write to a
// privileged sink. The label lives below the application, so nothing the
// application does -- re-encoding, copying, forking, reconnecting -- touches
// it.
//
// Three deliberate choices, recorded here because they are the design:
//
//   - The taint bit is a package-level global, which makes it exactly
//     sandbox-wide. It is not per-task, per-process or per-fd. Process-level
//     over-approximation is sound; partial propagation between processes would
//     not be, and is worse than an honest coarse bit.
//
//   - It is monotonic. There is no Untaint. A declassifier is a real design
//     question (rung 3) and a silent one here would be a hole.
//
//   - It cannot live on kernel.Kernel, which is where a sandbox-global flag
//     would otherwise belong: pkg/sentry/kernel imports pkg/sentry/vfs, and
//     the read hook is in vfs, so vfs cannot import kernel. A leaf package
//     both can import is the way out.
package ladder

import (
	"strings"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// policy is the sandbox's label configuration. It is written once by
// Configure, from the boot goroutine before the application is started, and is
// read-only for the life of the sandbox thereafter.
var policy struct {
	// enabled mirrors --ladder-taint. Every exported predicate returns false
	// when it is false.
	enabled bool

	// untrusted holds the absolute in-sandbox path prefixes whose contents are
	// labeled untrusted. Reading from any of them taints the sandbox.
	untrusted []string

	// sinks holds the absolute in-sandbox path prefixes of privileged sinks:
	// unix sockets that a tainted sandbox may not write to.
	sinks []string

	// attest mirrors --ladder-attest (rung 3). See attest.go.
	attest bool

	// peers holds the absolute in-sandbox path prefixes of peer channels:
	// unix sockets on which every outbound message is stamped and every
	// inbound message's stamp is applied.
	peers []string

	// identity is this sandbox's name in the stamps it writes.
	identity string

	// grants is this sandbox's capability set, as the launcher declared it,
	// carried in the stamps it writes. It is a label, not a privilege.
	grants string

	// chain mirrors --ladder-chain (rung 4). See chain.go.
	chain bool
}

// tainted is the bit. It is sandbox-wide and write-once.
var tainted atomicbitops.Bool

// sourceMu protects source.
var sourceMu sync.Mutex

// source is the path that flipped tainted, kept for the log line and for the
// Ladder.Status control call. Empty until the flip.
var source string

// Configure installs the sandbox's label policy. It must be called once,
// before the application starts. Paths are absolute, as seen from inside the
// sandbox; a trailing slash is ignored, and a prefix matches a path only at a
// component boundary, so "/untrusted" does not label "/untrusted-notes".
func Configure(enabled bool, untrusted, sinks []string) {
	policy.enabled = enabled
	policy.untrusted = normalize(untrusted)
	policy.sinks = normalize(sinks)
	if !enabled {
		return
	}
	log.Warningf("LADDER taint enabled: untrusted=%s sinks=%s",
		strings.Join(policy.untrusted, ","), strings.Join(policy.sinks, ","))
}

func normalize(paths []string) []string {
	var out []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for len(p) > 1 && strings.HasSuffix(p, "/") {
			p = p[:len(p)-1]
		}
		out = append(out, p)
	}
	return out
}

// Enabled reports whether --ladder-taint was set. Callers on hot paths check
// this first so that the disabled case costs one predictable branch.
func Enabled() bool {
	return policy.enabled
}

// under reports whether path is prefix itself or lies beneath it.
func under(prefix, path string) bool {
	if path == prefix {
		return true
	}
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, prefix+"/")
}

// UntrustedPath reports whether path is under a source labeled untrusted.
func UntrustedPath(path string) bool {
	if !policy.enabled {
		return false
	}
	for _, prefix := range policy.untrusted {
		if under(prefix, path) {
			return true
		}
	}
	return false
}

// PrivilegedSink reports whether path names a privileged sink.
func PrivilegedSink(path string) bool {
	if !policy.enabled {
		return false
	}
	for _, prefix := range policy.sinks {
		if under(prefix, path) {
			return true
		}
	}
	return false
}

// Taint records that bytes from path entered the sandbox. It is idempotent and
// irreversible: only the first call logs, and no call clears the bit.
func Taint(path, how string) {
	if !policy.enabled {
		return
	}
	if !tainted.CompareAndSwap(false, true) {
		return
	}
	sourceMu.Lock()
	source = path
	sourceMu.Unlock()
	log.Warningf("LADDER TAINT set source=%s via=%s sinks=%s: this sandbox may no longer write to a privileged sink",
		path, how, strings.Join(policy.sinks, ","))
}

// Tainted reports whether the sandbox has read from a labeled-untrusted
// source. It is false whenever the flag is off.
func Tainted() bool {
	return policy.enabled && tainted.Load()
}

// Source returns the path that flipped the taint bit, or "" if it is unset.
func Source() string {
	sourceMu.Lock()
	defer sourceMu.Unlock()
	return source
}

// DenyWrite logs the one line the rung-2 demo greps for. It is called on the
// denial path only, so it is not rate-limited: a denied agent that retries in
// a loop is exactly what an operator wants to see in the log.
func DenyWrite(sink string) {
	log.Warningf("LADDER DENY sink=%s taint=set source=%s reason=write-to-privileged-sink-from-tainted-sandbox",
		sink, Source())
}

// Status describes the sandbox's taint state for the host-side control call.
type Status struct {
	// Enabled mirrors --ladder-taint.
	Enabled bool

	// Tainted is the bit.
	Tainted bool

	// Source is the path that flipped Tainted, or "".
	Source string

	// UntrustedPaths and PrivilegedSinks are the configured labels.
	UntrustedPaths  []string
	PrivilegedSinks []string
}

// CurrentStatus returns the sandbox's taint state.
func CurrentStatus() Status {
	return Status{
		Enabled:         policy.enabled,
		Tainted:         Tainted(),
		Source:          Source(),
		UntrustedPaths:  policy.untrusted,
		PrivilegedSinks: policy.sinks,
	}
}
