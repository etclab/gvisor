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

package sandbox

import (
	"context"
	"time"
)

// Liveness, contract version 3.
//
// [Sandbox.Apply] returns once, and ticket 23 measured what that costs: the
// acknowledgement left Apply 1.856 ms after the workload was started and the
// workload was dead at 43 ms, with the tunnel still up. An acknowledgement is a
// claim about the past. What the contract had no verb for was the present —
// "the policy you pushed is the policy I am enforcing, now" — so a tunnel went
// on asserting something the sandbox no longer believed.
//
// The verb is one message and no reply: a sandbox that has acknowledged a
// policy sends `alive` with that policy's digest every [DefaultPulse] until it
// closes. Liveness is lost when an attachment that acknowledged stops sending
// them, sends one for a different policy, or closes its socket, and a tunnel
// whose push is no longer live is closed by whoever is watching, under its own
// reason in the refusal taxonomy. Naming that reason here is package tunneld's
// job and not this package's, which imports nothing of it. Nothing crosses the
// tunnel for it either: the peer learns what it learns from every other
// refusal, which is that its tunnel went.
//
// The heartbeat is the sandbox's and not tunneld's because only the sandbox
// knows. Tunneld cannot ask "is the workload still running" of a process it
// does not own, in a sandbox whose implementation it is deliberately ignorant
// of; the sandbox can answer it by not saying anything.
const (
	// DefaultPulse is how often a sandbox that has acknowledged a policy says
	// so. Spike E3 measured the send at 17 µs at the median (30 µs mean) and
	// the receiving side at 255 µs of CPU per pulse, so a second is not a cost decision:
	// it is the resolution at which "the workload is gone" becomes a fact on
	// the far side of a tunnel, and the teardown it bounds is three of them.
	DefaultPulse = time.Second

	// DefaultMisses is how many consecutive pulses may be missed before
	// liveness is lost. Three is what distinguishes a scheduling hiccup from a
	// workload that is gone: E3 measured a 1 s ticker drifting by well under a
	// millisecond over a minute, so one missed pulse is already a strong
	// signal, and three is the margin that keeps a loaded machine from
	// producing a refusal nobody can explain.
	DefaultMisses = 3
)

// A Live sandbox says, continuously, which policy it is enforcing. It is an
// optional interface: a caller that pushed a policy and got an acknowledgement
// asks whether the sandbox beside it also implements this, and watches if it
// does.
//
// Only [Host] implements it, and that is the design rather than an accident. A
// sandbox in this process has no liveness question — it is this process, and a
// caller that wants to know whether it is still there has already been told by
// the runtime. The question exists because there is a process boundary, so the
// answer lives with the thing that owns the boundary.
//
// Watch reports the loss of liveness for the policy whose digest is given, for
// every attachment that acknowledged one. The returned channel receives exactly
// one error when liveness is lost and is closed afterwards; it is closed
// without an error when ctx is cancelled or the sandbox is closed, so a caller
// that reads it as `err, ok := <-ch` is told the two apart.
//
// DropEnforcing is the other half and is here rather than beside it because the
// two are one contract: whoever is told the claim is lost is the one that has to
// stop it being made. A watcher that could only watch would leave the sandbox
// saying a policy is in force with nothing enforcing it, and the next stream or
// push would be answered under it.
type Live interface {
	Watch(ctx context.Context, digest string) <-chan error

	// DropEnforcing gives up the attachment whose claim was lost and leaves no
	// policy in force.
	DropEnforcing()
}
