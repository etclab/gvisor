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

package boot

import (
	"gvisor.dev/gvisor/pkg/sentry/ladder"
)

// Ladder is the control-channel receiver for the ladder research prototype.
// It exists so that the taint bit is observable from the HOST and only from
// the host: runsc's control socket is a unix socket on the host filesystem
// whose FD is donated to the sandbox before chroot, and nothing bind-mounts it
// inside. An agent therefore cannot read this, and more importantly cannot
// write it -- there is no control method that clears a bit.
type Ladder struct{}

// LadderStatusArgs are arguments to Status. It takes none; the sandbox is the
// unit.
type LadderStatusArgs struct{}

// LadderStatusResult is returned by Status.
type LadderStatusResult struct {
	// Enabled reports whether the sandbox was started with --ladder-taint.
	Enabled bool

	// Tainted reports whether the sandbox has read from a labeled-untrusted
	// source. Once true it never returns to false.
	Tainted bool

	// Source is the path whose read set Tainted, or "" if it is unset.
	Source string

	// UntrustedPaths and PrivilegedSinks are the labels the sandbox booted
	// with.
	UntrustedPaths  []string
	PrivilegedSinks []string
}

// Status reports the sandbox's rung-2 taint state.
func (*Ladder) Status(_ *LadderStatusArgs, result *LadderStatusResult) error {
	s := ladder.CurrentStatus()
	*result = LadderStatusResult{
		Enabled:         s.Enabled,
		Tainted:         s.Tainted,
		Source:          s.Source,
		UntrustedPaths:  s.UntrustedPaths,
		PrivilegedSinks: s.PrivilegedSinks,
	}
	return nil
}
