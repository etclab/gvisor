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

package vfs

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/ladder"
)

// This file is the read half of the ladder rung-2 taint bit: where a source is
// labeled, and where reading from a labeled source flips the sandbox's bit.
// The write half -- the gate on privileged sinks -- is in
// pkg/sentry/socket/unix. Everything here is a no-op when --ladder-taint is
// off. See pkg/sentry/ladder for the design.

// ladderLabelFD attaches the untrusted-source label to a newly opened
// FileDescription, if the path it was opened at is under a labeled prefix.
//
// The label is taken from the resolved location rather than from the path the
// application asked for: a symlink into the labeled mount, or a path with
// ".." in it, must not launder the label.
//
// Preconditions: fd has just been opened and is not yet visible to any other
// goroutine.
func (vfs *VirtualFilesystem) ladderLabelFD(ctx context.Context, pop *PathOperation, fd *FileDescription) {
	if !ladder.Enabled() {
		return
	}
	pathname, err := vfs.PathnameWithDeleted(ctx, pop.Root, fd.VirtualDentry())
	if err != nil {
		// An fd whose pathname cannot be reconstructed cannot be checked
		// against the label set. Say so rather than silently treating it as
		// trusted: a quiet failure here is a hole in the claim.
		log.Warningf("LADDER label: cannot resolve pathname for a new fd (%v); it is NOT labeled", err)
		return
	}
	if ladder.UntrustedPath(pathname) {
		fd.ladderUntrusted = pathname
		log.Warningf("LADDER label: fd opened at %s is labeled untrusted", pathname)
	}
}

// ladderTaint flips the sandbox's taint bit if this fd is labeled untrusted.
// how names the operation that moved the bytes, for the log line.
func (fd *FileDescription) ladderTaint(how string) {
	if fd.ladderUntrusted == "" {
		return
	}
	ladder.Taint(fd.ladderUntrusted, how)
}
