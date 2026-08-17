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

package unix

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/ladder"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
)

// This file is the write half of the ladder rung-2 taint bit: which unix
// sockets count as privileged sinks, and the gate that refuses a write to one
// from a tainted sandbox. The read half -- where a source is labeled and where
// the bit is flipped -- is in pkg/sentry/vfs. Everything here is a no-op when
// --ladder-taint is off. See pkg/sentry/ladder for the design.
//
// The gate is at the WRITE and not at connect(2). An agent that connects to
// the broker before it reads the untrusted page would sail through a
// connect-time check; gating the write means the bit is consulted at the
// moment the bytes would actually leave.

// ladderSinkPathname resolves the unix path in sockaddr the way connect(2)
// will resolve it, and returns the resulting absolute pathname, or "" if it is
// not resolvable, is abstract, or the ladder is off.
//
// It resolves rather than string-matching sockaddr because both a relative
// path (chdir into the broker's directory, then connect to "broker.sock") and
// a symlink planted in scratch would otherwise present the sink under a name
// the label set does not cover. O_PATH is used so that nothing is read and no
// source label is attached by the open itself.
func ladderSinkPathname(t *kernel.Task, sockaddr []byte) string {
	// ladder.Active(), not ladder.Enabled(): rung 3 resolves peer-channel paths
	// through this same function, and --ladder-attest alone must be enough to run
	// it. With every ladder flag off this is still one branch and no work.
	if !ladder.Active() {
		return ""
	}
	raw, err := extractPath(sockaddr)
	if err != nil || len(raw) == 0 || isAbstract(raw) {
		return ""
	}
	p := fspath.Parse(raw)
	root := t.FSContext().RootDirectory()
	defer root.DecRef(t)
	start := root
	if !p.Absolute {
		start = t.FSContext().WorkingDirectory()
		defer start.DecRef(t)
	}
	pop := &vfs.PathOperation{
		Root:               root,
		Start:              start,
		Path:               p,
		FollowFinalSymlink: true,
	}
	fd, e := t.Kernel().VFS().OpenAt(t, t.Credentials(), pop, &vfs.OpenOptions{Flags: linux.O_PATH})
	if e != nil {
		return ""
	}
	defer fd.DecRef(t)
	name, e := t.Kernel().VFS().PathnameWithDeleted(t, root, fd.VirtualDentry())
	if e != nil {
		return ""
	}
	return name
}

// ladderMarkSink records that this socket is connected to a privileged sink,
// so that later writes on it can be gated. Called after a successful
// connect(2).
func (s *Socket) ladderMarkSink(t *kernel.Task, sockaddr []byte) {
	name := ladderSinkPathname(t, sockaddr)
	if name == "" || !ladder.PrivilegedSink(name) {
		return
	}
	s.ladderSink = name
}

// ladderDenied reports whether a write on this socket must be refused, and
// logs the denial line if so.
func (s *Socket) ladderDenied() bool {
	if s.ladderSink == "" || !ladder.Tainted() {
		return false
	}
	ladder.DenyWrite(s.ladderSink)
	return true
}

// ladderDeniedTo is ladderDenied for a datagram addressed at send time rather
// than at connect time.
func ladderDeniedTo(t *kernel.Task, to []byte) bool {
	if !ladder.Tainted() {
		return false
	}
	name := ladderSinkPathname(t, to)
	if name == "" || !ladder.PrivilegedSink(name) {
		return false
	}
	ladder.DenyWrite(name)
	return true
}

// ladderErr is the error a denied write returns. EPERM, because the sandbox is
// refusing an operation the caller is not permitted to perform -- not EACCES,
// which would read as a filesystem permission on the socket.
var ladderErr = syserr.ErrNotPermitted

// ---------------------------------------------------------------- rung 3

// ladderMarkPeer records that this socket is connected to a mediated peer
// channel, so that the send path knows to stamp and the receive path knows to
// read a stamp. Called after a successful connect(2), alongside ladderMarkSink.
//
// Labeled at connect and not at send for the same reason rung 2 labels the sink
// there: the path is resolved once, by the same resolver, so a relative path or a
// planted symlink cannot present the channel under a name the label set misses.
// What is deliberately NOT decided at connect time is the stamp's contents; see
// ladder.Stamp.
func (s *Socket) ladderMarkPeer(t *kernel.Task, sockaddr []byte) {
	if !ladder.AttestEnabled() {
		return
	}
	name := ladderSinkPathname(t, sockaddr)
	if name == "" || !ladder.PeerChannel(name) {
		return
	}
	s.ladderPeer = name
}

// ladderStamp returns the label to prepend to the next message on this socket, or
// nil if this socket is not a peer channel.
func (s *Socket) ladderStamp() []byte {
	if s.ladderPeer == "" {
		return nil
	}
	return ladder.Stamp(s.ladderPeer)
}
