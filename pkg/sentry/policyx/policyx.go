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

// Package policyx enforces the X component of a pushed policy: the allow list
// of exec identities.
//
// It is a seccheck sink and nothing else. pkg/sentry/kernel/task_exec.go fires
// PointExecve before the new image is installed and, unlike every other
// seccheck site, propagates the sink's error into the syscall — so a sink that
// returns EACCES is an execve that fails EACCES, with no patch to the syscall
// path. The identity it decides on is the one the point already carries: the
// resolved path of the first executable the exec opened, and the SHA-256 of its
// contents, computed once per (mount, inode, size, mtime) by the LRU in
// pkg/sentry/seccheck.
//
// A refusal is recorded under its own point, sentry/exec_refused, and never by
// re-entering PointExecve: a sink that emitted an execve point from inside the
// execve point would be calling itself.
//
// The package is its own because the graph allows nothing smaller: it needs
// seccheck, the points protos and linuxerr, and runsc/boot needs it. It knows
// nothing about policies, tables or tunnels; runsc/boot hands it the set.
package policyx

import (
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

// ReasonNotInX is the one reason this package refuses an exec.
const ReasonNotInX = "not-in-x"

// execveHashCacheCapacity is the size of the hash cache this package asks for
// when nothing else has set one up. It is pkg/sentry/seccheck's own default.
const execveHashCacheCapacity = 512

// An Allow is one X component: the paths and the digests that may be executed.
// Nil is not the empty set — nil means no X is in force and every exec is
// permitted, which is what a sandbox looks like before the first push that
// carries one.
type Allow struct {
	paths   map[string]struct{}
	digests map[string]struct{}
}

// NewAllow builds an allow list. Digests are matched in lowercase hex.
func NewAllow(paths, digests []string) *Allow {
	a := &Allow{
		paths:   make(map[string]struct{}, len(paths)),
		digests: make(map[string]struct{}, len(digests)),
	}
	for _, p := range paths {
		a.paths[p] = struct{}{}
	}
	for _, d := range digests {
		a.digests[strings.ToLower(d)] = struct{}{}
	}
	return a
}

// Paths is the sorted list of paths this allow list names.
func (a *Allow) Paths() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.paths))
	for p := range a.paths {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Digests is the sorted list of digests this allow list names.
func (a *Allow) Digests() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.digests))
	for d := range a.digests {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// Permits is the whole decision: the binary is permitted when the path it
// resolved to is one of x's paths, or when the hash of its contents is one of
// x's digests. Either is enough, and a nil allow list permits everything.
//
// A path matches the resolved path and not the string the workload typed, so
// `sh`, `/bin/sh` and `../bin/sh` are one identity; a digest matches the
// contents and not the name, so a copy of a permitted binary under another name
// is permitted and a different binary at a permitted path is not — which is why
// a policy that means to name a binary should name its digest.
func (a *Allow) Permits(path, digest string) bool {
	if a == nil {
		return true
	}
	if _, ok := a.paths[path]; ok {
		return true
	}
	if digest != "" {
		if _, ok := a.digests[digest]; ok {
			return true
		}
	}
	return false
}

// A Sink is the installed enforcer. One is installed per sandbox, at the first
// push that carries an x, and the set it decides on is replaced under a lock by
// every later narrowing: the sink is registered with seccheck once and only
// once, because seccheck has no way to take one back that does not also take
// back the remote sink the refusal events go to.
type Sink struct {
	seccheck.SinkDefaults

	mu sync.RWMutex
	// +checklocks:mu
	allow *Allow

	refused atomicbitops.Uint64
	checked atomicbitops.Uint64
	nanos   atomicbitops.Uint64
}

// reportEvery is how many decisions the sink makes between the lines it writes
// about itself. One line per exec would cost more than the decision does; one
// line per hundred is what spike E2's numbers are read off, and is what a run
// of any length carries afterwards.
const reportEvery = 100

// NewSink builds a sink that permits everything until Narrow is called.
func NewSink() *Sink { return &Sink{} }

// Narrow replaces the set the sink decides on.
//
// It does what its name says and nothing wider: a nil allow list is the state
// a fresh sink starts in, where every exec is permitted, and once a set is in
// force a narrowing back to that state is ignored rather than obeyed. The
// caller already refuses a pushed policy that drops x — that refusal is
// runsc/boot's policySubset and is where the peer is told why — but an
// installed sink is the only thing standing between the workload and an
// unpoliced execve, and one caller's mistake should not be able to hand it
// back. Replacing one set with another, wider or narrower, is the caller's
// business and is not second-guessed here; this package knows nothing about
// policies and cannot tell which of two sets a peer was entitled to.
func (s *Sink) Narrow(a *Allow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a == nil && s.allow != nil {
		log.Warningf("policy x: a narrowing to no allow list at all was ignored; the sink keeps the %d paths and %d digests it is enforcing", len(s.allow.paths), len(s.allow.digests))
		return
	}
	s.allow = a
}

// Allow is the set in force.
func (s *Sink) Allow() *Allow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allow
}

// Counts returns how many execs this sink has decided on, how many it refused,
// and how long it spent deciding.
func (s *Sink) Counts() (checked, refused, nanos uint64) {
	return s.checked.Load(), s.refused.Load(), s.nanos.Load()
}

// Report writes the one line this sink says about itself, which is the cost of
// the decision and the hit rate of the hash the decision is made on. The hash
// is not computed here — the execve point computed it before this sink was
// called — so the two numbers belong together: a miss is a binary read and
// hashed, and a hit is not.
func (s *Sink) Report() {
	checked, refused, nanos := s.Counts()
	mean := time.Duration(0)
	if checked > 0 {
		mean = time.Duration(nanos / checked)
	}
	var hits, misses uint64
	if cache := seccheck.Global.ExecveHashCache(); cache != nil {
		hits, misses = cache.Stats()
	}
	log.Infof("exec sink: checked=%d refused=%d mean=%v hash-cache hits=%d misses=%d", checked, refused, mean, hits, misses)
}

// Name implements seccheck.Sink.Name.
func (*Sink) Name() string { return "policy-x" }

// Status implements seccheck.Sink.Status.
func (*Sink) Status() seccheck.SinkStatus { return seccheck.SinkStatus{} }

// Stop implements seccheck.Sink.Stop.
func (*Sink) Stop() {}

// Execve implements seccheck.Sink.Execve. The error it returns is the errno the
// execve fails with.
func (s *Sink) Execve(ctx context.Context, fields seccheck.FieldSet, info *pb.ExecveInfo) error {
	allow := s.Allow()
	if allow == nil {
		return nil
	}
	start := time.Now()
	n := s.checked.Add(1)
	digest := hex.EncodeToString(info.GetBinarySha256())
	path := info.GetBinaryPath()
	permitted := allow.Permits(path, digest)
	s.nanos.Add(uint64(time.Since(start)))
	if n%reportEvery == 0 {
		s.Report()
	}
	if permitted {
		return nil
	}
	s.refused.Add(1)
	// The path is the workload's: it chose the name and it chose the file.
	// Quoted and scrubbed for the same reason a refused DNS name is, so that a
	// path with a newline in it cannot forge a line of this log.
	log.Warningf("exec refused: path=%q sha256=%s reason=%s", Printable(path), digest, ReasonNotInX)
	emitExecRefused(ctx, info, path, digest)
	return linuxerr.EACCES
}

// emitExecRefused sends one sentry/exec_refused point. The context data is the
// execve point's own, already loaded by the caller of the point, so nothing
// here reaches back into the task.
func emitExecRefused(ctx context.Context, info *pb.ExecveInfo, path, digest string) {
	if !seccheck.Global.Enabled(seccheck.PointExecRefused) {
		return
	}
	out := &pb.ExecRefused{
		ContextData: info.GetContextData(),
		Path:        Printable(path),
		Sha256:      digest,
		Reason:      ReasonNotInX,
	}
	fields := seccheck.Global.GetFieldSet(seccheck.PointExecRefused)
	// The error is deliberately dropped: the exec is refused whether or not a
	// sink could be told about it, and a sink that errors here must not turn a
	// refusal into some other errno.
	seccheck.Global.SentToSinks(func(c seccheck.Sink) error {
		return c.ExecRefused(ctx, fields, out)
	})
}

// maxPath bounds a path taken from the sandbox in a log line or an event.
const maxPath = 4096

// Printable renders a path the workload chose. Everything outside printable
// ASCII becomes '?'.
func Printable(path string) string {
	if len(path) > maxPath {
		path = path[:maxPath]
	}
	clean := []byte(path)
	for i, b := range clean {
		if b < 0x20 || b > 0x7e {
			clean[i] = '?'
		}
	}
	return string(clean)
}

// Install registers the sink with seccheck, enables PointExecve with the
// binary_sha256 field and PointExecRefused beside it, and sets up the hash
// cache if nothing else has.
//
// It adds; it never clears. seccheck's only way to remove a sink removes every
// sink and the hash cache with them, and the remote sink the refusal events go
// to was registered by the pod-init trace session before this sandbox ran a
// single instruction. The field set for PointExecve is the union of whatever a
// session already asked for and the one field this sink needs, so enabling X
// does not silently take a field away from a trace already running.
func Install(s *Sink) {
	execFields := seccheck.Global.GetFieldSet(seccheck.PointExecve)
	execFields.Local.Add(seccheck.FieldSentryExecveBinarySHA256)
	if execFields.Context.Empty() {
		execFields.Context = seccheck.MakeFieldMask(
			seccheck.FieldCtxtTime,
			seccheck.FieldCtxtContainerID,
			seccheck.FieldCtxtThreadID,
			seccheck.FieldCtxtProcessName,
		)
	}
	refusedFields := seccheck.Global.GetFieldSet(seccheck.PointExecRefused)
	if refusedFields.Context.Empty() {
		refusedFields.Context = execFields.Context
	}
	reqs := []seccheck.PointReq{
		{Pt: seccheck.PointExecve, Fields: execFields},
		{Pt: seccheck.PointExecRefused, Fields: refusedFields},
	}
	if cache := seccheck.Global.ExecveHashCache(); cache == nil || !cache.Opts().SHA256 {
		seccheck.Global.SetupExecveHashCache(execveHashCacheCapacity, reqs)
	}
	seccheck.Global.AppendSink(s, reqs)
	log.Infof("policy x: the exec sink is installed; PointExecve is on with binary_sha256")
}
