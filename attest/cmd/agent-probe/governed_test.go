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

// Ticket 26's loopback proof: a policy pushed by a peer over a tunnel reaches
// the sentry inside a runsc sandbox, and the agent inside that sandbox runs —
// or is refused — under it, with no restart.
//
//	root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry
//	                     │                                                  Policy.Narrow
//	                     └──tunnel──▶ tunneld b ──▶ this test's exit ──▶ the real network
//
// This is where the model-backed agent task is proven under a pushed policy,
// because the compiled-in egress ceiling permits no TCP egress from a measured
// guest: the two-guest proof cannot run an agent that talks to a model, and
// this can.
//
// # Why there is a third tunneld
//
// Ticket 25's harness has two, a and b, and nobody pushes at a: a pushes at b,
// the sandboxes attach to a's socket, and the table inside the sentry comes
// from --tunnel-table and never changes. A pushed policy has to arrive from a
// peer, so this file adds `root`, which dials a and whose whole purpose is the
// document it carries. A push is once per tunnel and [tunneld.Config.PushPolicy]
// is one document fixed at New, so a second policy is a second peer — which is
// ticket 23's finding (twohops_test.go, `widen`) and is what makes a narrowing
// mid-run and a widening reachable at all.
//
// # What the runs are
//
//	off-policy  the table names both destinations and the push leaves the model
//	            endpoint out. The agent is refused and the run costs nothing.
//	on-policy   the push is the whole table. The task completes through the
//	            tunnel, and the workload's exit ends liveness.
//	narrowed    the push is the whole table, and a second peer removes the
//	            document host while the task is running. A third peer tries to
//	            put it back and is refused.
//	killed      the sandbox is killed mid-task, which is the same teardown as
//	            the workload exiting and is reached from the outside.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The policies these runs push. They are written out rather than built, because
// the digest is over exactly these bytes and a marshaller that reordered a
// field would change the number every side of the arrangement compares.
//
// `x` names the workload by its path inside the rootfs. `f` is tracked and
// enforced by nothing but the mounts (docs/sandbox-contract.md); it is here
// because the subset check carries it and the digest covers it.
const (
	// governedP0 is the whole of the boot table, which is the widest policy a
	// first push may carry: in the sentry P0 for `n` is the table itself.
	governedP0 = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[{"path":"/agent-probe"}]}`

	// governedOffPolicy is P0 without the model's endpoint: the control, whose
	// table still names it.
	governedOffPolicy = `{"format":"policy","version":1,` +
		`"n":[{"host":"www.rfc-editor.org","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[{"path":"/agent-probe"}]}`

	// governedNarrowed is P0 without the document host: what the second peer
	// pushes while the task is running.
	governedNarrowed = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],` +
		`"f":[{"path":"./summary.txt","modes":["w"]}],"x":[{"path":"/agent-probe"}]}`

	// governedClaude is E4's: the API host and nothing else, against a boot
	// table that also names the log intake.
	governedClaude = `{"format":"policy","version":1,` +
		`"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[],"x":[]}`
)

// The two sentences a's console carries when a policy stops being enforced, and
// the sentence the sentry sends back when a push would widen. They are matched
// on rather than reconstructed, because what the record has to say is what the
// operator reads.
const (
	livenessLost    = "SANDBOX liveness lost:"
	noLongerLive    = "no longer live"
	widensComponent = "it widens n by"
)

func TestGovernedLoopback(t *testing.T) {
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a runsc with the adapter: set %s=1 and %s to the binary", liveEnv, runscEnv)
	}
	runsc := os.Getenv(runscEnv)
	if info, err := os.Stat(runsc); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not a runsc this test can start: %v", runscEnv, runsc, err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatalf("%s=1 and no ANTHROPIC_API_KEY in the environment: the agent inside the sandbox needs it", liveEnv)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	l := newLoopback(t, ctx, out, runsc, proof{
		title: "A pushed policy inside the sandbox, over loopback",
		preamble: "Four runsc sandboxes, one after the other, sharing a rootfs, a bundle shape, an exit, an " +
			"allow list and a `--tunnel-table` that names both destinations. What differs is the policy a third " +
			"tunneld pushes at `a` once the sandbox has attached to its socket, and when a second and a third " +
			"peer arrive. The workload is this package built with `CGO_ENABLED=0` and run as " +
			"`/agent-probe -network plain -task summarize -dir /tmp`: no contract, no dialer of its own, Go's own " +
			"resolver, and nothing in it knows a policy exists.",
		allow: modelHost + ":443," + docHost + ":443",
		under: "ticket26/loopback",
	})
	l.console = &timeline{}
	// Short, because a pushed policy is delivered over --root/runsc-<id>.sock
	// and a sockaddr_un holds 108 bytes (spike E1 §7a).
	l.stateIn = l.shm
	l.points = append(l.points, "sentry/exec_refused")
	l.buildRootfs(t)

	probe := workload{
		args: []string{"/agent-probe", "-network", "plain", "-task", "summarize", "-dir", "/tmp"},
		env:  []string{"PATH=/", "HOME=/tmp", "SSL_CERT_FILE=" + anchors},
		cwd:  "/tmp",
		mounts: []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
			map[string]any{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
				"options": []string{"rw", "nosuid", "nodev", "mode=1777"}},
		},
	}
	table := map[string]int{modelHost: tunnelledPort, docHost: tunnelledPort}

	var notes strings.Builder
	fmt.Fprintf(&notes, "## The policies\n\n| what | sha256 | bytes |\n|---|---|---|\n")
	for _, p := range []struct{ what, doc string }{
		{"P0, the whole table", governedP0},
		{"P0 without the model endpoint (the control's)", governedOffPolicy},
		{"P1, P0 without the document host (the narrowing)", governedNarrowed},
	} {
		fmt.Fprintf(&notes, "| %s | `%s` | %d |\n", p.what, digestOf(p.doc), len(p.doc))
	}
	fmt.Fprintf(&notes, "\n```\nP0 = %s\n```\n\n", governedP0)

	// ===== (b) the off-policy control, first because it is the only one that
	// spends nothing and because it says whether the push lands before the
	// workload's first query, which every other run depends on.
	var offRoot *pusher
	off := l.govern(t, "off-policy", table, probe, func(stop <-chan struct{}) {
		if !l.waitAttached(stop) || !l.waitStarted(stop) {
			return
		}
		offRoot = l.pushAt(t, "root-off", governedOffPolicy)
	})
	l.tellOff(t, &notes, off, offRoot)

	// ===== (a) on-policy: the task completes under the pushed policy, and (d)
	// is its tail — the workload exits, the socket goes, the tunnel goes.
	var onRoot *pusher
	on := l.govern(t, "on-policy", table, probe, func(stop <-chan struct{}) {
		if !l.waitAttached(stop) || !l.waitStarted(stop) {
			return
		}
		onRoot = l.pushAt(t, "root-on", governedP0)
	})
	l.tellOn(t, &notes, on, onRoot)

	// ===== (c) a narrowing while the task runs, and a widening refused.
	var cRoot, cRoot2, cRoot3 *pusher
	narrowed := l.govern(t, "narrowed", table, probe, func(stop <-chan struct{}) {
		if !l.waitAttached(stop) || !l.waitStarted(stop) {
			return
		}
		cRoot = l.pushAt(t, "root-narrowed", governedP0)
		// The task is under way: the exit has accepted the stream the first
		// model request is on, which is after the resolver answered and after
		// the connect hook let it through.
		if !l.waitExit(stop, "EXIT accepted") {
			return
		}
		cRoot2 = l.pushAt(t, "root2-narrowed", governedNarrowed)
		cRoot3 = l.pushAt(t, "root3-narrowed", governedP0)
	})
	l.tellNarrowed(t, &notes, narrowed, cRoot, cRoot2, cRoot3)

	// ===== (d) the same teardown reached from the outside: the sandbox is
	// killed while the task is running.
	var kRoot *pusher
	var killedAt time.Time
	killed := l.govern(t, "killed", table, probe, func(stop <-chan struct{}) {
		if !l.waitAttached(stop) || !l.waitStarted(stop) {
			return
		}
		kRoot = l.pushAt(t, "root-killed", governedP0)
		if !l.waitExit(stop, "EXIT accepted") {
			return
		}
		killedAt = l.kill(t)
	})
	l.tellKilled(t, &notes, killed, kRoot, killedAt)

	fmt.Fprintf(&notes, "## a's console, in full\n\nEvery line `a` wrote, with the second it was written in. "+
		"`SANDBOX applied` is one per acknowledged push, `PUSH` is a pusher's own account of its round trip, "+
		"and `REFUSED` is `a`'s refusal log.\n\n```\n%s\n```\n\n", strings.Join(l.console.all(), "\n"))

	l.record(t, notes.String(), off, on, narrowed, killed)
}

// ===== what each run is asserted and recorded to have been =====

// tellOff is the control: the table names the model's endpoint and the policy
// in force does not, so the agent never reaches it and the run is free.
func (l *loopback) tellOff(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## off-policy — the refusal is the push and not the table\n\n")
	if root == nil || root.err != nil {
		t.Errorf("off-policy: the control's policy was not pushed: %v", root.errOr())
		fmt.Fprintf(notes, "The push did not land: %v\n\n", root.errOr())
		return
	}
	if r.err == nil {
		t.Error("off-policy: the agent completed its task, and the policy in force does not name the model's endpoint")
	}
	said := l.bothSaid(r)
	refused := refusalIn(said)
	if refused == "" {
		t.Errorf("off-policy: the agent failed, but not with either refusal the adapter can produce:\n%s", said)
	}
	if dialed := r.at.matching("EXIT dialed " + modelHost); len(dialed) != 0 {
		t.Errorf("off-policy: the exit dialed %s, and the policy in force does not name it: %v", modelHost, dialed)
	}
	fmt.Fprintf(notes, "The table is `%s` and the policy pushed is `n = [%s:443]`. The agent was refused at %s, "+
		"runsc ended with status %d after %s, and the exit was never asked to dial %s — so nothing was sent to "+
		"the model and **this run cost nothing**.\n\n", strings.Join(r.names, ", "), docHost,
		where(refused), r.status, r.elapsed.Round(time.Millisecond), modelHost)
	fmt.Fprintf(notes, "What the agent said, in its own words:\n\n```\n%s\n```\n\n", strings.TrimSpace(said))
	l.tellPush(notes, r, root)
	l.tellEvents(notes, r)
}

// tellOn is the proof: the whole table pushed, the task completed through the
// tunnel, and the workload's exit ending liveness.
func (l *loopback) tellOn(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## on-policy — the task completes under the policy, and its end ends the tunnel\n\n")
	if root == nil || root.err != nil {
		t.Errorf("on-policy: P0 was not pushed: %v", root.errOr())
		fmt.Fprintf(notes, "The push did not land: %v\n\n", root.errOr())
		return
	}
	if r.err != nil {
		t.Errorf("on-policy: the sandbox ended with %v; the policy in force names both destinations", r.err)
	}
	if said := l.said(r.stdout); !strings.Contains(said, "DONE") {
		t.Errorf("on-policy: the transcript does not end in the model's last word:\n%s", said)
	}
	if dialed := r.at.matching("EXIT dialed " + modelHost + ":443"); len(dialed) == 0 {
		t.Errorf("on-policy: the exit never dialed %s:443, so the model request did not travel over the tunnel", modelHost)
	}
	fmt.Fprintf(notes, "`%s`, and the task completed: runsc ended with status %d after %s, `%s`. Every stream the "+
		"exit carried is in the run's section above.\n\n", r.at.timings(), r.status, r.elapsed.Round(time.Millisecond),
		firstLineWith(l.said(r.stdout), "DONE"))
	l.tellPush(notes, r, root)
	l.tellTeardown(t, notes, r, "the workload exiting")
	l.tellEvents(notes, r)
}

// tellNarrowed is the narrowing under the task and the widening after it.
func (l *loopback) tellNarrowed(t *testing.T, notes *strings.Builder, r *sandboxRun, first, second, third *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## narrowed — a second peer removes a destination while the task is running\n\n")
	if first == nil || first.err != nil {
		t.Errorf("narrowed: P0 was not pushed: %v", first.errOr())
		fmt.Fprintf(notes, "The first push did not land: %v\n\n", first.errOr())
		return
	}
	if second == nil || second.err != nil {
		t.Errorf("narrowed: the narrowing was not applied: %v", second.errOr())
	}
	if third == nil || third.err == nil {
		t.Errorf("narrowed: the widening was not refused; a third peer put a name back and the sandbox took it")
	} else if !strings.Contains(third.err.Error(), widensComponent) {
		t.Errorf("narrowed: the widening was refused but the sentence does not name the component: %v", third.err)
	}

	narrow := sentrySaid(r, "tunnel narrow: sha256=")
	gone := sentrySaid(r, "is gone")
	fmt.Fprintf(notes, "The sentry's own account of the two policies that landed, and of the name the second one "+
		"removed:\n\n```\n%s\n```\n\n", strings.Join(lines(append(append([]spoken{}, narrow...), gone...)), "\n"))
	if len(narrow) < 2 {
		t.Errorf("narrowed: the sentry recorded %d policies applied; want two", len(narrow))
	}

	// What the agent observed. Whether the document was already fetched when
	// the name went is a race with the model's first answer, and the record
	// says which way it fell rather than asserting one.
	said := l.bothSaid(r)
	fetched := len(r.at.matching("EXIT dialed "+docHost)) != 0
	fmt.Fprintf(notes, "The narrowing landed %s after the exit accepted the first stream. The document host "+
		"had **%s** been dialled when it landed, and what the agent saw was:\n\n```\n%s\n```\n\n",
		l.betweenExitAndPush(r, second), map[bool]string{true: "already", false: "not"}[fetched],
		strings.TrimSpace(keepLines(said, "fetch_url", "no such host", "unreachable", "DONE", "TOOL")))
	fmt.Fprintf(notes, "runsc ended with status %d after %s, `%s`, and the workload ran throughout: the "+
		"narrowing is not a restart and the process the run started is the process that finished.\n\n",
		r.status, r.elapsed.Round(time.Millisecond), r.at.timings())

	// The first pusher's tunnel goes, because the sandbox is now pulsing a
	// digest that is not the one it pushed.
	if mismatch, ok := l.console.await(second.at, noLongerLive, 5*time.Second); ok {
		fmt.Fprintf(notes, "**The first peer's tunnel is torn down as a mismatch**, %s after the narrowing was "+
			"acknowledged, while the workload kept running:\n\n```\n%s\n```\n\n",
			mismatch.when.Sub(second.at).Round(time.Millisecond), mismatch.text)
		if !strings.Contains(mismatch.text, first.digest) {
			t.Errorf("narrowed: the mismatch does not name the digest the first peer pushed:\n%s", mismatch.text)
		}
	} else {
		t.Error("narrowed: the first peer's tunnel was not torn down after the sandbox began enforcing another policy")
		fmt.Fprintf(notes, "**No mismatch was reported**, and the first peer's policy is not the one in force.\n\n")
	}

	fmt.Fprintf(notes, "And the third peer, pushing P0 again at a sandbox now holding P1, is refused with the "+
		"sentence naming the component:\n\n```\n%v\n```\n\n", third.errOr())
	l.tellPush(notes, r, first, second, third)
	l.tellEvents(notes, r)
}

// tellKilled is the teardown reached from outside, which is the same one.
func (l *loopback) tellKilled(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher, killedAt time.Time) {
	t.Helper()
	fmt.Fprintf(notes, "## killed — the same teardown, reached with `runsc kill`\n\n")
	if root == nil || root.err != nil {
		t.Errorf("killed: P0 was not pushed: %v", root.errOr())
		fmt.Fprintf(notes, "The push did not land: %v\n\n", root.errOr())
		return
	}
	if killedAt.IsZero() {
		fmt.Fprintf(notes, "The sandbox was not killed: the task ended before the exit had accepted a stream.\n\n")
		return
	}
	fmt.Fprintf(notes, "`runsc kill %s KILL` was sent %s into the run, while the first model request was in "+
		"flight. runsc ended with status %d after %s.\n\n", r.id, killedAt.Sub(r.began).Round(time.Millisecond),
		r.status, r.elapsed.Round(time.Millisecond))
	l.tellPush(notes, r, root)
	l.tellTeardown(t, notes, r, "`runsc kill`")
	l.tellEvents(notes, r)
}

// tellTeardown is the two lines and the one number (d) asks for: how long after
// runsc exited a's console said the policy was no longer live.
func (l *loopback) tellTeardown(t *testing.T, notes *strings.Builder, r *sandboxRun, why string) {
	t.Helper()
	ended := r.began.Add(r.elapsed)
	lost, haveLost := l.console.await(r.began, livenessLost, 8*time.Second)
	refused, haveRefused := l.console.await(r.began, noLongerLive, 8*time.Second)
	if !haveLost || !haveRefused {
		t.Errorf("%s: liveness was not reported lost after %s (lost=%v refused=%v)", r.name, why, haveLost, haveRefused)
		fmt.Fprintf(notes, "**Liveness was not reported lost** after %s.\n\n", why)
		return
	}
	fmt.Fprintf(notes, "Liveness ends with %s, and the tunnel goes with it:\n\n```\n%s\n%s\n```\n\n"+
		"runsc exited at %s; the loss was reported **%s** later and the tunnel was refused **%s** later. The "+
		"bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).\n\n",
		why, lost.text, refused.text, ended.Format("15:04:05.000"),
		lost.when.Sub(ended).Round(time.Millisecond), refused.when.Sub(ended).Round(time.Millisecond))
	if !strings.Contains(lost.text, "closed its socket") {
		t.Errorf("%s: the loss was reported as %q; the workload going is the socket closing", r.name, lost.text)
	}
}

// tellPush is the push round trip from both sides, which is RQ5's "installation
// and binding of P".
func (l *loopback) tellPush(notes *strings.Builder, r *sandboxRun, pushers ...*pusher) {
	fmt.Fprintf(notes, "The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the "+
		"other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract "+
		"socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part "+
		"of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry "+
		"had started the workload is refused and takes its tunnel with it, so the next one is a fresh "+
		"handshake.\n\n| peer | sha256 | handshakes | cold Open | Apply at a | outcome |\n|---|---|---|---|---|---|\n")
	for _, p := range pushers {
		if p == nil {
			continue
		}
		outcome := "acknowledged"
		if p.err != nil {
			outcome = "refused"
		}
		fmt.Fprintf(notes, "| `%s` | `%s` | %d | %s | %s | %s |\n", p.name, short(p.digest), p.tries,
			p.took.Round(time.Millisecond), p.applyTook().Round(time.Microsecond), outcome)
	}
	inside := sentrySaid(r, "tunnel narrow: applied in ")
	if len(inside) != 0 {
		fmt.Fprintf(notes, "\nAnd the sentry's own, one line per policy it accepted:\n\n```\n%s\n```\n",
			strings.Join(lines(inside), "\n"))
	}
	fmt.Fprintf(notes, "\n")
}

// tellEvents is what the seccheck receiver printed for this run, which is the
// only place the reason for a refusal is written down.
func (l *loopback) tellEvents(notes *strings.Builder, r *sandboxRun) {
	if r.events == "" {
		fmt.Fprintf(notes, "No seccheck event was recorded for this run: no receiver was listening.\n\n")
		return
	}
	said := strings.TrimSpace(l.said(r.events))
	if said == "" {
		fmt.Fprintf(notes, "The seccheck receiver printed nothing for this run: nothing was refused.\n\n")
		return
	}
	fmt.Fprintf(notes, "What the sentry emitted on the seccheck sink:\n\n```\n%s\n```\n\n", said)
}

// ===== E4: Claude Code under a pushed policy =====

// TestClaudeGoverned is ticket 26's E4 and the definition of done's governed
// Claude Code run, which are one run: the shipped agent runtime, unmodified,
// under a policy whose `n` is the API host and nothing else, on a table that
// also names the log intake it contacts without being asked.
//
// Three governed runs and one unrestricted one, in that order, so that the
// comparison is against the same binary, the same rootfs and the same exit on
// the same afternoon. What is being asked is E4's question: what the task did,
// every refusal with its errno, and whether the two are distinguishable from
// outside the guest.
func TestClaudeGoverned(t *testing.T) {
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a runsc and the Claude Code ELF: set %s=1, %s and %s", liveEnv, runscEnv, claudeEnv)
	}
	runsc := os.Getenv(runscEnv)
	if info, err := os.Stat(runsc); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not a runsc this test can start: %v", runscEnv, runsc, err)
	}
	elf := os.Getenv(claudeEnv)
	if info, err := os.Stat(elf); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not the Claude Code binary: %v", claudeEnv, elf, err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatalf("%s=1 and no ANTHROPIC_API_KEY in the environment: the CLI inside the sandbox needs it", liveEnv)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	l := newLoopback(t, ctx, out, runsc, proof{
		title: "E4: Claude Code under a pushed policy",
		preamble: "Four runsc sandboxes with the same rootfs, the same table — `" + modelHost + ":443` and `" +
			intakeHost + ":443` — and the same command, `claude -p \"" + smokePrompt + "\" --output-format json " +
			"--model " + smokeModel + "`. The first three have a policy pushed at `a` by a third tunneld once the " +
			"sandbox has attached, whose `n` is the API host and nothing else, so the push narrows the table by " +
			"the log intake. The fourth has no push and is the comparison.",
		allow: modelHost + ":443," + intakeHost + ":443",
		under: "ticket26/spikes/E4",
	})
	l.console = &timeline{}
	l.stateIn = l.shm
	l.buildClaudeRootfs(t, elf)

	claude := workload{
		args:     []string{"/usr/local/bin/claude", "-p", smokePrompt, "--output-format", "json", "--model", smokeModel},
		env:      []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/agent", "SSL_CERT_FILE=" + anchors},
		cwd:      "/work",
		writable: true,
		mounts: []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
			map[string]any{"destination": "/sys", "type": "sysfs", "source": "sysfs",
				"options": []string{"nosuid", "noexec", "nodev", "ro"}},
		},
	}
	table := map[string]int{modelHost: tunnelledPort, intakeHost: tunnelledPort}

	var runs []*sandboxRun
	var pushes []*pusher
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("governed-%d", i)
		var p *pusher
		r := l.govern(t, name, table, claude, func(stop <-chan struct{}) {
			if !l.waitAttached(stop) {
				return
			}
			p = l.pushAt(t, "root-"+name, governedClaude)
		})
		if p == nil || p.err != nil {
			t.Errorf("%s: the policy was not pushed: %v", name, p.errOr())
		}
		runs, pushes = append(runs, r), append(pushes, p)
	}
	free := l.govern(t, "unrestricted", table, claude, func(stop <-chan struct{}) {})
	runs = append(runs, free)

	// The one assertion each run carries over from the smoke: the ELF ran.
	for _, r := range runs {
		if !containsString(r.comms, "claude") {
			t.Errorf("%s: the sentry traced no syscalls from a process called claude; what ran was %v", r.name, r.comms)
		}
	}
	// And the one this test adds: the governed runs must not have reached the
	// intake, and the unrestricted one is expected to.
	for _, r := range runs[:3] {
		if dialed := r.at.matching("EXIT dialed " + intakeHost); len(dialed) != 0 {
			t.Errorf("%s: the exit dialed %s, and the policy in force does not name it: %v", r.name, intakeHost, dialed)
		}
	}

	l.record(t, l.tellClaude(t, runs, pushes), runs...)
}

// tellClaude is E4's own section of the README: the outcome of each run, every
// refusal with its errno, and the comparison.
func (l *loopback) tellClaude(t *testing.T, runs []*sandboxRun, pushes []*pusher) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "## The policy\n\n```\n%s\n```\n\nsha256 `%s`, %d bytes. `n` is the API host and nothing "+
		"else; `f` and `x` are empty, so exec stays unconstrained and no file is named — which is what makes "+
		"the only difference between these runs and the fourth a single destination.\n\n",
		governedClaude, digestOf(governedClaude), len(governedClaude))

	fmt.Fprintf(&b, "## The four runs\n\n| run | policy | result | is_error | turns | cost | wall | api ms | "+
		"runsc | streams at the exit | intake dialled |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
	var spent float64
	for _, r := range runs {
		res, ok := claudeJSON(l.said(r.stdout))
		pushed := "pushed"
		if r.name == "unrestricted" {
			pushed = "none"
		}
		result := res.Result
		if !ok {
			result = "(no JSON result object)"
		}
		spent += res.TotalCost
		fmt.Fprintf(&b, "| %s | %s | `%s` | %v | %d | $%.6f | %s | %d | %d | %d | %s |\n",
			r.name, pushed, oneLine(result), res.IsError, res.NumTurns, res.TotalCost,
			r.elapsed.Round(time.Millisecond), res.DurationAPI, r.status,
			len(r.at.matching("EXIT accepted")), yesNo(len(r.at.matching("EXIT dialed "+intakeHost)) != 0))
	}
	fmt.Fprintf(&b, "\nThe four runs cost $%.6f between them, as the CLI reported it.\n\n", spent)

	fmt.Fprintf(&b, "## Every refusal, with the errno\n\n")
	for i, r := range runs {
		fmt.Fprintf(&b, "### %s\n\n", r.name)
		if i < len(pushes) && pushes[i] != nil {
			fmt.Fprintf(&b, "The push: sha256 `%s`, %d handshake(s), cold Open %s, `Apply` at `a` %s, %v.\n\n",
				short(pushes[i].digest), pushes[i].tries, pushes[i].took.Round(time.Millisecond),
				pushes[i].applyTook().Round(time.Microsecond), acknowledged(pushes[i].err))
		}
		asked := askedFor(r.tunnel)
		fmt.Fprintf(&b, "| name | queries | types | answers |\n|---|---|---|---|\n")
		for _, a := range asked {
			fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", a.name, a.n, strings.Join(a.types, ", "), strings.Join(a.answers, ", "))
		}
		fmt.Fprintf(&b, "\n")
		if refused := sentrySaid(r, "tunnel: refused "); len(refused) != 0 {
			fmt.Fprintf(&b, "What the sentry refused:\n\n```\n%s\n```\n\n", strings.Join(lines(refused), "\n"))
		}
		if r.events != "" {
			if said := strings.TrimSpace(l.said(r.events)); said != "" {
				fmt.Fprintf(&b, "The seccheck sink:\n\n```\n%s\n```\n\n", said)
			} else {
				fmt.Fprintf(&b, "The seccheck sink printed nothing for this run.\n\n")
			}
		}
		fmt.Fprintf(&b, "The syscalls that failed, and the network ones among them, are in this run's "+
			"`strace-digest.txt`; the failing DNS path is `%s`.\n\n", failingCalls(l.said(r.digest)))
	}
	return b.String()
}

// ===== the pusher =====

// A pusher is a third peer whose whole purpose is the document it carries: one
// tunneld with the fake platform, admitted by the same reference values as a
// and b, dialling a and pushing once.
type pusher struct {
	name   string
	policy string
	digest string
	td     *tunneld.Tunneld

	at    time.Time     // when the push returned, for placing a teardown against it
	took  time.Duration // the cold Open of the attempt that settled it: dial, both verdicts, push, ack
	tries int           // how many handshakes it took, which is how early the first one was
	err   error

	// applied is a's own clock on Apply — the contract socket, the helper, urpc
	// and the sentry — in nanoseconds. It is written on a's goroutine while the
	// pusher's is inside Peer, so it is atomic rather than a field two
	// goroutines share by hoping.
	applied atomic.Int64

	refusals lineLog
}

// errOr is the pusher's error, or the fact that there was no pusher, in a form
// a record can print.
// applyTook is a's clock on this push.
func (p *pusher) applyTook() time.Duration {
	if p == nil {
		return 0
	}
	return time.Duration(p.applied.Load())
}

func (p *pusher) errOr() error {
	if p == nil {
		return fmt.Errorf("no pusher reached a in this run")
	}
	return p.err
}

// pushAt brings up one pusher and makes its push. The policy is fixed at New
// because a push is once per tunnel, so a second policy is a second peer.
//
// It retries, and only for one sentence. The helper is on a's socket before the
// sentry process exists (runsc/sandbox/sandbox.go, createSandboxProcess), but
// the boot controller honours a policy only from a loader whose state is
// `started` (runsc/boot/policy.go:106) — so there is a window in which a push
// can be made and cannot land, and a push refused in it takes its tunnel with
// it. A retry is therefore a fresh handshake and a fresh push, which is what
// Peer does once the connection it had has gone. Every attempt is one refusal
// in a's log, and the count is recorded rather than hidden.
func (l *loopback) pushAt(t *testing.T, name, policy string) *pusher {
	p := &pusher{name: name, policy: policy, digest: digestOf(policy)}
	p.td = l.w.start(t, name, rootImage, tunneld.PeerTable{"a": l.aTd.Addr().String()}, policy,
		func(r *attest.Refusal) { p.refusals.add(r.LogString()) })
	l.pushing.Store(p)
	for p.tries = 1; ; p.tries++ {
		began := time.Now()
		_, p.err = p.td.Peer(l.ctx, "a")
		p.took = time.Since(began)
		if p.err == nil || !tooEarly(p.err) || p.tries >= 40 {
			break
		}
		l.out.logf("%s  push %d was too early: %v", name, p.tries, p.err)
		select {
		case <-time.After(25 * time.Millisecond):
		case <-l.ctx.Done():
		}
	}
	p.at = time.Now()
	l.pushing.Store(nil)
	l.out.logf("\n%s  PUSH sha256=%s bytes=%d returned after %s on attempt %d: err=%v", name, p.digest, len(policy),
		p.took.Round(time.Millisecond), p.tries, p.err)
	l.console.add(fmt.Sprintf("PUSH %s sha256=%s cold_open=%s apply=%s tries=%d err=%v",
		name, short(p.digest), p.took.Round(time.Millisecond), p.applyTook().Round(time.Microsecond), p.tries, p.err))
	return p
}

// notStarted is the sentry's own sentence for a policy that arrived before the
// workload did, carried back through the helper and the contract word for word.
const notStarted = "a policy is honoured only by a started one"

// tooEarly reports whether a push failed because the sandbox had not started
// yet, which is the one failure worth making again.
func tooEarly(err error) bool { return err != nil && strings.Contains(err.Error(), notStarted) }

// appliedAt is a's contract socket with a's own clock on it. It embeds the host
// rather than the interface, so what tunneld watches after a push is still a
// sandbox that says which policy it is enforcing.
type appliedAt struct {
	*sandbox.Host
	l *loopback
}

func (h *appliedAt) Apply(ctx context.Context, policy []byte) error {
	began := time.Now()
	err := h.Host.Apply(ctx, policy)
	took := time.Since(began)
	h.l.out.logf("a  Apply returned after %s: %v", took.Round(time.Microsecond), err)
	if p := h.l.pushing.Load(); p != nil {
		p.applied.Store(int64(took))
	}
	return err
}

// ===== the world, governed =====

// govern runs one sandbox and lets `during` push at a while it is up. The
// pusher runs on its own goroutine because l.sandbox blocks for the whole life
// of the container, which is the window a push has to arrive in.
func (l *loopback) govern(t *testing.T, name string, names map[string]int, w workload, during func(stop <-chan struct{})) *sandboxRun {
	t.Helper()
	// A previous run's helper may still be dropping off a's socket, and a
	// pusher that waited for "a sandbox" would find that one and push into a
	// container that is already gone.
	for waited := time.Duration(0); l.aHost.Attached() != 0; waited += 20 * time.Millisecond {
		if waited > 30*time.Second {
			t.Fatalf("%d sandboxes are still attached to %s from an earlier run", l.aHost.Attached(), l.socket)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop, finished := make(chan struct{}), make(chan struct{})
	go func() { defer close(finished); during(stop) }()
	r := l.sandbox(t, name, names, w)
	close(stop)
	<-finished
	// The teardown is measured after the run, and a watch looks every quarter
	// of a pulse: this is the window it is looked for in.
	time.Sleep(2 * time.Second)
	return r
}

// waitAttached waits for a sandbox to be on a's socket, which is the moment
// there is something for a push to land in. The helper is started before the
// sentry process is (runsc/sandbox/sandbox.go, createSandboxProcess), so this
// is reached well before the workload's first query — which the sentry's own
// log timestamps in every run are the evidence for.
func (l *loopback) waitAttached(stop <-chan struct{}) bool {
	return l.until(stop, 2*time.Minute, func() bool { return l.aHost.Attached() > 0 })
}

// waitStarted waits for the sentry to have started the workload, which is when
// Policy.Narrow stops refusing. The signal is the sentry's own log line, which
// is written one statement before `l.state = started`
// (runsc/boot/loader.go:1370). A push made as soon as the helper attached would
// be a hundred and seventy milliseconds too early on this machine, and the
// workload's first query is a hundred and fifteen milliseconds after this line
// — so this is where a push has to be made from if it is to land before the
// thing it governs.
func (l *loopback) waitStarted(stop <-chan struct{}) bool {
	w := &bootWatch{}
	return l.until(stop, 5*time.Minute, func() bool {
		r := l.now.Load()
		return r != nil && w.has(r.debug, "Process should have started")
	})
}

// A bootWatch is a tail of the sentry's boot log. It keeps its place, because
// the log is tens of megabytes by the end of a --strace run and the line it is
// waiting for is in the first few hundred kilobytes.
type bootWatch struct {
	path string
	off  int64
}

func (w *bootWatch) has(dir, mark string) bool {
	if w.path == "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".boot.") {
				w.path = filepath.Join(dir, e.Name())
			}
		}
		if w.path == "" {
			return false
		}
	}
	f, err := os.Open(w.path)
	if err != nil {
		return false
	}
	defer f.Close()
	// Back up by the length of the mark, so that a mark split across two reads
	// is not missed.
	if w.off > int64(len(mark)) {
		w.off -= int64(len(mark))
	}
	if _, err := f.Seek(w.off, 0); err != nil {
		return false
	}
	buf := make([]byte, 1<<20)
	found := false
	for {
		n, err := f.Read(buf)
		if n > 0 {
			w.off += int64(n)
			if strings.Contains(string(buf[:n]), mark) {
				found = true
			}
		}
		if err != nil || n == 0 {
			return found
		}
	}
}

// waitExit waits for the exit to have said something, which is how a pusher
// arriving "while the task is running" is synchronised on the task rather than
// on a sleep.
func (l *loopback) waitExit(stop <-chan struct{}, substr string) bool {
	return l.until(stop, 10*time.Minute, func() bool {
		at := l.at.Load()
		return at != nil && len(at.matching(substr)) != 0
	})
}

func (l *loopback) until(stop <-chan struct{}, within time.Duration, ready func() bool) bool {
	deadline := time.Now().Add(within)
	for {
		if ready() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-stop:
			return false
		case <-l.ctx.Done():
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// kill ends the run in progress from outside the sandbox, which is the teardown
// the ticket asks for reached without waiting for a task to finish.
func (l *loopback) kill(t *testing.T) time.Time {
	r := l.now.Load()
	if r == nil {
		return time.Time{}
	}
	cmd := exec.CommandContext(l.ctx, l.runsc, "--root="+r.root, "kill", r.id, "KILL")
	at := time.Now()
	said, err := cmd.CombinedOutput()
	l.out.logf("%s  $ %s --root=%s kill %s KILL -> %v %s", r.name, l.runsc, r.root, r.id, err, strings.TrimSpace(string(said)))
	if err != nil {
		t.Errorf("%s: runsc kill: %v: %s", r.name, err, said)
		return time.Time{}
	}
	return at
}

// betweenExitAndPush is how long after the exit accepted the first stream a
// pusher's push returned, which is what "while the task was running" means in
// seconds.
func (l *loopback) betweenExitAndPush(r *sandboxRun, p *pusher) string {
	if p == nil || p.at.IsZero() {
		return "(never)"
	}
	r.at.mu.Lock()
	took, ok := r.at.at["tunnel_open"]
	r.at.mu.Unlock()
	if !ok {
		return "(the exit accepted nothing)"
	}
	return p.at.Sub(r.began.Add(took)).Round(time.Millisecond).String()
}

// bothSaid is both of a run's captured streams, because a refusal the workload
// reported can be on either.
func (l *loopback) bothSaid(r *sandboxRun) string {
	return l.said(r.stdout) + l.said(r.stderr)
}

// aSays wraps a's console so that a governed run has it with a clock on it.
// Without one it is the voice it always was.
func (l *loopback) aSays(say func(string, ...any)) func(string, ...any) {
	return func(format string, args ...any) {
		say(format, args...)
		l.console.add(fmt.Sprintf(format, args...))
	}
}

// aRefused is a's refusal log, kept the same way. It is the only place the
// eleventh reason is written down.
func (l *loopback) aRefused(r *attest.Refusal) {
	l.console.add("REFUSED " + r.LogString())
}

// ===== a clock on what was said =====

// A spoken is one line and the moment it was said.
type spoken struct {
	when time.Time
	text string
}

// A timeline is a line log with a clock on it. The lineLog next door answers
// "was this said"; a teardown is "how long after that was this said", and the
// difference is a field.
//
// The nil timeline swallows everything, so a harness that did not ask for one
// pays nothing and every caller is unconditional.
type timeline struct {
	mu    sync.Mutex
	lines []spoken
}

func (tl *timeline) add(text string) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	tl.lines = append(tl.lines, spoken{when: time.Now(), text: text})
	tl.mu.Unlock()
}

// after is the lines said at or after `from` that carry substr.
func (tl *timeline) after(from time.Time, substr string) []spoken {
	if tl == nil {
		return nil
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	var found []spoken
	for _, s := range tl.lines {
		if !s.when.Before(from) && strings.Contains(s.text, substr) {
			found = append(found, s)
		}
	}
	return found
}

// await waits for such a line to be said, up to `within`.
func (tl *timeline) await(from time.Time, substr string, within time.Duration) (spoken, bool) {
	deadline := time.Now().Add(within)
	for {
		if found := tl.after(from, substr); len(found) != 0 {
			return found[0], true
		}
		if time.Now().After(deadline) {
			return spoken{}, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// all is everything said, stamped, for the record.
func (tl *timeline) all() []string {
	if tl == nil {
		return nil
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	said := make([]string, 0, len(tl.lines))
	for _, s := range tl.lines {
		said = append(said, fmt.Sprintf("%s  %s", s.when.Format("15:04:05.000"), s.text))
	}
	return said
}

// ===== reading the sentry's own log =====

// sentrySaid is the lines of the sentry's debug log that carry mark, with the
// timestamp its logger put on each one.
//
// digest() keeps the same lines for the README and cuts the prefix off, which
// is right for a list of what the adapter did; when a narrowing landed relative
// to a query is a different question and needs the clock. The format is
// gVisor's: `I0918 15:34:06.516550       1 policy.go:225] …`.
func sentrySaid(r *sandboxRun, mark string) []spoken {
	boot := ""
	entries, err := os.ReadDir(r.debug)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".boot.") {
			boot = filepath.Join(r.debug, e.Name())
		}
	}
	if boot == "" {
		return nil
	}
	f, err := os.Open(boot)
	if err != nil {
		return nil
	}
	defer f.Close()
	var found []spoken
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, mark)
		if i < 0 {
			continue
		}
		found = append(found, spoken{when: sentryTime(line, r.began), text: line[i:]})
	}
	return found
}

// sentryTime is the moment a sentry log line was written, read off the line
// itself. A line it cannot read is placed at the run's start rather than at the
// zero time, so that an ordering built from these never puts an unreadable line
// before the run that produced it.
func sentryTime(line string, began time.Time) time.Time {
	if len(line) < 22 || (line[0] != 'I' && line[0] != 'W' && line[0] != 'D' && line[0] != 'E') {
		return began
	}
	when, err := time.ParseInLocation("0102 15:04:05.000000", line[1:21], time.Local)
	if err != nil {
		return began
	}
	return when.AddDate(began.Year(), 0, 0)
}

// lines is a timeline's text, stamped, for a fenced block in the record.
func lines(said []spoken) []string {
	sort.Slice(said, func(i, j int) bool { return said[i].when.Before(said[j].when) })
	out := make([]string, 0, len(said))
	for _, s := range said {
		out = append(out, fmt.Sprintf("%s  %s", s.when.Format("15:04:05.000000"), s.text))
	}
	return out
}

// ===== small things =====

// short is a digest as a record prints it: enough to tell two apart.
func short(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:8] + "…" + digest[len(digest)-4:]
}

// where names which of the two places a refusal landed, in the words the
// harness already uses for them.
func where(refusal string) string {
	switch refusal {
	case notFound:
		return "the resolver (`" + notFound + "`, which is NXDOMAIN)"
	case unreachable:
		return "the connect (`" + unreachable + "`, which is ENETUNREACH)"
	}
	return "neither place this harness knows"
}

func acknowledged(err error) string {
	if err == nil {
		return "acknowledged"
	}
	return fmt.Sprintf("refused: %v", err)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// oneLine is a result as a table cell: one line, and short enough to read.
func oneLine(text string) string {
	text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\n", " "), "|", "\\|"))
	if len(text) > 120 {
		return text[:117] + "…"
	}
	return text
}

// firstLineWith is the first line of text that carries substr.
func firstLineWith(text, substr string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, substr) {
			return strings.TrimSpace(line)
		}
	}
	return "(" + substr + " was not said)"
}

// keepLines is the lines of text that carry any of the words, which is how a
// long transcript is quoted for the one thing it is being quoted for.
func keepLines(text string, words ...string) string {
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		for _, word := range words {
			if strings.Contains(line, word) {
				kept = append(kept, strings.TrimSpace(line))
				break
			}
		}
	}
	return strings.Join(kept, "\n")
}

// failingCalls is the one line of a strace digest that names the resolver's
// failures, for a record that keeps the whole digest beside it anyway.
func failingCalls(digest string) string {
	for _, line := range strings.Split(digest, "\n") {
		if strings.Contains(line, "connect") && strings.Contains(line, "errno=") {
			return strings.TrimSpace(line)
		}
	}
	return "(no failing connect in the digest)"
}

// containsString is slices.Contains without the import, which this file would
// otherwise take for one call.
func containsString(have []string, want string) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
}
