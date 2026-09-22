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
	"slices"
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

	// enforcingAttached is the part of a's console line that says the one client
	// which can be pushed a policy is on the socket: `SANDBOX attached on <path>
	// role=enforcing` (attest/sandbox, contract v4). The socket path sits in the
	// middle of it, so the role is what is matched on, and nothing else a writes
	// carries it. The early-push run is timed against that line.
	enforcingAttached = "role=enforcing"
)

func TestGovernedLoopback(t *testing.T) {
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a runsc with the adapter: set %s=1 and %s to the binary", liveEnv, runscEnv)
	}
	runsc := os.Getenv(runscEnv)
	if info, err := os.Stat(runsc); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not a runsc this test can start: %v", runscEnv, runsc, err)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	l := newLoopback(t, ctx, out, runsc, proof{
		title: "A pushed policy inside the sandbox, over loopback",
		preamble: "Five runsc sandboxes, one after the other, sharing a rootfs, a bundle shape, an exit, an " +
			"allow list and a `--tunnel-table` that names both destinations. What differs is the policy a third " +
			"tunneld pushes at `a` — once the sandbox has attached to its socket, or before it attaches in " +
			"early-push — and when a second and a third peer arrive. The workload is this package built with " +
			"`CGO_ENABLED=0` and run as `/agent-probe -network plain -task summarize -without-model -dir /tmp`: " +
			"no contract, no dialer of its own, Go's own resolver, and nothing in it knows a policy exists.\n\n" +
			"**The model was not called in these runs.** `-without-model` leaves out the one step that needs a " +
			"key and nothing else: the model endpoint is requested for real over the same client and therefore " +
			"the same tunnel, with the body the loop builds and no `x-api-key` header, so what it answers is an " +
			"authentication error — and a status that came back at all is a stream that crossed the tunnel and " +
			"an exit that dialled `" + modelHost + ":443`. The document host is then fetched the way the " +
			"`fetch_url` tool fetches it. No number below is a token count, a cost or a summary, because no " +
			"model was asked; each run ends in `" + withoutModelMarker + "`, whose figures are the statuses and " +
			"byte counts measured.",
		allow: modelHost + ":443," + docHost + ":443",
		under: "ticket27/loopback",
	})
	l.console = &timeline{}
	l.stateIn = l.shm
	l.points = append(l.points, "sentry/exec_refused")
	l.buildRootfs(t)

	probe := workload{
		args: []string{"/agent-probe", "-network", "plain", "-task", "summarize", "-without-model", "-dir", "/tmp"},
		env:  []string{"PATH=/", "HOME=/tmp", "SSL_CERT_FILE=" + anchors},
		cwd:  "/tmp",
		mounts: []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
			map[string]any{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
				"options": []string{"rw", "nosuid", "nodev", "mode=1777"}},
		},
	}
	table := map[string]int{modelHost: tunnelledPort, docHost: tunnelledPort}
	notes := l.governedNotes()

	// (b) off-policy control
	var offRoot *pusher
	off := l.govern(t, "off-policy", table, probe, func(stop <-chan struct{}) {
		root := l.pusherFor(t, "root-off", governedOffPolicy)
		if l.waitAttached(stop) {
			offRoot = root.push(l, stop)
		}
	})
	l.tellOff(t, notes, off, offRoot)

	// (a) on-policy
	var onRoot *pusher
	on := l.govern(t, "on-policy", table, probe, func(stop <-chan struct{}) {
		root := l.pusherFor(t, "root-on", governedP0)
		if l.waitAttached(stop) {
			onRoot = root.push(l, stop)
		}
	})
	l.tellOn(t, notes, on, onRoot)

	// (c) narrowing & widening refusal
	var cRoot, cRoot2, cRoot3 *pusher
	narrowed := l.govern(t, "narrowed", table, probe, func(stop <-chan struct{}) {
		first := l.pusherFor(t, "root-narrowed", governedP0)
		second := l.pusherFor(t, "root2-narrowed", governedNarrowed)
		third := l.pusherFor(t, "root3-narrowed", governedP0)
		if l.waitAttached(stop) {
			cRoot = first.push(l, stop)
			if l.waitExit(stop, "EXIT accepted") {
				cRoot2 = second.push(l, stop)
				cRoot3 = third.push(l, stop)
			}
		}
	})
	l.tellNarrowed(t, notes, narrowed, cRoot, cRoot2, cRoot3)

	// (d) killed mid-task
	var kRoot *pusher
	var killedAt time.Time
	killed := l.govern(t, "killed", table, probe, func(stop <-chan struct{}) {
		root := l.pusherFor(t, "root-killed", governedP0)
		if l.waitAttached(stop) {
			kRoot = root.push(l, stop)
			if l.waitExit(stop, "EXIT accepted") {
				killedAt = l.kill(t)
			}
		}
	})
	l.tellKilled(t, notes, killed, kRoot, killedAt)

	// ===== (e) early-push: the push is inside a's Apply before the sandbox
	// exists. The pusher is built and its first handshake made before runsc is
	// started at all — holdStart is what keeps the two in that order rather than
	// leaving it to a goroutine being scheduled — so the acknowledgement this
	// run is judged on is one that could only have come from the enforcing
	// sandbox, which did not exist when the document arrived.
	var earlyRoot *pusher
	earlyPusher := l.pusherFor(t, "root-early", governedP0)
	l.holdStart = func() bool { return !earlyPusher.enteredAt().IsZero() }
	early := l.govern(t, "early-push", table, probe, func(stop <-chan struct{}) {
		earlyRoot = earlyPusher.push(l, stop)
	})
	l.holdStart = nil
	l.tellEarly(t, notes, early, earlyRoot)

	fmt.Fprintf(notes, "## a's console, in full\n\nEvery line `a` wrote, with the second it was written in. "+
		"`SANDBOX applied` is one per acknowledged push, `PUSH` is a pusher's own account of its round trip, "+
		"and `REFUSED` is `a`'s refusal log.\n\n```\n%s\n```\n\n", strings.Join(l.console.all(), "\n"))

	l.record(t, notes.String(), off, on, narrowed, killed, early)
}

// ===== what each run is asserted and recorded to have been =====

// tellOff is the control: the table names the model's endpoint and the policy
// in force does not, so the agent never reaches it and the run is free.
func (l *loopback) tellOff(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## off-policy — the refusal is the push and not the table\n\n")
	if root == nil || root.err != nil {
		t.Errorf("off-policy: the control's policy was not pushed: %v", root.errOr())
		l.unproven(notes, r, root)
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
	fmt.Fprintf(notes, "The table is `%s` and the policy pushed is `n = [%s:443]`. The workload was refused at "+
		"%s, runsc ended with status %d after %s, and the exit was never asked to dial %s — so **the refusal is "+
		"the pushed policy's and not the table's**, which is the whole of what this control says.\n\n",
		strings.Join(r.names, ", "), docHost, where(refused), r.status, r.elapsed.Round(time.Millisecond), modelHost)
	fmt.Fprintf(notes, "What the workload said, in its own words:\n\n```\n%s\n```\n\n", strings.TrimSpace(said))
	l.tellTail(t, notes, r, "", root)
}

func (l *loopback) governedNotes() *strings.Builder {
	notes := &strings.Builder{}
	fmt.Fprintf(notes, "## The policies\n\n| what | sha256 | bytes |\n|---|---|---|\n")
	for _, p := range []struct{ what, doc string }{
		{"P0, the whole table", governedP0},
		{"P0 without the model endpoint (the control's)", governedOffPolicy},
		{"P1, P0 without the document host (the narrowing)", governedNarrowed},
	} {
		fmt.Fprintf(notes, "| %s | `%s` | %d |\n", p.what, digestOf(p.doc), len(p.doc))
	}
	fmt.Fprintf(notes, "\n```\nP0 = %s\n```\n\n", governedP0)
	fmt.Fprintf(notes, "## What was not run\n\nThe workload ran with `-without-model`, so the model was never "+
		"called: the run needs no `ANTHROPIC_API_KEY` and none was read. Every leg of the path is measured "+
		"except the model's answer. The request to `%s` is made with the body the loop builds and without the "+
		"key header, so the status in each run's transcript is the API's answer to an unauthenticated request; "+
		"a status that arrived is a stream that crossed the tunnel and an exit that dialled `%s:443`. The "+
		"document fetch that follows is the `fetch_url` tool's, over the same client, and the byte count is what "+
		"was read. Nothing in this record is model output, and the gap between the two requests is the fixed "+
		"`withoutModelPause` rather than a model thinking.\n\n", modelEndpoint, modelHost)
	return notes
}

// unproven is what a run's section says when its assertions did not hold: what
// the push it needed answered, and every line `a` wrote around that sandbox —
// because a refused push is `a`'s own account of why and not the pusher's, and a
// reader of the record should not have to go to the transcript for it.
func (l *loopback) unproven(notes *strings.Builder, r *sandboxRun, p *pusher) {
	fmt.Fprintf(notes, "**This run did not prove what it is here for**, and the assertions that failed are in the "+
		"transcript. The push it needed answered `%v`. What `a` said around this sandbox:\n\n```\n%s\n```\n\n",
		p.errOr(), strings.Join(lines(l.console.after(r.began, "")), "\n"))
}

func (l *loopback) assertGovernedSuccess(t *testing.T, r *sandboxRun, root *pusher, runName string) bool {
	t.Helper()
	if root == nil || root.err != nil {
		t.Errorf("%s: P0 was not pushed: %v", runName, root.errOr())
		return false
	}
	if r.err != nil {
		t.Errorf("%s: the sandbox ended with %v; the policy in force names both destinations", runName, r.err)
		return false
	}
	if said := l.said(r.stdout); !strings.Contains(said, withoutModelMarker) {
		t.Errorf("%s: the transcript does not end in %s, so the run did not get through its steps:\n%s",
			runName, withoutModelMarker, said)
		return false
	}
	if dialed := r.at.matching("EXIT dialed " + modelHost + ":443"); len(dialed) == 0 {
		t.Errorf("%s: the exit never dialed %s:443, so the model request did not travel over the tunnel", runName, modelHost)
		return false
	}
	return true
}

// tellTail is the part every run's section ends with: the push from both ends,
// the window before it landed, the teardown when there is one to report, and
// whatever the seccheck receiver printed. It is one function because it is one
// list, and a run that differs in its tail differs by naming a different `why`
// or by naming none.
func (l *loopback) tellTail(t *testing.T, notes *strings.Builder, r *sandboxRun, why string, pushers ...*pusher) {
	t.Helper()
	l.tellPush(notes, r, pushers...)
	l.tellWindow(notes, r)
	if why != "" {
		l.tellTeardown(t, notes, r, why)
	}
	l.tellEvents(notes, r)
}

// workloadExited is what ended liveness in the runs the workload was left to
// finish, and is the `why` tellTail prints.
const workloadExited = "the workload exiting"

// tellOn is the proof: the whole table pushed, the task completed through the
// tunnel, and the workload's exit ending liveness.
func (l *loopback) tellOn(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## on-policy — the task completes under the policy, and its end ends the tunnel\n\n")
	if !l.assertGovernedSuccess(t, r, root, "on-policy") {
		l.unproven(notes, r, root)
		return
	}
	fmt.Fprintf(notes, "`%s`, and the task completed: runsc ended with status %d after %s, `%s`. Every stream the "+
		"exit carried is in the run's section above.\n\n", r.at.timings(), r.status, r.elapsed.Round(time.Millisecond),
		firstLineWith(l.said(r.stdout), withoutModelMarker))
	l.tellTail(t, notes, r, workloadExited, root)
}

// tellNarrowed is the narrowing under the task and the widening after it.
func (l *loopback) tellNarrowed(t *testing.T, notes *strings.Builder, r *sandboxRun, first, second, third *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## narrowed — a second peer removes a destination while the task is running\n\n")
	if !l.assertGovernedSuccess(t, r, first, "narrowed") {
		l.unproven(notes, r, first)
		return
	}
	if second == nil || second.err != nil {
		t.Errorf("narrowed: the narrowing was not applied: %v", second.errOr())
		return
	}
	if third == nil || third.err == nil {
		t.Errorf("narrowed: the widening was not refused; a third peer put a name back and the sandbox took it")
	}

	l.tellNarrowing(t, notes, r, second)
	l.tellWidening(t, notes, second, third)
	l.tellTail(t, notes, r, "", first, second, third)
}

// tellNarrowing is what the second peer's document did: the sentry's account of
// it, the refusal the workload met afterwards, and the liveness that was not
// lost for it.
func (l *loopback) tellNarrowing(t *testing.T, notes *strings.Builder, r *sandboxRun, second *pusher) {
	t.Helper()
	narrow := sentrySaid(r, "tunnel narrow: sha256=")
	gone := sentrySaid(r, "is gone")
	fmt.Fprintf(notes, "The sentry's own account of the two policies that landed, and of the name the second one "+
		"removed:\n\n```\n%s\n```\n\n", strings.Join(lines(append(append([]spoken{}, narrow...), gone...)), "\n"))
	if len(narrow) < 2 {
		t.Errorf("narrowed: the sentry recorded %d policies applied; want two", len(narrow))
	}

	// What the workload met. With the model step left out, the gap between its
	// two requests is a constant, so the second is certain to be made after the
	// narrowing landed and the refusal is asserted rather than recorded either
	// way — which is the one thing this run gained by not calling a model.
	said := l.bothSaid(r)
	if dialed := r.at.matching("EXIT dialed " + docHost); len(dialed) != 0 {
		t.Errorf("narrowed: the exit dialled %s after the narrowing removed it: %v. The workload's two requests "+
			"are %s apart (withoutModelPause), and the narrowing landed %s after the exit accepted the first "+
			"stream, so the second request was made under the narrowed policy.", docHost, dialed,
			withoutModelPause, l.betweenExitAndPush(r, second))
	}
	if refused := refusalIn(said); refused == "" {
		t.Errorf("narrowed: the workload was not refused the document host the narrowing removed:\n%s", said)
	}
	fmt.Fprintf(notes, "The narrowing landed %s after the exit accepted the first stream, and the workload's "+
		"second request is a fixed %s after its first — so the document host was **not** dialled after the name "+
		"went, and what the workload saw was:\n\n```\n%s\n```\n\n",
		l.betweenExitAndPush(r, second), withoutModelPause,
		strings.TrimSpace(keepLines(said, "fetch_url", "no such host", "unreachable", withoutModelMarker, "TOOL")))
	// A narrowing is not a mismatch, and this is where ticket 27 differs from
	// ticket 26 in what it asserts. A sandbox that takes a second policy starts
	// pulsing that policy's digest, and ticket 26's watch over the first digest
	// read that as a sandbox that had stopped enforcing: it closed the first
	// peer's tunnel, which was the intent, and dropped the enforcing attachment,
	// which since ticket 27's reaping of the helper would tear the sandbox down
	// mid-task. So the watch over the old policy is retired before the new one is
	// pushed (attest/tunneld/push.go, applyOrRefuse), and what must hold is that
	// nothing was lost between the narrowing and the workload's own exit.
	ended := r.began.Add(r.elapsed)
	var lostEarly []spoken
	for _, s := range l.console.after(second.at, livenessLost) {
		if s.when.Before(ended) {
			lostEarly = append(lostEarly, s)
		}
	}
	if len(lostEarly) != 0 {
		t.Errorf("narrowed: the narrowing was read as a loss of liveness while the workload was still running, which drops the enforcing attachment and ends the sandbox:\n%s",
			strings.Join(lines(lostEarly), "\n"))
	}
	if lost, ok := l.console.await(second.at, livenessLost, 8*time.Second); ok {
		fmt.Fprintf(notes, "**The narrowing is not read as a mismatch.** The sandbox pulses the new policy's "+
			"digest from the moment it takes it, and the watch over the old one is retired before the new one is "+
			"pushed — so nothing is lost while the workload runs, and the one loss reported is the workload's own "+
			"exit, %s after the narrowing landed:\n\n```\n%s\n```\n\n"+
			"This is the one place this run differs from ticket 26's, where the first peer's tunnel was torn down "+
			"as a mismatch and the number recorded was how long that took. Reading a lawful narrowing as a loss "+
			"now costs the sandbox rather than one tunnel, so it is not read as one — and the first peer, whose "+
			"policy is no longer the one in force, keeps its tunnel and is told nothing. That is a finding and "+
			"not an assertion of this run.\n\n", lost.when.Sub(second.at).Round(time.Millisecond), lost.text)
	} else {
		t.Error("narrowed: no liveness loss was reported at all, not even for the workload exiting")
	}
}

// tellWidening is the third peer's push at a sandbox that has already narrowed,
// and the two halves of the refusal it gets.
//
// The sentence naming the component stays on this side of the tunnel. What the
// peer is told is that its policy did not land, in a fixed sentence
// (attest/tunneld/push.go, `ackRefused`), because which component widened is a
// fact about this guest and the peer supplied the document rather than the
// machine. Both halves are recorded, because a reader looking for the sentence
// in the wrong place would conclude it was not written.
func (l *loopback) tellWidening(t *testing.T, notes *strings.Builder, second, third *pusher) {
	t.Helper()
	widened := l.console.after(second.at, widensComponent)
	if len(widened) == 0 {
		t.Error("narrowed: a's refusal log does not carry the sentence naming the component that widened")
		fmt.Fprintf(notes, "**a's log does not name the component that widened.**\n\n")
	} else {
		fmt.Fprintf(notes, "And the third peer, pushing P0 again at a sandbox now holding P1, is refused. The "+
			"sentence naming the component is `a`'s and stays there:\n\n```\n%s\n```\n\nWhat the peer is told "+
			"is the fixed sentence the boundary carries back, and not which component widened — that is a fact "+
			"about this guest, and the peer supplied the document rather than the machine "+
			"(`attest/tunneld/push.go`, `ackRefused`):\n\n```\n%v\n```\n\n",
			strings.Join(lines(widened), "\n"), third.errOr())
		for _, r := range third.refusals.matching("did not apply the policy") {
			fmt.Fprintf(notes, "The third peer's own refusal log: `%s`\n\n", r)
		}
	}
}

// tellKilled is the teardown reached from outside, which is the same one.
func (l *loopback) tellKilled(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher, killedAt time.Time) {
	t.Helper()
	fmt.Fprintf(notes, "## killed — the same teardown, reached with `runsc kill`\n\n")
	if root == nil || root.err != nil {
		t.Errorf("killed: P0 was not pushed: %v", root.errOr())
		l.unproven(notes, r, root)
		return
	}
	if killedAt.IsZero() {
		fmt.Fprintf(notes, "The sandbox was not killed: the task ended before the exit had accepted a stream.\n\n")
		return
	}
	fmt.Fprintf(notes, "`runsc kill %s KILL` was sent %s into the run, while the first model request was in "+
		"flight. runsc ended with status %d after %s.\n\n", r.id, killedAt.Sub(r.began).Round(time.Millisecond),
		r.status, r.elapsed.Round(time.Millisecond))
	l.tellTail(t, notes, r, "`runsc kill`", root)
}

// tellEarly is ticket 27's scenario and the thing the whole ticket is about: the
// push arrives before the sandbox's helper has attached, and the acknowledgement
// it eventually gets means the enforcing sandbox has the document.
//
// Four moments are read off two clocks and compared. `entered` is when a's Apply
// was first entered, taken on a's own goroutine; `attached` is when a's console
// said an enforcing client was on the socket; `applied` is the one console line a
// push acknowledged by the enforcing sandbox writes; and the pusher's own PUSH
// line is when Apply came back. entered before attached is what makes this the
// early push and not the on-policy run again. applied and the ack after attached
// is what makes the acknowledgement true — an Apply that returned nil before the
// helper was on the socket would be an acknowledgement of a policy nothing was
// enforcing, and is the defect this run exists to catch.
func (l *loopback) tellEarly(t *testing.T, notes *strings.Builder, r *sandboxRun, root *pusher) {
	t.Helper()
	fmt.Fprintf(notes, "## early-push — the push arrives before the sandbox attaches\n\n")
	if !l.assertGovernedSuccess(t, r, root, "early-push") {
		l.unproven(notes, r, root)
		return
	}
	entered, acked := root.enteredAt(), root.ackedAt()
	attached, haveAttached := l.console.await(r.began, enforcingAttached, 30*time.Second)
	applied, haveApplied := l.console.await(r.began, "SANDBOX applied ", 30*time.Second)
	switch {
	case entered.IsZero():
		t.Error("early-push: a's Apply was never entered, so there was no push to be early")
	case !haveAttached:
		t.Errorf("early-push: a's console never carried %q, so no enforcing sandbox attached", enforcingAttached)
	case !entered.Before(attached.when):
		t.Errorf("early-push: the push entered a's Apply at %s and the enforcing sandbox attached at %s, so this run is not the early push it is named for",
			entered.Format("15:04:05.000000"), attached.when.Format("15:04:05.000000"))
	case acked.Before(attached.when):
		t.Errorf("early-push: Apply acknowledged the push at %s, before the enforcing sandbox attached at %s: the acknowledgement was a lie",
			acked.Format("15:04:05.000000"), attached.when.Format("15:04:05.000000"))
	}
	if !haveApplied {
		t.Errorf("early-push: a's console carries no `SANDBOX applied` line, so no sandbox acknowledged P0 (%s)", short(root.digest))
	} else {
		if !strings.Contains(applied.text, root.digest) {
			t.Errorf("early-push: the line a wrote for the acknowledged push is %q, which does not name P0's digest %s", applied.text, root.digest)
		}
		if haveAttached && applied.when.Before(attached.when) {
			t.Errorf("early-push: a wrote %q at %s, before the enforcing sandbox attached at %s", applied.text,
				applied.when.Format("15:04:05.000000"), attached.when.Format("15:04:05.000000"))
		}
		if root.at.Before(applied.when) {
			t.Errorf("early-push: the push returned at %s, before a wrote %q at %s", root.at.Format("15:04:05.000000"),
				applied.text, applied.when.Format("15:04:05.000000"))
		}
	}
	// The sentry's own account, which is the difference between the helper
	// having the document and the sandbox enforcing it.
	if narrowed := sentrySaid(r, "tunnel narrow: sha256="); len(narrowed) == 0 {
		t.Error("early-push: the sentry's log records no policy applied, so the acknowledged document did not reach it")
	}
	fmt.Fprintf(notes, "The push was made at `a` before `runsc` was started: the pusher's handshake was already "+
		"done and its document already inside `Host.Apply` when the sandbox was created, which is what the "+
		"harness holds the two in order for. `Host.Apply` waited there for an enforcing attachment, handed it "+
		"the document, and acknowledged only once the sentry had applied it.\n\n")
	fmt.Fprintf(notes, "| moment | clock | when |\n|---|---|---|\n")
	for _, m := range []struct {
		what, whose string
		when        time.Time
	}{
		{"`Host.Apply` entered at `a`", "a's goroutine", entered},
		{quoted(attached.text), "a's console", attached.when},
		{quoted(applied.text), "a's console", applied.when},
		{"`Host.Apply` acknowledged the push", "a's goroutine", acked},
		{"the pusher's `PUSH` line: `Peer` returned", "the pusher", root.at},
	} {
		fmt.Fprintf(notes, "| %s | %s | %s |\n", m.what, m.whose, when(m.when))
	}
	fmt.Fprintf(notes, "\nThe push was entered **%s** before the enforcing sandbox attached, and acknowledged "+
		"**%s** after it, having been made %s. The workload then ran governed and completed: runsc ended with "+
		"status %d after %s, `%s`.\n\n", attached.when.Sub(entered).Round(time.Millisecond),
		acked.Sub(attached.when).Round(time.Millisecond), times(root.tries), r.status,
		r.elapsed.Round(time.Millisecond), firstLineWith(l.said(r.stdout), withoutModelMarker))
	l.tellTail(t, notes, r, workloadExited, root)
}

// when is one of those moments, or the fact that it never happened.
func when(at time.Time) string {
	if at.IsZero() {
		return "(never)"
	}
	return at.Format("15:04:05.000000")
}

// quoted is one console line for a table cell, or the fact that it was never
// written.
func quoted(text string) string {
	if text == "" {
		return "(not written)"
	}
	return "`" + text + "`"
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
	// One loss per run, which is the sandbox going. A second is a claim reported
	// lost that nobody was making: an operator reading this console has to be
	// able to take a loss as a sandbox that stopped enforcing, and every extra
	// one is a refusal written against a peer for something that did not happen.
	if all := l.console.after(r.began, livenessLost); len(all) != 1 {
		t.Errorf("%s: liveness was reported lost %d times in one run, and the sandbox goes once:\n%s",
			r.name, len(all), strings.Join(lines(all), "\n"))
	}
	// The two can land either side of `ended`: the sandbox's socket closes when
	// the sentry goes, and runsc's own exit is accounted a few milliseconds
	// afterwards — so a loss reported before runsc returned is the ordinary case
	// and not a clock running backwards. Which side it fell is printed rather
	// than a negative duration.
	fmt.Fprintf(notes, "Liveness ends with %s, and the tunnel goes with it:\n\n```\n%s\n%s\n```\n\n"+
		"runsc exited at %s; the loss was reported **%s %s** that and the tunnel was refused **%s %s** that. The "+
		"bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).\n\n",
		why, lost.text, refused.text, ended.Format("15:04:05.000"),
		absDur(lost.when.Sub(ended)).Round(time.Millisecond), earlierLater(lost.when, ended),
		absDur(refused.when.Sub(ended)).Round(time.Millisecond), earlierLater(refused.when, ended))
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

// tellWindow is the honest number: how much of the workload's life ran under
// the boot table alone, before the pushed policy landed. It is read off the
// sentry's own log, because both ends of it are lines the sentry wrote.
func (l *loopback) tellWindow(notes *strings.Builder, r *sandboxRun) {
	started := sentrySaid(r, "Process should have started")
	landed := sentrySaid(r, "tunnel narrow: sha256=")
	asked := sentrySaid(r, "tunnel dns: ")
	if len(started) == 0 || len(landed) == 0 {
		fmt.Fprintf(notes, "The sentry's log does not carry both ends of the window between the workload "+
			"starting and the policy landing, so this run has no number for it.\n\n")
		return
	}
	first := ""
	if len(asked) != 0 {
		first = fmt.Sprintf(" The workload's first query was %s after it started, and the policy was %s %s it.",
			asked[0].when.Sub(started[0].when).Round(time.Millisecond),
			absDur(landed[0].when.Sub(asked[0].when)), earlierLater(landed[0].when, asked[0].when))
	}
	fmt.Fprintf(notes, "**The window.** The sentry started the workload at %s and the first policy landed at "+
		"%s, so **%s** of this run was governed by `--tunnel-table` and nothing else.%s A policy cannot be "+
		"applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the "+
		"arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every "+
		"push narrows.\n\n", started[0].when.Format("15:04:05.000000"), landed[0].when.Format("15:04:05.000000"),
		landed[0].when.Sub(started[0].when).Round(time.Millisecond), first)
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
		t.Skipf("%s=1 and no ANTHROPIC_API_KEY in the environment: the CLI inside the sandbox needs it", liveEnv)
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
			root := l.pusherFor(t, "root-"+name, governedClaude)
			if !l.waitAttached(stop) {
				return
			}
			p = root.push(l, stop)
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
		if !slices.Contains(r.comms, "claude") {
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
		fmt.Fprintf(&b, "What failed at the syscall level: %s The whole tally is in this run's "+
			"`strace-digest.txt`.\n\n", networkFailures(l.said(r.digest)))
	}
	l.tellDistinguishable(&b, runs)
	return b.String()
}

// tellDistinguishable is E4's own question, answered from outside the guest:
// is a run under the policy distinguishable from a run without one?
//
// Four places are compared, and the syscall tally is one of them because it is
// the place an observer inside the guest would look.
func (l *loopback) tellDistinguishable(b *strings.Builder, runs []*sandboxRun) {
	free := runs[len(runs)-1]
	fmt.Fprintf(b, "## Distinguishable from the outside?\n\n")
	fmt.Fprintf(b, "| what is compared | governed | unrestricted |\n|---|---|---|\n")
	var walls, streams []string
	for _, r := range runs[:len(runs)-1] {
		walls = append(walls, r.elapsed.Round(time.Millisecond).String())
		streams = append(streams, fmt.Sprint(len(r.at.matching("EXIT accepted"))))
	}
	fmt.Fprintf(b, "| the task's result | `OK`, `is_error=false` | `OK`, `is_error=false` |\n")
	fmt.Fprintf(b, "| runsc's exit status | %s | %d |\n", statuses(runs[:len(runs)-1]), free.status)
	fmt.Fprintf(b, "| wall | %s | %s |\n", strings.Join(walls, ", "), free.elapsed.Round(time.Millisecond))
	fmt.Fprintf(b, "| streams the exit accepted | %s | %d |\n", strings.Join(streams, ", "),
		len(free.at.matching("EXIT accepted")))
	fmt.Fprintf(b, "| destinations the exit dialled | %s | %s |\n", dialled(runs[0]), dialled(free))
	fmt.Fprintf(b, "| `sentry/egress_refused` events | %d | %d |\n", countEvents(l, runs[0]), countEvents(l, free))
	fmt.Fprintf(b, "\nAnd the syscall tallies, which is where an observer *inside* the guest would look. These are "+
		"the rows of `## syscalls that failed` that differ between the first governed run and the unrestricted "+
		"one:\n\n```\n%s\n```\n\n", differingRows(l.said(runs[0].digest), l.said(free.digest)))
}

// statuses is the exit statuses of several runs, for one table cell.
func statuses(runs []*sandboxRun) string {
	var said []string
	for _, r := range runs {
		said = append(said, fmt.Sprint(r.status))
	}
	return strings.Join(said, ", ")
}

// dialled is the distinct destinations the exit was asked for in one run.
func dialled(r *sandboxRun) string {
	var seen []string
	for _, line := range r.at.matching("EXIT dialed ") {
		rest := strings.TrimPrefix(line, "EXIT dialed ")
		if where, _, ok := strings.Cut(rest, " ->"); ok && !slices.Contains(seen, where) {
			seen = append(seen, where)
		}
	}
	if len(seen) == 0 {
		return "(none)"
	}
	return "`" + strings.Join(seen, "`, `") + "`"
}

// countEvents is how many refusals the sentry emitted in one run.
func countEvents(l *loopback, r *sandboxRun) int {
	if r.events == "" {
		return 0
	}
	n := 0
	for _, line := range strings.Split(l.said(r.events), "\n") {
		if strings.HasPrefix(line, "egress_refused") || strings.HasPrefix(line, "exec_refused") {
			n++
		}
	}
	return n
}

// differingRows is the failed-syscall rows one digest has and the other has
// not, or has with a different count. A row is `<count>  <name> errno=…`, so
// the comparison is on the name and the errno and the count is printed beside
// each.
func differingRows(a, b string) string {
	rows := func(digest string) map[string]string {
		found := map[string]string{}
		in := false
		for _, line := range strings.Split(digest, "\n") {
			switch {
			case strings.HasPrefix(line, "## syscalls that failed"):
				in = true
				continue
			case strings.HasPrefix(line, "## "):
				in = false
			}
			fields := strings.Fields(line)
			if !in || len(fields) < 2 {
				continue
			}
			found[strings.Join(fields[1:], " ")] = fields[0]
		}
		return found
	}
	left, right := rows(a), rows(b)
	var keys []string
	for k := range left {
		keys = append(keys, k)
	}
	for k := range right {
		if _, both := left[k]; !both {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var said []string
	for _, k := range keys {
		if left[k] == right[k] {
			continue
		}
		said = append(said, fmt.Sprintf("%8s %8s  %s", orNone(left[k]), orNone(right[k]), k))
	}
	if len(said) == 0 {
		return "(the two tallies are identical, row for row)"
	}
	return "governed unrestricted  syscall\n" + strings.Join(said, "\n")
}

func orNone(count string) string {
	if count == "" {
		return "-"
	}
	return count
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

	// entered is when a's Apply was first entered for this push, and acked is
	// when the Apply that acknowledged it came back. They are what the
	// early-push run is judged on — a push entered before the enforcing sandbox
	// attached and acknowledged only after it had the document — and they are
	// unix nanoseconds in atomics for applied's reason: they are written on a's
	// goroutine and read on the test's.
	entered, acked atomic.Int64

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

// enteredApply records the first moment a's Apply was entered for this push, and
// enteredAt reads it back. Only the first is kept: a push refused for being
// early is retried, and what the early-push run asserts is about the attempt
// that was made before the sandbox existed.
func (p *pusher) enteredApply(at time.Time) { p.entered.CompareAndSwap(0, at.UnixNano()) }

// ackedApply records the moment the Apply that acknowledged this push returned.
func (p *pusher) ackedApply(at time.Time) { p.acked.Store(at.UnixNano()) }

func (p *pusher) enteredAt() time.Time { return stamp(p.entered.Load()) }
func (p *pusher) ackedAt() time.Time   { return stamp(p.acked.Load()) }

// stamp turns one of those nanosecond counts back into a time, and zero into the
// zero time rather than into 1970.
func stamp(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

func (p *pusher) errOr() error {
	if p == nil {
		return fmt.Errorf("no pusher reached a in this run")
	}
	return p.err
}

// pusherFor builds one pusher and pushes nothing. Building it is a tunneld with
// a platform, a verifier and a listener, which is a hundred milliseconds of key
// material on this machine — and the window a first push has to land in is
// about that wide, so it is built before the wait and not after it.
func (l *loopback) pusherFor(t *testing.T, name, policy string) *pusher {
	p := &pusher{name: name, policy: policy, digest: digestOf(policy)}
	p.td = l.w.start(t, name, rootImage, tunneld.PeerTable{"a": l.aTd.Addr().String()}, policy,
		func(r *attest.Refusal) { p.refusals.add(r.LogString()) })
	return p
}

// push is the push itself: one handshake, one document, one acknowledgement.
// The policy is fixed at New because a push is once per tunnel, so a second
// policy is a second peer.
//
// It retries back to back, and for two sentences. The boot controller honours a
// policy only from a loader whose state is `started` (runsc/boot/policy.go:106)
// and [sandbox.Host.Apply] refuses a push with nothing to push to — so there is
// a window, most of a sandbox's startup long, in which a push can be made and
// cannot land. A push refused in it takes its tunnel with it, so a retry is a
// fresh handshake and a fresh push, which is what Peer does once the connection
// it had has gone.
//
// There is no way to be in front of it. The workload starts when the sentry
// starts it, and a policy cannot be applied before that moment, so the first
// milliseconds of every workload run under the boot table and nothing else.
// That is not this harness's race: it is the arrangement's, and the number of
// milliseconds is recorded per run rather than hidden. Retrying with no pause
// between attempts is what makes it small — the handshake of the attempt that
// wins is already under way when the sandbox starts.
//
// Every attempt is one refusal in a's log, and the count is recorded.
func (p *pusher) push(l *loopback, stop <-chan struct{}) *pusher {
	l.pushing.Store(p)
	for p.tries = 1; ; p.tries++ {
		began := time.Now()
		_, p.err = p.td.Peer(l.ctx, "a")
		p.took = time.Since(began)
		if p.err == nil || p.tries >= 60 || !l.tooEarly(began) {
			break
		}
		l.out.logf("%s  push %d was too early: %v", p.name, p.tries, p.err)
		select {
		case <-stop:
		case <-l.ctx.Done():
		default:
			continue
		}
		break
	}
	p.at = time.Now()
	l.pushing.Store(nil)
	into := ""
	if r := l.now.Load(); r != nil {
		into = fmt.Sprintf(" %s into the run", p.at.Sub(r.began).Round(time.Millisecond))
	}
	l.out.logf("\n%s  PUSH sha256=%s bytes=%d returned after %s on attempt %d%s: err=%v", p.name, p.digest,
		len(p.policy), p.took.Round(time.Millisecond), p.tries, into, p.err)
	l.console.add(fmt.Sprintf("PUSH %s sha256=%s cold_open=%s apply=%s tries=%d err=%v",
		p.name, short(p.digest), p.took.Round(time.Millisecond), p.applyTook().Round(time.Microsecond), p.tries, p.err))
	return p
}

// notStarted is the sentry's own sentence for a policy that arrived before the
// workload did, carried back through the helper and the contract word for word.
const notStarted = "a policy is honoured only by a started one"

// notYet are the sentences in a's own log that mean a push was early rather
// than wrong. There are four because a sandbox becomes ready for a policy in
// four steps and a push can arrive between any two of them: the helper is not
// on the contract socket yet; the sentry's control socket does not exist yet;
// it exists and nobody is serving it yet; the loader has it but has not started
// the workload. Every one of them is a push that would land a moment later,
// and none of them is a verdict on the document.
var notYet = []string{
	"no sandbox is attached",
	"no such file or directory",
	"connection refused",
	notStarted,
}

// tooEarly reads a's own refusal log for the two sentences that mean "not yet"
// rather than "no".
//
// The pusher cannot tell them apart and is not meant to: what crosses the
// tunnel is the fixed sentence `the sandbox beside this tunneld did not apply
// it`, because which of its own reasons a guest refused for is a fact about
// that guest (attest/tunneld/push.go, the ack sentences). An
// [attest.Refusal] answers Error() with "attest: verification failed" and keeps
// the rest for the log. This harness is on both sides of one loopback and reads
// the operator's log, which is the only place the reason is written down — and
// it is why a widening, refused for a reason that is not one of these two, is
// not retried at all.
func (l *loopback) tooEarly(since time.Time) bool {
	for _, said := range l.console.after(since, "REFUSED ") {
		for _, sentence := range notYet {
			if strings.Contains(said.text, sentence) {
				return true
			}
		}
	}
	return false
}

// appliedAt is a's contract socket with a's own clock on it. It embeds the host
// rather than the interface, so what tunneld watches after a push is still a
// sandbox that says which policy it is enforcing.
type appliedAt struct {
	*sandbox.Host
	l *loopback
}

func (h *appliedAt) Apply(ctx context.Context, policy []byte) error {
	p := h.l.pushing.Load()
	if p != nil {
		p.enteredApply(time.Now())
	}
	took, err := timeApply(ctx, h.Host, policy, h.l.out, "a")
	if p != nil {
		p.applied.Store(int64(took))
		if err == nil {
			p.ackedApply(time.Now())
		}
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
	if l.holdStart != nil && !l.until(stop, 30*time.Second, l.holdStart) {
		t.Fatalf("%s: what this run waits for before starting the sandbox did not happen", name)
	}
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
	ok := l.until(stop, 2*time.Minute, func() bool { return l.aHost.Attached() > 0 })
	if r := l.now.Load(); ok && r != nil {
		l.out.logf("%s  a sandbox is on a's socket, %s into the run", r.name, time.Since(r.began).Round(time.Millisecond))
	}
	return ok
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
		case <-time.After(2 * time.Millisecond):
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

// absDur is a duration without its sign, for a sentence that says which way
// round two moments were in words.
func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func earlierLater(a, b time.Time) string {
	if a.Before(b) {
		return "before"
	}
	return "after"
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

// networkFailures is what a strace digest says about the network, in a sentence.
//
// It is written this way because of what it kept finding: nothing. A name the
// policy in force does not carry is answered NXDOMAIN, and a resolver turns
// that into EAI_NONAME — a library result and not an errno — so the refusal
// leaves no failed syscall behind at all. The rows are matched on the syscall's
// name and not on a substring, because `futex errno=110 (connection timed out)`
// contains the word `connect`.
func networkFailures(digest string) string {
	var said []string
	for _, line := range strings.Split(digest, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[2], "errno=") {
			continue
		}
		switch fields[1] {
		case "connect", "sendto", "sendmsg", "socket":
			said = append(said, strings.TrimSpace(line))
		}
	}
	if len(said) == 0 {
		return "nothing on the network path failed. The refusal is in what the resolver answered and not in an errno, so there is no failed `connect` to find."
	}
	return "\n\n```\n" + strings.Join(said, "\n") + "\n```\n"
}
