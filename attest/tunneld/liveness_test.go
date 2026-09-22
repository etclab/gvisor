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

package tunneld_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
)

// The eleventh reason: a peer that applied the policy pushed at it and stopped
// enforcing it (contract v3, attest/sandbox/live.go).
//
// The push tests above are about whether a policy landed. These are about what
// happens afterwards, which ticket 23 measured as nothing at all: the sandbox
// acknowledged, its workload died, and the tunnel went on carrying streams
// under a policy nobody was enforcing. The refusal is this side's own — nothing
// about it crosses the wire — so what the pusher sees is what it sees for every
// refusal after admission, which is that its tunnel went.
//
// The sandbox is a second process in every case here, because the three ways
// liveness is lost are only three things when there is a process that can stop
// without closing.

// livenessSocketEnv names the socket for the re-executed test binary. Its
// presence is what turns one of these tests into the sandbox process.
const livenessSocketEnv = "GVISOR_TUNNELD_LIVENESS_SOCKET"

// anotherPolicysDigest is a well-formed digest that is not the pushed policy's:
// what a sandbox pulses once it is enforcing something else.
var anotherPolicysDigest = strings.Repeat("00", 32)

// a livenessCase is one way a sandbox stops enforcing what it acknowledged, and
// what the operator's console should say about it.
type livenessCase struct {
	name    string
	signal  syscall.Signal
	says    string
	within  time.Duration
	explain string
}

// TestASandboxThatStopsEnforcingAPushedPolicyClosesTheTunnel drives the
// eleventh reason through tunneld, three ways.
func TestASandboxThatStopsEnforcingAPushedPolicyClosesTheTunnel(t *testing.T) {
	for _, c := range []livenessCase{
		{
			name:    "it stops pulsing",
			signal:  syscall.SIGSTOP,
			says:    "missed 3 pulses",
			within:  8 * time.Second,
			explain: "a sandbox stopped in its tracks is one whose socket is open and silent",
		},
		{
			name:    "it pulses another policy's digest",
			signal:  syscall.SIGUSR1,
			says:    "expected",
			within:  4 * time.Second,
			explain: "a sandbox enforcing something else says so, and what it says is not what was pushed",
		},
		{
			name:    "its workload exits",
			signal:  syscall.SIGUSR2,
			says:    "closed its socket",
			within:  4 * time.Second,
			explain: "the workload ends, the sandbox's client closes, and the attachment goes",
		},
	} {
		t.Run(c.name, func(t *testing.T) { runLivenessCase(t, c) })
	}
}

// runLivenessCase puts a sandbox in another process beside the receiving
// tunneld, pushes a policy over the tunnel, and then makes that sandbox stop
// enforcing it.
func runLivenessCase(t *testing.T, c livenessCase) {
	t.Helper()
	console := &eventLog{}
	var child *exec.Cmd
	pair := startLivenessPair(t, func(b *pushNode) {
		host, err := sandbox.Listen(filepath.Join(t.TempDir(), "sandbox.sock"), b.Tunneld,
			func(format string, a ...any) { console.record(fmt.Sprintf(format, a...)) })
		if err != nil {
			t.Fatalf("listening for a sandbox: %v", err)
		}
		t.Cleanup(func() { host.Close() })
		child = startLivenessSandbox(t, host.Path())
		for host.Attached() == 0 {
			time.Sleep(time.Millisecond)
		}
		b.Attach(host)
	})

	// Two pulses, so that what is interrupted is the steady state rather than
	// the acknowledgement.
	time.Sleep(2 * sandbox.DefaultPulse)
	if err := child.Process.Signal(c.signal); err != nil {
		t.Fatalf("signalling the sandbox with %v: %v", c.signal, err)
	}

	if err := endsWithin(t, pair.stream, c.within); err == nil {
		t.Errorf("the tunnel outlived the policy it was carrying: %s", c.explain)
	}
	r := pair.b.refusals.next(t)
	if got := r.Reason(); got != attest.ReasonPolicyNotLive {
		t.Errorf("b refused with %v; want %v (log: %s)", got, attest.ReasonPolicyNotLive, r.LogString())
	}
	if line := r.LogString(); !strings.Contains(line, attest.ReasonPolicyNotLive.String()) {
		t.Errorf("the operator log does not name the reason: %q", line)
	}
	if d := r.Detail(); !strings.Contains(d, c.says) {
		t.Errorf("the refusal's detail is %q; want it to say %q", d, c.says)
	}

	// The console a hardware transcript is read off: the digest that was pushed
	// when it landed, and what was lost when it stopped.
	sum := sha256.Sum256([]byte(policyV1))
	applied := fmt.Sprintf("SANDBOX applied format=%s version=%d bytes=%d sha256=%s",
		sandbox.PolicyFormat, sandbox.PolicyVersion, len(policyV1), hex.EncodeToString(sum[:]))
	said := console.order()
	if !strings.Contains(said, applied) {
		t.Errorf("the sandbox console does not carry the digest that was pushed:\n%s", said)
	}
	if !strings.Contains(said, "SANDBOX liveness lost: ") || !strings.Contains(said, c.says) {
		t.Errorf("the sandbox console does not say what was lost: %q", said)
	}
	// The pushing side is untouched by any of this. Its push was acknowledged,
	// so makePush refused nothing; all it ever learns is that its stream ended.
	if logged := pair.a.refusals.none(); len(logged) != 0 {
		t.Errorf("the pushing side refused something too: %s", logged[0].LogString())
	}
}

// TestASandboxInThisProcessIsNotWatched: only a sandbox across a process
// boundary has liveness to lose, so a tunneld with the null sandbox in its own
// process carries its tunnel exactly as it did before contract v3.
func TestASandboxInThisProcessIsNotWatched(t *testing.T) {
	pair := startLivenessPair(t, func(b *pushNode) { b.Attach(sandbox.NewNull(b.Tunneld, nil)) })

	// Five seconds is past three missed pulses twice over: a watch that had
	// been started on a sandbox which never pulses would have fired by now.
	if err := endsWithin(t, pair.stream, 5*time.Second); err != nil {
		t.Errorf("the tunnel ended with %v; a sandbox in this process has no liveness to lose", err)
	}
	if logged := pair.b.refusals.none(); len(logged) != 0 {
		t.Errorf("b refused a tunnel whose sandbox is in its own process: %s", logged[0].LogString())
	}
}

func TestALivenessWatchSurvivesThePushingTunnelBeingClosedAndStillReportsTheLoss(t *testing.T) {
	for _, c := range []struct {
		name   string
		signal syscall.Signal
		says   string
	}{
		{
			name:   "on a miss",
			signal: syscall.SIGSTOP,
			says:   "missed 3 pulses",
		},
		{
			name:   "on a mismatch",
			signal: syscall.SIGUSR1,
			says:   "expected",
		},
		{
			name:   "on a close",
			signal: syscall.SIGUSR2,
			says:   "closed its socket",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			console := &eventLog{}
			var child *exec.Cmd
			var host *sandbox.Host
			pair := startLivenessPair(t, func(b *pushNode) {
				var err error
				host, err = sandbox.Listen(filepath.Join(t.TempDir(), "sandbox.sock"), b.Tunneld,
					func(format string, a ...any) { console.record(fmt.Sprintf(format, a...)) })
				if err != nil {
					t.Fatalf("listening for a sandbox: %v", err)
				}
				t.Cleanup(func() { host.Close() })
				child = startLivenessSandbox(t, host.Path())
				for host.Attached() == 0 {
					time.Sleep(time.Millisecond)
				}
				b.Attach(host)
			})

			// Steady state.
			time.Sleep(2 * sandbox.DefaultPulse)

			// Close the stream and the pushing tunnel.
			pair.stream.Close()
			pair.a.Close()

			time.Sleep(100 * time.Millisecond)

			if err := child.Process.Signal(c.signal); err != nil {
				t.Fatalf("signalling the sandbox with %v: %v", c.signal, err)
			}

			r := pair.b.refusals.next(t)
			if got := r.Reason(); got != attest.ReasonPolicyNotLive {
				t.Errorf("b refused with %v; want %v (log: %s)", got, attest.ReasonPolicyNotLive, r.LogString())
			}
			if d := r.Detail(); !strings.Contains(d, c.says) {
				t.Errorf("the refusal detail is %q; want it to say %q", d, c.says)
			}
			if d := r.Detail(); !strings.Contains(d, "no tunnel was closed because none was open") {
				t.Errorf("the refusal detail %q does not say no tunnel was closed because none was open", d)
			}

			// The enforcing attachment must have been dropped.
			deadline := time.Now().Add(5 * time.Second)
			for host.Attached() != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("timed out waiting for enforcing attachment to drop")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

// policyNarrower is a second version 1 policy, narrower than policyV1 by the
// letters it leaves empty. What makes it the case this test is about is only
// that its bytes — and so its digest — are not policyV1's; tunneld reads the
// envelope and never n, f or x, so which of the two is the narrower one is the
// sentry's reading and not this one's.
const policyNarrower = `{"format":"policy","version":1,"n":["one"],"f":[],"x":[]}`

// aSlowInstall is longer than the quarter-pulse a watch looks at the heartbeat
// on (watchInterval, attest/sandbox/host.go), so a sandbox that spends this long
// answering a push is certain to be looked at while it is answering.
const aSlowInstall = sandbox.DefaultPulse / 2

// TestASecondPushOfANarrowerPolicyIsNotAMismatch is the lawful case a mismatch
// must not be read as: a second peer pushes a narrower policy, the sandbox takes
// it, and from then on it pulses that policy's digest — which is not the digest
// the watch over the first policy was started with.
//
// Reading that as a lost claim would close the tunnel and drop the enforcing
// attachment for a narrowing the peer was entitled to make, and with the helper
// exiting when tunneld closes its client, dropping it tears the sandbox down. So
// the watch over the old policy is retired before the new one is pushed, and the
// only thing a mismatch can still mean is a sandbox pulsing a digest nobody
// applied.
func TestASecondPushOfANarrowerPolicyIsNotAMismatch(t *testing.T) {
	if os.Getenv(livenessSocketEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	console := &eventLog{}
	var host *sandbox.Host

	// A sandbox that says which policy it is enforcing as it installs it and
	// only then answers, which is what a sentry handed a policy does and is the
	// window a watch left over from the previous policy would look into. The
	// client reaches its own callback through a channel, because the callback
	// runs on the goroutine Dial starts and the variable would otherwise be
	// written and read with nothing ordering the two.
	dialed := make(chan *sandbox.Client, 1)
	pair := startLivenessPair(t, func(b *pushNode) {
		var client *sandbox.Client
		host, client = hostBeside(t, b, console, func(_ context.Context, policy []byte) error {
			c := <-dialed
			dialed <- c
			sum := sha256.Sum256(policy)
			if err := c.Alive(hex.EncodeToString(sum[:])); err != nil {
				return err
			}
			time.Sleep(aSlowInstall)
			return nil
		})
		dialed <- client
	})

	// Two pulses of the first policy, so that what the narrowing interrupts is
	// the steady state and not the acknowledgement.
	time.Sleep(2 * sandbox.DefaultPulse)

	ch, err := pair.a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	defer ch.Close()
	if answer := pushed(t, ch, policyNarrower); !answer.OK {
		t.Fatalf("the narrowing was refused: %s", answer.Reason)
	}

	// Past every look a watch left over from the first policy would have taken.
	time.Sleep(4 * aSlowInstall)

	if logged := pair.b.refusals.none(); len(logged) != 0 {
		t.Errorf("b refused a lawful narrowing: %s", logged[0].LogString())
	}
	if n := host.Attached(); n != 1 {
		t.Errorf("%d sandboxes are attached after the narrowing; want the enforcing one still there", n)
	}
	if err := endsWithin(t, pair.stream, 500*time.Millisecond); err != nil {
		t.Errorf("the tunnel the first policy arrived on ended with %v; a narrowing closes no tunnel", err)
	}
	if said := console.order(); strings.Contains(said, "liveness lost") {
		t.Errorf("the host reported a lost claim for a policy the sandbox had just taken:\n%s", said)
	}
}

// waitFor blocks until what it is waiting for is true, or fails the test. Every
// wait in this file is bounded: a sandbox that never attaches is a test that
// says so rather than a test that hangs.
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// hostBeside puts a sandbox host beside the receiving tunneld with one
// in-process enforcing client attached to it, and hands back both. The console
// it writes to is the host's, which is where the sandbox's own sentences appear.
func hostBeside(t *testing.T, b *pushNode, console *eventLog, apply func(context.Context, []byte) error) (*sandbox.Host, *sandbox.Client) {
	t.Helper()
	host, err := sandbox.Listen(filepath.Join(t.TempDir(), "sandbox.sock"), b.Tunneld,
		func(format string, a ...any) { console.record(fmt.Sprintf(format, a...)) })
	if err != nil {
		t.Fatalf("listening for a sandbox: %v", err)
	}
	t.Cleanup(func() { host.Close() })
	client, err := sandbox.Dial(host.Path(), sandbox.RoleEnforcing, apply)
	if err != nil {
		t.Fatalf("dialing %s: %v", host.Path(), err)
	}
	t.Cleanup(func() { client.Close() })
	waitFor(t, "the sandbox to attach", func() bool { return host.Attached() > 0 })
	b.Attach(host)
	return host, client
}

// TestAWatchThatHasFiredIsNotStartedAgainByAPushThatDidNotLand is the other way
// a watch outlives what it was over. A watch that has reported its loss has had
// that loss answered — the tunnel closed, the attachment given up — so it is
// spent; a later push that does not land must not put it back on, because the
// digest it names is one nothing is enforcing and the sandbox says so at once.
func TestAWatchThatHasFiredIsNotStartedAgainByAPushThatDidNotLand(t *testing.T) {
	if os.Getenv(livenessSocketEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	console := &eventLog{}
	var (
		host  *sandbox.Host
		first *sandbox.Client
	)
	pair := startLivenessPair(t, func(b *pushNode) {
		host, first = hostBeside(t, b, console, func(context.Context, []byte) error { return nil })
	})

	// The first sandbox goes, which is a loss the watch reports and answers.
	first.Close()
	if r := pair.b.refusals.next(t); r.Reason() != attest.ReasonPolicyNotLive {
		t.Fatalf("b refused with %v; want %v (log: %s)", r.Reason(), attest.ReasonPolicyNotLive, r.LogString())
	}
	waitFor(t, "the first sandbox to go", func() bool { return host.Attached() == 0 })

	// A second sandbox attaches and refuses what the next peer pushes, which is
	// a push that does not land and so a watch that would be started again.
	second, err := sandbox.Dial(host.Path(), sandbox.RoleEnforcing, func(context.Context, []byte) error {
		return errors.New("this sandbox will not have it")
	})
	if err != nil {
		t.Fatalf("dialing the second sandbox: %v", err)
	}
	defer second.Close()
	waitFor(t, "the second sandbox to attach", func() bool { return host.Attached() == 1 })

	c := startPushNode(t, "sandbox-c", imageA, admitting(imageB), nil, toward("b", pair.b), pushing(policyNarrower))
	if _, err := c.Peer(ctx(t), "b"); err == nil {
		t.Fatal("a push the sandbox refused was acknowledged")
	}

	// Past every look the spent watch would have taken had it been started
	// again, and past the refusal it would have reported at once.
	time.Sleep(4 * aSlowInstall)

	var live int
	for _, r := range pair.b.refusals.none() {
		if r.Reason() == attest.ReasonPolicyNotLive {
			live++
		}
	}
	if live != 1 {
		t.Errorf("b logged %d %v refusals; want the one for the sandbox that went, and none for the push that did not land", live, attest.ReasonPolicyNotLive)
	}
	if n := host.Attached(); n != 1 {
		t.Errorf("%d sandboxes are attached; want the second one still there", n)
	}
	select {
	case <-second.Done():
		t.Error("the second sandbox was closed by a watch that had already fired")
	default:
	}
}

// a livenessPair is what every test here is run over: a delegator, a receiver
// with something beside it, and a stream held open on the tunnel between them.
type livenessPair struct {
	a, b   *pushNode
	stream *tunnel.Stream
}

// startLivenessPair starts the two, puts beside's sandbox next to the receiving
// one, and asks for the peer — which is what pushes the policy. The stream is
// opened before anything else happens to the sandbox so that a test sees the
// tunnel end rather than infer it from a channel that would quietly re-dial.
func startLivenessPair(t *testing.T, beside func(*pushNode)) livenessPair {
	t.Helper()
	b := startPushNode(t, "sandbox-b", imageB, admitting(imageA), nil)
	beside(b)
	a := startPushNode(t, "sandbox-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))
	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}
	t.Cleanup(func() { ch.Close() })
	stream, err := ch.OpenStream(ctx(t))
	if err != nil {
		t.Fatalf("opening a stream: %v", err)
	}
	t.Cleanup(func() { stream.Close() })
	return livenessPair{a: a, b: b, stream: stream}
}

// startLivenessSandbox re-executes this test binary as the sandbox beside the
// receiving tunneld.
func startLivenessSandbox(t *testing.T, socket string) *exec.Cmd {
	t.Helper()
	if os.Getenv(livenessSocketEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	said, err := os.Create(filepath.Join(t.TempDir(), "sandbox.txt"))
	if err != nil {
		t.Fatalf("creating the sandbox's log: %v", err)
	}
	defer said.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestTunneldLivenessChildProcess$", "-test.v")
	child.Env = append(os.Environ(), livenessSocketEnv+"="+socket)
	child.Stdout, child.Stderr = said, said
	if err := child.Start(); err != nil {
		t.Fatalf("starting the sandbox process: %v", err)
	}
	t.Cleanup(func() {
		// SIGCONT first, so that a stopped sandbox is reaped rather than left.
		child.Process.Signal(syscall.SIGCONT)
		child.Process.Kill()
		child.Wait()
		if t.Failed() {
			if out, err := os.ReadFile(said.Name()); err == nil {
				t.Logf("the sandbox process said:\n%s", out)
			}
		}
	})
	return child
}

// TestTunneldLivenessChildProcess is the sandbox for the tests above, in the
// process they re-executed. It is skipped in every ordinary run.
//
// It acknowledges what it is pushed, which starts the heartbeat, and then waits
// to be told what to become: a sandbox enforcing something else (SIGUSR1), a
// sandbox whose workload has exited (SIGUSR2), or — with no signal at all, by
// being stopped — a sandbox that has gone quiet.
func TestTunneldLivenessChildProcess(t *testing.T) {
	socket := os.Getenv(livenessSocketEnv)
	if socket == "" {
		t.Skip("not the sandbox process; " + livenessSocketEnv + " is unset")
	}
	client, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()

	told := make(chan os.Signal, 2)
	signal.Notify(told, syscall.SIGUSR1, syscall.SIGUSR2)
	switch <-told {
	case syscall.SIGUSR1:
		if err := client.Alive(anotherPolicysDigest); err != nil {
			t.Fatalf("saying it enforces something else: %v", err)
		}
		time.Sleep(time.Minute)
	case syscall.SIGUSR2:
		// The workload exited: this process goes, and with it the socket.
	}
}
