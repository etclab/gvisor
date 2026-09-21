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
	client, err := sandbox.Dial(socket, func(context.Context, []byte) error { return nil })
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
