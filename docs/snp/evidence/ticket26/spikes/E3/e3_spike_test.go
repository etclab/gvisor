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

// Ticket 26, spike E3: what one `alive` per second costs, how far a one-second
// ticker drifts, and how long a tunnel takes to go down after the sandbox at
// the far end stops enforcing what was pushed to it.
//
// This file is a throwaway. run.sh copies it into attest/tunneld, runs it, and
// removes it again; it lives in the evidence directory and not in the tree.
// Everything with a name here is prefixed e3 so that it cannot collide with the
// package's own tests, whose harness (start, startPushNode, toward, pushing,
// ctx, imageA, imageB, admitting, policyV1) it reuses wholesale.
//
// The three teardown cases are the three ways liveness is lost:
//
//	kill      SIGKILL to the sandbox process — its socket closes
//	wrong     SIGUSR1, on which it pulses a digest that is not the pushed one
//	stop      SIGSTOP — it stops pulsing without closing anything
//
// SIGSTOP is the honest way to write "a client that stops pulsing without
// closing": the process is still there, its socket is still open, and nothing
// is coming out of it. It is also a real failure mode rather than an invented
// one.
package tunneld_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/sandbox"
)

const (
	e3SocketEnv = "E3_SANDBOX_SOCKET"
	e3ModeEnv   = "E3_MODE"
	e3CountEnv  = "E3_COUNT"
)

// e3Sentinel is a digest no policy has: the child pulses it to say "I am done",
// which the parent sees as the watch firing on a mismatch. It is how a phase
// ends at an instant the parent can timestamp without the host growing an
// accessor nothing in production would use.
var e3Sentinel = strings.Repeat("e3", 32)

// e3Trials is how many times each teardown case is measured.
const e3Trials = 10

func TestE3(t *testing.T) {
	if os.Getenv(e3ModeEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	t.Run("cost", e3Cost)
	t.Run("drift", e3Drift)
	t.Run("teardown", e3Teardown)
}

// e3Cost measures both costs a heartbeat has: what it costs the sandbox to send
// one, and what it costs the far side to receive one.
//
// The receiving cost is measured twice, because the two numbers answer
// different questions. At one hertz — the rate the contract actually runs at —
// the cost is dominated by waking a process up, and that is what a guest pays.
// In a burst the wakeup is amortised over thousands of messages, and that is
// the marginal cost of the message itself.
func e3Cost(t *testing.T) {
	const burst = 10000
	const window = 10 * time.Second

	host := e3Host(t, "cost")

	// Nothing attached but the process itself: the floor every other number
	// here is measured above. It is taken before the sandbox process exists,
	// because a client dials as soon as it is started.
	idle := e3CPUOver(window)
	t.Logf("E3-cost: idle CPU with nothing attached: %v over %v", idle, window)

	child, out := e3Child(t, host.Path(), "cost", burst)
	e3Attach(t, host)
	pulsing := e3CPUOver(window)
	perPulse := (pulsing - idle) / time.Duration(window/sandbox.DefaultPulse)
	t.Logf("E3-cost: CPU with one attachment pulsing at 1 Hz: %v over %v", pulsing, window)
	t.Logf("E3-cost: receive side, %d pulses at 1 Hz: %v of CPU each", int(window/sandbox.DefaultPulse), perPulse)

	lost := host.Watch(context.Background(), e3Digest(policyV1))
	began, cpuBefore := time.Now(), e3CPU()
	e3Signal(t, child, syscall.SIGUSR1)
	e3Await(t, lost)
	wall, cpu := time.Since(began), e3CPU()-cpuBefore
	t.Logf("E3-cost: receive side, a burst of %d: %v of CPU over %v wall (%v of CPU each, %v of wall each)",
		burst, cpu, wall, cpu/burst, wall/burst)
	t.Logf("E3-cost: the sandbox said:\n%s", e3Read(t, out))
}

// e3Drift measures what a one-second ticker is worth over a minute: the
// sandbox's own view of its ticker, tick by tick, and the parent's view of how
// long sixty pulses took to arrive.
func e3Drift(t *testing.T) {
	const pulses = 60

	host := e3Host(t, "drift")
	child, out := e3Child(t, host.Path(), "drift", pulses)
	e3Attach(t, host)

	lost := host.Watch(context.Background(), e3Digest(policyV1))
	began := time.Now()
	e3Signal(t, child, syscall.SIGUSR1)
	e3Await(t, lost)
	elapsed := time.Since(began)
	t.Logf("E3-drift: %d pulses, sent and received: %v of wall (%v of drift, at most %v of it the watch's granularity)",
		pulses, elapsed, elapsed-pulses*sandbox.DefaultPulse, sandbox.DefaultPulse/4)
	t.Logf("E3-drift: the sandbox said:\n%s", e3Read(t, out))
}

// e3Teardown measures the wall time from the sandbox failing to the pusher's
// stream ending, ten times for each of the three ways liveness is lost.
func e3Teardown(t *testing.T) {
	for _, how := range []string{"kill", "wrong", "stop"} {
		var took []time.Duration
		for i := 0; i < e3Trials; i++ {
			t.Run(fmt.Sprintf("%s-%02d", how, i+1), func(t *testing.T) {
				d, reason := e3OneTeardown(t, how, i)
				took = append(took, d)
				t.Logf("E3-teardown %s trial %d: %v, refused as %v", how, i+1, d, reason)
			})
		}
		e3Summarise(t, how, took)
	}
}

// e3OneTeardown is one trial: two tunnelds, a sandbox in another process beside
// the receiving one, a policy pushed over the tunnel, a stream held open on it,
// and then the sandbox made to stop enforcing what it acknowledged.
func e3OneTeardown(t *testing.T, how string, trial int) (time.Duration, attest.Reason) {
	b := startPushNode(t, "e3-b", imageB, admitting(imageA), nil)
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, b.Tunneld, nil)
	if err != nil {
		t.Fatalf("listening for a sandbox: %v", err)
	}
	t.Cleanup(func() { host.Close() })
	child, _ := e3Child(t, socket, "hold", 0)
	e3WaitAttached(t, host)
	b.Attach(host)

	a := startPushNode(t, "e3-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))
	stream, err := a.Open(ctx(t), "b")
	if err != nil {
		t.Fatalf("opening a stream to b: %v", err)
	}
	t.Cleanup(func() { stream.Close() })
	ended := make(chan time.Time, 1)
	go func() {
		io.ReadAll(stream)
		ended <- time.Now()
	}()

	// Two pulses, so that the steady state is the thing being interrupted
	// rather than the acknowledgement, and then a tenth of a pulse more per
	// trial. The offset is the point of the ten trials: a workload does not die
	// on the beat, and how long a teardown takes depends on where in the
	// interval it died — for a miss, on how old the last pulse already was, and
	// for the other two, on where the watch's own tick fell.
	time.Sleep(2*sandbox.DefaultPulse + time.Duration(trial)*sandbox.DefaultPulse/10)

	began := time.Now()
	switch how {
	case "kill":
		e3Signal(t, child, syscall.SIGKILL)
	case "wrong":
		e3Signal(t, child, syscall.SIGUSR1)
	case "stop":
		e3Signal(t, child, syscall.SIGSTOP)
	}
	select {
	case at := <-ended:
		return at.Sub(began), b.refusals.next(t).Reason()
	case <-time.After(30 * time.Second):
		t.Fatalf("the tunnel was still up 30s after %s", how)
		return 0, attest.ReasonNone
	}
}

func e3Summarise(t *testing.T, how string, took []time.Duration) {
	if len(took) == 0 {
		return
	}
	sorted := slices.Clone(took)
	slices.Sort(sorted)
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	t.Logf("E3-teardown %s: n=%d min=%v median=%v max=%v mean=%v", how, len(sorted),
		sorted[0], sorted[len(sorted)/2], sorted[len(sorted)-1], total/time.Duration(len(sorted)))
	var each []string
	for _, d := range took {
		each = append(each, d.String())
	}
	t.Logf("E3-teardown %s: every trial in order: %s", how, strings.Join(each, " "))
}

// e3Host is a tunneld with a socket beside it, for the phases that need no
// tunnel.
func e3Host(t *testing.T, mode string) *sandbox.Host {
	b := start(t, "e3-"+mode, imageB, admitting(imageA), nil)
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, b.Tunneld, nil)
	if err != nil {
		t.Fatalf("listening for a sandbox: %v", err)
	}
	t.Cleanup(func() { host.Close() })
	return host
}

// e3Attach waits for the sandbox process, pushes the policy at it and requires
// the acknowledgement, which is what starts the heartbeat.
func e3Attach(t *testing.T, host *sandbox.Host) {
	t.Helper()
	e3WaitAttached(t, host)
	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("pushing the policy: %v", err)
	}
}

// e3Child re-executes this test binary as the sandbox, with its stdout in a
// file the parent reads when the phase is over.
func e3Child(t *testing.T, socket, mode string, count int) (*exec.Cmd, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "sandbox-"+mode+".txt")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("creating %s: %v", out, err)
	}
	defer f.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestE3Child$", "-test.v")
	child.Env = append(os.Environ(),
		e3SocketEnv+"="+socket, e3ModeEnv+"="+mode, e3CountEnv+"="+strconv.Itoa(count))
	child.Stdout, child.Stderr = f, f
	if err := child.Start(); err != nil {
		t.Fatalf("starting the sandbox process: %v", err)
	}
	t.Cleanup(func() {
		if child.Process != nil {
			// SIGCONT first: SIGKILL reaches a stopped process, but Wait does
			// not return for one that was never continued on some kernels.
			child.Process.Signal(syscall.SIGCONT)
			child.Process.Kill()
			child.Wait()
		}
	})
	return child, out
}

func e3WaitAttached(t *testing.T, host *sandbox.Host) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for host.Attached() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sandbox process never attached")
		}
		time.Sleep(time.Millisecond)
	}
}

func e3Signal(t *testing.T, child *exec.Cmd, sig syscall.Signal) {
	t.Helper()
	if err := child.Process.Signal(sig); err != nil {
		t.Fatalf("signalling the sandbox with %v: %v", sig, err)
	}
}

func e3Await(t *testing.T, lost <-chan error) {
	t.Helper()
	select {
	case err, ok := <-lost:
		if !ok {
			t.Fatal("the watch ended without reporting anything")
		}
		if !strings.Contains(err.Error(), e3Sentinel) {
			t.Fatalf("the watch reported %v; want the sentinel", err)
		}
	case <-time.After(5 * time.Minute):
		t.Fatal("the sandbox never reached the end of its phase")
	}
}

func e3Read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func e3Digest(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}

// e3CPU is this process's own CPU time, user plus system.
func e3CPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano()) + time.Duration(ru.Stime.Nano())
}

func e3CPUOver(d time.Duration) time.Duration {
	before := e3CPU()
	time.Sleep(d)
	return e3CPU() - before
}

// TestE3Child is the sandbox, in the process TestE3 re-executed. It is skipped
// in every ordinary run.
func TestE3Child(t *testing.T) {
	socket := os.Getenv(e3SocketEnv)
	if socket == "" {
		t.Skip("not the sandbox process; " + e3SocketEnv + " is unset")
	}
	count, _ := strconv.Atoi(os.Getenv(e3CountEnv))

	// The composition a sandbox in another process makes: a client that
	// acknowledges what it is pushed, and therefore pulses the digest of it.
	client, err := sandbox.Dial(socket, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()

	go1 := make(chan os.Signal, 1)
	signal.Notify(go1, syscall.SIGUSR1)

	switch mode := os.Getenv(e3ModeEnv); mode {
	case "hold":
		// Pulse until something is done to this process. SIGUSR1 means "say you
		// are enforcing something else"; SIGKILL and SIGSTOP say the rest.
		<-go1
		if err := client.Alive(e3Sentinel); err != nil {
			t.Fatalf("pulsing the sentinel: %v", err)
		}
		time.Sleep(5 * time.Minute)
	case "cost":
		<-go1
		e3Burst(t, client, count)
		time.Sleep(5 * time.Minute)
	case "drift":
		<-go1
		e3Ticker(t, count)
		if err := client.Alive(e3Sentinel); err != nil {
			t.Fatalf("pulsing the sentinel: %v", err)
		}
		time.Sleep(5 * time.Minute)
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

// e3Burst is the send side's cost: n pulses as fast as they will go, each one
// timed on its own.
func e3Burst(t *testing.T, client *sandbox.Client, n int) {
	digest := e3Digest(policyV1)
	each := make([]time.Duration, 0, n)
	began := time.Now()
	for i := 0; i < n; i++ {
		at := time.Now()
		if err := client.Alive(digest); err != nil {
			t.Fatalf("pulse %d of %d: %v", i, n, err)
		}
		each = append(each, time.Since(at))
	}
	wall := time.Since(began)
	slices.Sort(each)
	var total time.Duration
	for _, d := range each {
		total += d
	}
	fmt.Printf("E3-child: send side, %d pulses in %v (%v each on average)\n", n, wall, wall/time.Duration(n))
	fmt.Printf("E3-child: send side per pulse: min=%v p50=%v p90=%v p99=%v max=%v mean=%v\n",
		each[0], each[n/2], each[n*9/10], each[n*99/100], each[n-1], total/time.Duration(n))
	if err := client.Alive(e3Sentinel); err != nil {
		t.Fatalf("pulsing the sentinel: %v", err)
	}
}

// e3Ticker is the drift of the ticker Client.pulse is built on, measured by the
// same construct in the same process under the same load.
func e3Ticker(t *testing.T, ticks int) {
	tick := time.NewTicker(sandbox.DefaultPulse)
	defer tick.Stop()
	began := time.Now()
	var worst time.Duration
	var last time.Duration
	var gaps []time.Duration
	for i := 1; i <= ticks; i++ {
		<-tick.C
		since := time.Since(began)
		gaps = append(gaps, since-last)
		last = since
		if off := since - time.Duration(i)*sandbox.DefaultPulse; off > worst {
			worst = off
		}
	}
	slices.Sort(gaps)
	fmt.Printf("E3-child: ticker, %d ticks of %v: %v elapsed, %v of cumulative drift, worst lateness %v\n",
		ticks, sandbox.DefaultPulse, last, last-time.Duration(ticks)*sandbox.DefaultPulse, worst)
	fmt.Printf("E3-child: ticker interval: min=%v p50=%v max=%v\n", gaps[0], gaps[ticks/2], gaps[ticks-1])
}
