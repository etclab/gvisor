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

// Ticket 27, spike E3: liveness after the tunnel is gone.
//
// With the idle timeout back at its 60s default, push a policy, let the tunnel
// idle out, then kill the workload. Record what the host's watch observes, what
// tunneld logs, how long after the kill it observes it, and what a stream
// opened afterwards does. Repeat with the workload stopped rather than killed,
// so that the three-miss path is covered as well as the close path. Answers
// what a miss with no tunnel to tear down should do.
package tunneld_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunnel"
)

const (
	e3SocketEnv = "E3_SANDBOX_SOCKET"
	e3ModeEnv   = "E3_MODE"
)

func TestE3LivenessAfterTunnelGone(t *testing.T) {
	if os.Getenv(e3ModeEnv) != "" {
		t.Skip("this process is the sandbox child")
	}

	t.Run("kill", func(t *testing.T) {
		e3RunLivenessScenario(t, "kill")
	})

	t.Run("stop", func(t *testing.T) {
		e3RunLivenessScenario(t, "stop")
	})
}

func e3RunLivenessScenario(t *testing.T, how string) {
	b := startPushNode(t, "e3-b", imageB, admitting(imageA), nil)
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, b.Tunneld, func(format string, a ...any) {
		t.Logf("host: "+format, a...)
	})
	if err != nil {
		t.Fatalf("listening for a sandbox: %v", err)
	}
	t.Cleanup(func() { host.Close() })

	// Start child sandbox that connects and pulses
	child := e3StartChild(t, socket)
	e3WaitAttached(t, host)
	b.Attach(host)

	// Node A dials B and pushes policy
	sum := sha256.Sum256([]byte(policyV1))
	digest := hex.EncodeToString(sum[:])
	a := startPushNode(t, "e3-a", imageA, admitting(imageB), nil, toward("b", b), pushing(policyV1))

	// Connect once to ensure tunnel is established and policy pushed
	ch, err := a.Peer(ctx(t), "b")
	if err != nil {
		t.Fatalf("a.Peer(b): %v", err)
	}

	// Apply policy to child so it knows to pulse this digest
	if err := host.Apply(ctx(t), []byte(policyV1)); err != nil {
		t.Fatalf("host.Apply: %v", err)
	}

	t.Logf("Policy pushed (digest %s). IdleTimeout=%v.", digest, tunnel.DefaultIdleTimeout)
	t.Logf("Closing connection ch and letting tunnel idle out...")
	ch.Close()

	// Wait for idle timeout (DefaultIdleTimeout = 60s)
	t.Logf("Waiting 62s for tunnel to idle out...")
	time.Sleep(62 * time.Second)

	// Verify host watch is still active
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	lost := host.Watch(watchCtx, digest)

	refusalsBefore := len(b.refusals.none())

	t.Logf("Tunnel is now idle. Triggering failure via %s...", how)
	began := time.Now()
	switch how {
	case "kill":
		syscall.Kill(child.Process.Pid, syscall.SIGKILL)
	case "stop":
		syscall.Kill(child.Process.Pid, syscall.SIGSTOP)
	}

	// 1. Record what the host's watch observes and when
	var watchErr error
	var watchElapsed time.Duration
	select {
	case err := <-lost:
		watchElapsed = time.Since(began)
		watchErr = err
		t.Logf("Host watch observed loss after %v: %v", watchElapsed, watchErr)
	case <-time.After(10 * time.Second):
		t.Fatalf("Host watch timed out without observing loss!")
	}

	// 2. Record what tunneld logs
	time.Sleep(500 * time.Millisecond)
	refusalsAfter := len(b.refusals.none())
	newRefusals := refusalsAfter - refusalsBefore
	t.Logf("Tunneld logged %d new refusal(s).", newRefusals)
	if newRefusals > 0 {
		for _, r := range b.refusals.none()[refusalsBefore:] {
			t.Logf("Tunneld logged refusal: %s", r.LogString())
		}
	} else {
		t.Logf("Tunneld logged NOTHING: watchLiveness exited silently when tunnel idled out.")
	}

	// 3. Record what a stream opened afterwards does
	t.Logf("Attempting to open a stream through host...")
	openCtx, cancelOpen := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelOpen()
	stream, err := host.Open(openCtx, "b")
	if err != nil {
		t.Logf("host.Open returned error: %v", err)
	} else {
		defer stream.Close()
		t.Logf("host.Open returned a stream to the %s sandbox (is open: true)!", how)
	}

	child.Process.Kill()
	child.Wait()
}

func e3StartChild(t *testing.T, socket string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestE3ChildProcess$")
	cmd.Env = append(os.Environ(),
		e3SocketEnv+"="+socket,
		e3ModeEnv+"=pulse",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	return cmd
}

func e3WaitAttached(t *testing.T, host *sandbox.Host) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for host.Attached() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for child to attach")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestE3ChildProcess(t *testing.T) {
	socket := os.Getenv(e3SocketEnv)
	if socket == "" {
		t.Skip("not child")
	}

	sum := sha256.Sum256([]byte(policyV1))
	digest := hex.EncodeToString(sum[:])

	client, err := sandbox.Dial(socket, func(ctx context.Context, p []byte) error {
		return nil
	})
	if err != nil {
		t.Fatalf("child dial: %v", err)
	}
	defer client.Close()

	// Pulse policyV1 until killed or stopped
	client.Alive(digest)

	tick := time.NewTicker(sandbox.DefaultPulse)
	defer tick.Stop()
	for range tick.C {
		if err := client.Alive(digest); err != nil {
			return
		}
	}
}
