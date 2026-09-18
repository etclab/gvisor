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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// Two sandboxes on one socket, both pulsing (contract v3).
//
// In a guest this binary is run twice against the same tunneld: once as the
// agent (`-network socket`) and once as the exit (`-exit -network socket`).
// Both are `socketSandbox`, so both are a [sandbox.Client] behind a
// [sandbox.Null], and a push fans out to both — [sandbox.Host.Apply] returns
// the first refusal and acknowledges only when every attachment has.
//
// Liveness is the same shape: every attachment that acknowledged must go on
// saying so, and one of them going quiet is the policy no longer being
// enforced. Nothing was added to agent-probe for this. The heartbeat comes from
// the client the exit already dials, which is the point worth a test.
func TestBothSandboxesOnOneSocketPulseWhatTheyAcknowledged(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, &localExit{logf: t.Logf}, func(format string, a ...any) { t.Logf(format, a...) })
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	// The agent's sandbox and the exit's, in the order the guest starts them.
	_, agent, err := socketSandbox(socket, t.Logf)
	if err != nil {
		t.Fatalf("the agent's sandbox: %v", err)
	}
	defer agent.Close()
	_, exit, err := socketSandbox(socket, t.Logf)
	if err != nil {
		t.Fatalf("the exit's sandbox: %v", err)
	}
	defer exit.Close()
	waitForAttached(t, host, 2)

	if err := host.Apply(context.Background(), []byte(p0)); err != nil {
		t.Fatalf("pushing the policy at both: %v", err)
	}
	pushed := digestOf(p0)

	// Four seconds without a loss is the assertion that both are pulsing: an
	// attachment that acknowledged and then said nothing is lost after three
	// missed pulses, so either one going quiet would have shown by now.
	lost := host.Watch(context.Background(), pushed)
	select {
	case err := <-lost:
		t.Fatalf("a sandbox stopped enforcing the policy on its own: %v", err)
	case <-time.After(4 * time.Second):
	}

	// The agent's workload ends. Its attachment goes, and the policy is no
	// longer being enforced by everything that acknowledged it — although the
	// exit is still there and still pulsing.
	agent.Close()
	select {
	case err, ok := <-lost:
		if !ok {
			t.Fatal("the watch ended without reporting the agent's sandbox going")
		}
		if !strings.Contains(err.Error(), "closed its socket") {
			t.Errorf("the agent's sandbox going was reported as %q; want its socket closing", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the agent's sandbox went and the watch reported nothing")
	}
	waitForAttached(t, host, 1)

	// And the exit is the one still pulsing, carrying the digest of the policy
	// it acknowledged. A watch for any other policy is how that is read back.
	elsewhere := host.Watch(context.Background(), strings.Repeat("00", 32))
	select {
	case err, ok := <-elsewhere:
		if !ok {
			t.Fatal("the watch over the exit ended without reporting anything")
		}
		if !strings.Contains(err.Error(), pushed) {
			t.Errorf("the exit's sandbox pulses %q; want the digest of what it acknowledged, %s", err, pushed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the exit's sandbox pulsed nothing")
	}
}

func waitForAttached(t *testing.T, host *sandbox.Host, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for host.Attached() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%d sandboxes are attached; want %d", host.Attached(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func digestOf(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}
