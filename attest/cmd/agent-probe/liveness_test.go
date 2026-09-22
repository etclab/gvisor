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
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// Two sandboxes on one socket, both pulsing (contract v3).
// TestBothSandboxesOnOneSocketPulseWhatTheyAcknowledged tests that an enforcing
// agent and a network exit can share a socket (contract v4): Host.Apply pushes
// only to the enforcing sandbox, which pulses what it acknowledged, and when
// the enforcing sandbox closes its socket liveness is lost while the network
// exit remains attached.
func TestBothSandboxesOnOneSocketPulseWhatTheyAcknowledged(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, &localExit{logf: t.Logf}, func(format string, a ...any) { t.Logf(format, a...) })
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	// The agent's enforcing sandbox and the exit's network attachment.
	var ready atomic.Pointer[sandbox.Null]
	agent, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(ctx context.Context, policy []byte) error {
		box := ready.Load()
		if box == nil {
			return errors.New("agent-probe: policy arrived before ready")
		}
		return box.Apply(ctx, policy)
	})
	if err != nil {
		t.Fatalf("the agent's sandbox: %v", err)
	}
	defer agent.Close()
	agentBox := sandbox.NewNull(agent, t.Logf)
	ready.Store(agentBox)

	_, exit, err := socketSandbox(socket, t.Logf)
	if err != nil {
		t.Fatalf("the exit's sandbox: %v", err)
	}
	defer exit.Close()
	for host.Attached() != 2 {
		time.Sleep(time.Millisecond)
	}

	if err := host.Apply(context.Background(), []byte(p0)); err != nil {
		t.Fatalf("pushing the policy at both: %v", err)
	}
	pushed := digestOf(p0)

	// Four seconds without a loss is the assertion that the enforcing sandbox
	// is pulsing.
	lost := host.Watch(context.Background(), pushed)
	select {
	case err := <-lost:
		t.Fatalf("a sandbox stopped enforcing the policy on its own: %v", err)
	case <-time.After(4 * time.Second):
	}

	// The agent's workload ends. Its attachment goes, and the policy is no
	// longer in force.
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
	for host.Attached() != 1 {
		time.Sleep(time.Millisecond)
	}

	// The exit remains attached, but was never pushed to and never acknowledged
	// a policy. A watch finds no enforcing sandbox that acknowledged, and says
	// that rather than that a socket closed: the exit is still sitting on this
	// one, and the claim that was lost is a claim nothing here ever made.
	elsewhere := host.Watch(context.Background(), strings.Repeat("00", 32))
	select {
	case err, ok := <-elsewhere:
		if !ok {
			t.Fatal("the watch over the exit ended without reporting anything")
		}
		if !strings.Contains(err.Error(), "no attachment has acknowledged this policy") {
			t.Errorf("watch returned %q; want the absence of an acknowledgement", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the watch reported nothing")
	}
}

func digestOf(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}
