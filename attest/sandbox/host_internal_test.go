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

package sandbox

// The one thing about this contract that cannot be driven from outside it: the
// bound a push falls back on when its caller named no deadline. Every other test
// of the host is in socket_test.go, over the exported contract, and this file is
// here only because ten seconds is the right bound for a running system and the
// wrong one for a test.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// silentNetwork answers nothing. The push these tests make never reaches Open or
// Accept, and a host needs a network to be built.
type silentNetwork struct{}

func (silentNetwork) Open(context.Context, string) (Stream, error) {
	return nil, errors.New("this network opens nothing")
}

func (silentNetwork) Accept(context.Context) (Stream, Attested, error) {
	return nil, Attested{}, errors.New("this network accepts nothing")
}

// TestAPushIsBoundedWhenTheSandboxNeverAnswersIt is the other half of the bound.
// A sandbox that has attached and then says nothing at all holds the same push
// slot a sandbox that never attached holds, and a caller that named no deadline
// has named nothing that would ever take it back.
func TestAPushIsBoundedWhenTheSandboxNeverAnswersIt(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := Listen(socket, silentNetwork{}, nil)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()
	host.applyWait = 250 * time.Millisecond

	// A sandbox that takes the policy and never answers, until this test ends.
	answer := make(chan struct{})
	defer close(answer)
	client, err := Dial(socket, RoleEnforcing, func(context.Context, []byte) error {
		<-answer
		return nil
	})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()
	deadline := time.Now().Add(10 * time.Second)
	for host.Attached() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the sandbox to attach")
		}
		time.Sleep(time.Millisecond)
	}

	answered := make(chan error, 1)
	go func() {
		answered <- host.Apply(context.Background(), []byte(`{"format":"policy","version":1}`))
	}()
	select {
	case err := <-answered:
		if err == nil {
			t.Fatal("a push the sandbox never answered was acknowledged")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a push with no caller deadline behind it never ended")
	}

	// And the push slot is free rather than wedged: the next push is answered
	// too, instead of queueing behind the one that was given up.
	began := time.Now()
	if err := host.Apply(context.Background(), []byte(`{"format":"policy","version":1}`)); err == nil {
		t.Error("the push after the unanswered one was acknowledged")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("the push after the unanswered one took %v; the slot was still held", took)
	}
}
