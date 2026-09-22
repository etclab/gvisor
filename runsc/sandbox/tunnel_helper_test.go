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

import (
	"errors"
	"strings"
	"testing"
)

// newTunnelHelperWatch is what startTunnelHelper builds, without the child.
// Pid is left at zero throughout these tests, so killForTunnelHelperLoss has
// nothing to signal and the verdict is all that is exercised.
func newTunnelHelperWatch() *tunnelHelperWatch {
	return &tunnelHelperWatch{
		gone:     make(chan struct{}),
		teardown: make(chan struct{}),
	}
}

// TestTunnelHelperExitedVerdict is the rule the watchdog goes by, and it is
// worth a test of its own because both halves of it can be got wrong in a way
// nobody notices: read too strictly and every ordinary run ends with a warning
// about a helper that did exactly what it should; read too loosely and a
// sandbox whose helper was refused goes on running with no policy and no way of
// ever being given one, which is ticket 27's finding 5.
func TestTunnelHelperExitedVerdict(t *testing.T) {
	const refusal = "Tunnel helper: tunneld closed this client, so no policy can reach this sandbox: a second enforcing client is not permitted on this socket"
	for _, tc := range []struct {
		name string
		// waitErr is what cmd.Wait answered: nil for exit 0.
		waitErr error
		// said is what the helper wrote on standard error.
		said string
		// teardown says the sandbox was already on its way out.
		teardown bool
		// want is what the recorded reason must contain, or "" when the exit
		// must be recorded as no failure at all.
		want string
	}{
		{
			name:    "a refused attach is fatal and carries the helper's own reason",
			waitErr: errors.New("exit status 128"),
			said:    refusal + "\n",
			want:    "a second enforcing client is not permitted on this socket",
		},
		{
			name:    "a refused attach names the exit status too",
			waitErr: errors.New("exit status 128"),
			said:    refusal,
			want:    "exit status 128",
		},
		{
			name:    "a helper that died saying nothing is still fatal",
			waitErr: errors.New("signal: killed"),
			want:    "its own log file is the only record of why",
		},
		{
			name:    "a clean exit is the sentry having closed the channel",
			waitErr: nil,
			want:    "",
		},
		{
			name:     "a clean exit during teardown is not a failure either",
			waitErr:  nil,
			teardown: true,
			want:     "",
		},
		{
			name:     "a helper killed along with its sandbox is not a failure",
			waitErr:  errors.New("signal: killed"),
			teardown: true,
			want:     "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Sandbox{ID: "test-sandbox"}
			s.tunnelHelper = newTunnelHelperWatch()
			if tc.teardown {
				s.tunnelHelperTeardown()
			}
			s.tunnelHelperExited(4242, tc.waitErr, tc.said, s.tunnelHelper)
			select {
			case <-s.tunnelHelper.gone:
			default:
				t.Fatal("the watchdog did not report the helper as reaped")
			}
			err := s.tunnelHelperFailure()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the exit was recorded as a failure: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("the exit was recorded as no failure, so the sandbox would be handed back as created")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the recorded reason is %q, wanted something with %q in it", err, tc.want)
			}
		})
	}
}

// TestTunnelHelperFailureWithoutAHelper: a sandbox runsc was given no
// --tunnel-socket for has no helper to watch, and neither has one read back
// from its state file. Neither may be reported as having lost one.
func TestTunnelHelperFailureWithoutAHelper(t *testing.T) {
	s := &Sandbox{ID: "test-sandbox"}
	if err := s.tunnelHelperFailure(); err != nil {
		t.Errorf("a sandbox with no tunnel helper reported %v", err)
	}
	// And saying the sandbox is being torn down must not panic on the absence.
	s.tunnelHelperTeardown()
}

// TestTunnelHelperTeardownIsIdempotent: destroy and waitForStopped both say it,
// and destroy calls waitForStopped, so it is said twice on the ordinary path.
func TestTunnelHelperTeardownIsIdempotent(t *testing.T) {
	s := &Sandbox{ID: "test-sandbox"}
	s.tunnelHelper = newTunnelHelperWatch()
	s.tunnelHelperTeardown()
	s.tunnelHelperTeardown()
	select {
	case <-s.tunnelHelper.teardown:
	default:
		t.Fatal("teardown was not signalled")
	}
}
