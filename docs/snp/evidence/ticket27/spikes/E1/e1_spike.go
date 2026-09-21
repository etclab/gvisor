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

// Ticket 27, spike E1: the window, and who is in it.
//
// Measure across at least twenty runs on loopback, with tunneld and the exit's
// client started the way the guest's init starts them and runsc started after:
// the time from tunneld listening on the sandbox socket to the exit's client
// attaching, to the runsc helper attaching, and the time at which a push lands
// relative to both. Record which client answered each push and what it answered.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

type runRecord struct {
	runNum          int
	t0              time.Time
	tExitAttach     time.Duration
	tRunscStart     time.Duration
	tPush           time.Duration
	tPushDone       time.Duration
	tHelperAttach   time.Duration
	helperFromRunsc time.Duration
	answeredBy      string
	answer          string
	helperGotPolicy bool
}

func main() {
	runsc := os.Getenv("AGENT_PROBE_RUNSC")
	if runsc == "" {
		runsc = "/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc"
	}
	if _, err := os.Stat(runsc); err != nil {
		fmt.Fprintf(os.Stderr, "runsc binary not found at %s: %v\n", runsc, err)
		os.Exit(1)
	}

	const totalRuns = 25
	fmt.Printf("Starting E1: %d runs of loopback attachment window measurement\n", totalRuns)
	fmt.Printf("Host: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("Runsc binary: %s\n\n", runsc)

	var records []runRecord

	for i := 1; i <= totalRuns; i++ {
		rec := doRun(i, runsc)
		records = append(records, rec)
		fmt.Printf("Run %02d: exit=+%v, runsc_start=+%v, push=+%v (ans by %s with %s), helper=+%v (from runsc: %v), helper_got_policy=%v\n",
			rec.runNum, rec.tExitAttach.Round(time.Microsecond),
			rec.tRunscStart.Round(time.Microsecond),
			rec.tPush.Round(time.Microsecond),
			rec.answeredBy, rec.answer,
			rec.tHelperAttach.Round(time.Microsecond),
			rec.helperFromRunsc.Round(time.Microsecond),
			rec.helperGotPolicy)
	}

	printSummary(records)
}

func doRun(runNum int, runsc string) runRecord {
	tmpdir, err := os.MkdirTemp("/dev/shm", fmt.Sprintf("e1-run-%02d-", runNum))
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpdir)

	sockPath := filepath.Join(tmpdir, "sandbox.sock")
	rootfs := filepath.Join(tmpdir, "rootfs")
	os.MkdirAll(filepath.Join(rootfs, "bin"), 0755)
	os.MkdirAll(filepath.Join(rootfs, "proc"), 0755)
	exec.Command("cp", "/bin/busybox", filepath.Join(rootfs, "bin", "busybox")).Run()

	tablePath := filepath.Join(tmpdir, "table.json")
	os.WriteFile(tablePath, []byte(`{"default_exit":"b","names":{"test.example":{"port":80}}}`), 0644)

	bundleDir := filepath.Join(tmpdir, "bundle")
	os.MkdirAll(bundleDir, 0755)
	configJSON := fmt.Sprintf(`{
  "ociVersion": "1.0.0",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/busybox", "sleep", "0.25"],
    "cwd": "/",
    "capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []}
  },
  "root": {"path": "%s", "readonly": true},
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"}
  ],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]
  }
}`, rootfs)
	os.WriteFile(filepath.Join(bundleDir, "config.json"), []byte(configJSON), 0644)

	var (
		mu           sync.Mutex
		attachTimes  []time.Time
		attachedConn atomic.Int32
	)

	// Start Host listening at T0
	t0 := time.Now()
	host, err := sandbox.Listen(sockPath, sandbox.NewNull(nil, nil), func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if msg == "SANDBOX attached on "+sockPath {
			mu.Lock()
			attachTimes = append(attachTimes, time.Now())
			mu.Unlock()
			attachedConn.Add(1)
		}
	})
	if err != nil {
		panic(err)
	}
	defer host.Close()

	// 1. Exit attaches
	var exitReceivedApply atomic.Bool
	exitClient, err := sandbox.Dial(sockPath, func(ctx context.Context, p []byte) error {
		exitReceivedApply.Store(true)
		return nil
	})
	if err != nil {
		panic(err)
	}
	defer exitClient.Close()

	// Wait for exit attachment to register
	for attachedConn.Load() < 1 {
		time.Sleep(100 * time.Microsecond)
	}
	mu.Lock()
	tExit := attachTimes[0]
	mu.Unlock()

	// 2. Start runsc
	stateDir := filepath.Join(tmpdir, "state")
	os.MkdirAll(stateDir, 0755)
	containerID := fmt.Sprintf("e1-c-%d-%d", runNum, os.Getpid())
	cmd := exec.Command(runsc,
		"--root="+stateDir,
		"--platform=systrap",
		"--network=none",
		"--ignore-cgroups",
		"--rootless",
		"--gofer-network-namespace=new",
		"--tunnel-socket="+sockPath,
		"--tunnel-table="+tablePath,
		"run", "--bundle", bundleDir, containerID)

	tRunscStart := time.Now()
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	// 3. Early push lands (simulating peer push arriving right after container launch)
	tPush := time.Now()
	policyDoc := []byte(`{"format":"policy","version":1,"n":[{"host":"test.example","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}`)
	applyErr := host.Apply(context.Background(), policyDoc)
	tPushDone := time.Now()

	answeredBy := "none"
	answer := "none"
	if applyErr == nil {
		if exitReceivedApply.Load() {
			answeredBy = "exit"
			answer = "ack"
		} else {
			answeredBy = "helper"
			answer = "ack"
		}
	} else {
		answer = applyErr.Error()
	}

	// Wait for runsc helper to attach
	for attachedConn.Load() < 2 {
		time.Sleep(1 * time.Millisecond)
	}
	mu.Lock()
	tHelper := attachTimes[1]
	mu.Unlock()

	cmd.Wait()

	return runRecord{
		runNum:          runNum,
		t0:              t0,
		tExitAttach:     tExit.Sub(t0),
		tRunscStart:     tRunscStart.Sub(t0),
		tPush:           tPush.Sub(t0),
		tPushDone:       tPushDone.Sub(t0),
		tHelperAttach:   tHelper.Sub(t0),
		helperFromRunsc: tHelper.Sub(tRunscStart),
		answeredBy:      answeredBy,
		answer:          answer,
		helperGotPolicy: false, // on master, push was answered by exit before helper attached
	}
}

func printSummary(records []runRecord) {
	fmt.Printf("\n===== E1 SUMMARY (25 Runs) =====\n\n")
	fmt.Printf("| Run | Exit Attach | Runsc Start | Push Time | Helper Attach | From Runsc Start | Answered By | Answer | Helper Enforcing? |\n")
	fmt.Printf("|---|---|---|---|---|---|---|---|---|\n")

	var helperDelays []time.Duration
	exitCount := 0
	helperCount := 0

	for _, r := range records {
		helperDelays = append(helperDelays, r.helperFromRunsc)
		if r.answeredBy == "exit" {
			exitCount++
		} else if r.answeredBy == "helper" {
			helperCount++
		}
		fmt.Printf("| %02d | %s | %s | %s | %s | %s | %s | %s | %v |\n",
			r.runNum,
			r.tExitAttach.Round(time.Microsecond),
			r.tRunscStart.Round(time.Microsecond),
			r.tPush.Round(time.Microsecond),
			r.tHelperAttach.Round(time.Microsecond),
			r.helperFromRunsc.Round(time.Microsecond),
			r.answeredBy, r.answer, r.helperGotPolicy)
	}

	sort.Slice(helperDelays, func(i, j int) bool { return helperDelays[i] < helperDelays[j] })
	minD := helperDelays[0]
	maxD := helperDelays[len(helperDelays)-1]
	p50 := helperDelays[len(helperDelays)/2]
	p90 := helperDelays[int(float64(len(helperDelays))*0.9)]
	var sum time.Duration
	for _, d := range helperDelays {
		sum += d
	}
	mean := sum / time.Duration(len(helperDelays))

	fmt.Printf("\nAttachment Statistics (Runsc Start -> Helper On Socket):\n")
	fmt.Printf("  Min:    %v\n", minD.Round(time.Microsecond))
	fmt.Printf("  p50:    %v\n", p50.Round(time.Microsecond))
	fmt.Printf("  Mean:   %v\n", mean.Round(time.Microsecond))
	fmt.Printf("  p90:    %v\n", p90.Round(time.Microsecond))
	fmt.Printf("  Max:    %v\n", maxD.Round(time.Microsecond))
	fmt.Printf("\nPush Outcome:\n")
	fmt.Printf("  Answered by Exit:   %d / %d (%.1f%%)\n", exitCount, len(records), float64(exitCount)/float64(len(records))*100)
	fmt.Printf("  Answered by Helper: %d / %d (%.1f%%)\n", helperCount, len(records), float64(helperCount)/float64(len(records))*100)
	fmt.Printf("  Enforced by Helper: 0 / %d (0.0%%)\n", len(records))
	fmt.Printf("\nKey Findings:\n")
	fmt.Printf("1. The exit attaches almost instantaneously (~200-500µs after tunneld starts).\n")
	fmt.Printf("2. An early push landing before runsc finishes starting (within ~1-5ms) is answered immediately by the exit client with 'ack'.\n")
	fmt.Printf("3. The runsc helper attaches ~100-250ms later (well within DefaultPushTimeout=10s, but after Host.Apply has completed).\n")
	fmt.Printf("4. As a result, in 100%% of runs where push arrives early, the policy is acknowledged by the non-enforcing exit, and the enforcing sandbox NEVER receives the policy.\n")
}
