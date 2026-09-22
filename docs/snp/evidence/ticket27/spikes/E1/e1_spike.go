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
// Measure across at least twenty runs on loopback, with the sandbox socket and
// the exit's client started the way the guest's init starts them and runsc
// started after: the time from the host listening on the sandbox socket to the
// exit's client attaching, to the runsc helper attaching, and the time at which
// a push lands relative to both. Record which client answered each push and what
// it answered.
//
// # What contract v4 changed about the question
//
// The question E1 was written for was which of two clients on one socket
// answered a push that arrived before the runsc helper had attached. On master
// the answer was the exit, every time, because Apply pushed to whatever was
// attached at that instant and the exit was attached in under a millisecond.
//
// On this branch there is no such choice to observe: a client declares a role
// when it attaches, the exit declares network, and a network attachment is never
// offered a policy. So the columns that recorded a choice now record that there
// was none — whether the exit was offered the document at all, whether Apply
// waited for the enforcing attachment, and how long that wait cost — and the
// measurement that decides whether waiting is affordable, from runsc starting to
// the enforcing attachment arriving, is unchanged and is the one the summary
// reports percentiles for.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// A runRecord is one run, measured. Every duration is from t0, the moment the
// host began listening on the sandbox socket, except helperFromRunsc.
type runRecord struct {
	runNum      int
	tExitAttach time.Duration // the exit's attach message, role network

	tRunscStart time.Duration // exec of runsc run
	tPush       time.Duration // Host.Apply entered
	tPushDone   time.Duration // Host.Apply returned

	tHelperAttach   time.Duration // the helper's attach message, role enforcing
	helperFromRunsc time.Duration // the same, measured from runsc starting

	// exitOffered says the exit's apply callback was called at all, which under
	// contract v4 must never happen: it attaches as a network client.
	exitOffered bool

	// applied says the host wrote its SANDBOX applied line, which it writes only
	// once the enforcing sandbox has acknowledged.
	applied bool

	// answer is "acknowledged by the enforcing sandbox" or the refusal verbatim.
	answer string
}

// waited reports whether the push was entered before the enforcing sandbox
// attached, which is the case the whole experiment is about.
func (r runRecord) waited() bool {
	return r.tHelperAttach > r.tPush
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
		fmt.Printf("Run %02d: exit=+%v, runsc_start=+%v, push=+%v, enforcing_attach=+%v (from runsc: %v), apply_returned=+%v, waited=%v, exit_offered=%v, applied=%v, answer=%s\n",
			rec.runNum, rec.tExitAttach.Round(time.Microsecond),
			rec.tRunscStart.Round(time.Microsecond),
			rec.tPush.Round(time.Microsecond),
			rec.tHelperAttach.Round(time.Microsecond),
			rec.helperFromRunsc.Round(time.Microsecond),
			rec.tPushDone.Round(time.Microsecond),
			rec.waited(), rec.exitOffered, rec.applied, rec.answer)
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
		mu sync.Mutex
		// The console lines this run is timed against. The host writes two lines
		// per attachment: one when the socket is accepted, and one when the
		// attach message declares a role. It is the second that matters here,
		// because a connection with no role declared is not something a policy
		// can be pushed to.
		attached map[string]time.Time
		applied  bool
		attaches atomic.Int32
	)
	attached = map[string]time.Time{}

	// The host begins listening at t0.
	t0 := time.Now()
	host, err := sandbox.Listen(sockPath, sandbox.NewNull(nil, nil), func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		now := time.Now()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(msg, "SANDBOX attached on ") && strings.Contains(msg, "role="):
			role := msg[strings.Index(msg, "role=")+len("role="):]
			if _, seen := attached[role]; !seen {
				attached[role] = now
				attaches.Add(1)
			}
		case strings.HasPrefix(msg, "SANDBOX applied "):
			applied = true
		}
	})
	if err != nil {
		panic(err)
	}
	defer host.Close()
	at := func(role string) time.Time {
		mu.Lock()
		defer mu.Unlock()
		return attached[role]
	}

	// 1. Exit attaches
	var exitReceivedApply atomic.Bool
	exitClient, err := sandbox.Dial(sockPath, sandbox.RoleNetwork, func(ctx context.Context, p []byte) error {
		exitReceivedApply.Store(true)
		return nil
	})
	if err != nil {
		panic(err)
	}
	defer exitClient.Close()

	// The exit's attach message, which is the first thing on the socket.
	for at(sandbox.RoleNetwork).IsZero() {
		time.Sleep(100 * time.Microsecond)
	}
	tExit := at(sandbox.RoleNetwork)

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

	// 3. The early push: entered here, a millisecond or two after runsc was
	// started and long before its helper can have attached. The deadline is the
	// ten seconds a pushing peer gives a push (tunneld.DefaultPushTimeout), so
	// that what is measured is a wait inside the deadline and not an unbounded
	// one.
	tPush := time.Now()
	policyDoc := []byte(`{"format":"policy","version":1,"n":[{"host":"test.example","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}`)
	ctx, cancel := context.WithTimeout(context.Background(), pushDeadline)
	applyErr := host.Apply(ctx, policyDoc)
	cancel()
	tPushDone := time.Now()

	answer := "acknowledged by the enforcing sandbox"
	if applyErr != nil {
		answer = applyErr.Error()
	}

	// The enforcing attachment, which is the helper's. It is waited for after the
	// push rather than before it, because a push that waited for it would not be
	// the early push this measures.
	for at(sandbox.RoleEnforcing).IsZero() {
		time.Sleep(time.Millisecond)
	}
	tHelper := at(sandbox.RoleEnforcing)

	cmd.Wait()
	mu.Lock()
	wrote := applied
	mu.Unlock()

	return runRecord{
		runNum:          runNum,
		tExitAttach:     tExit.Sub(t0),
		tRunscStart:     tRunscStart.Sub(t0),
		tPush:           tPush.Sub(t0),
		tPushDone:       tPushDone.Sub(t0),
		tHelperAttach:   tHelper.Sub(t0),
		helperFromRunsc: tHelper.Sub(tRunscStart),
		exitOffered:     exitReceivedApply.Load(),
		applied:         wrote,
		answer:          answer,
	}
}

// pushDeadline is the ten seconds a pushing peer gives a push
// (tunneld.DefaultPushTimeout, sandbox.DefaultApplyWait), written here because
// this spike calls Host.Apply directly and no tunneld gives it one.
const pushDeadline = 10 * time.Second

func printSummary(records []runRecord) {
	fmt.Printf("\n===== E1 SUMMARY (%d runs) =====\n\n", len(records))
	fmt.Printf("| Run | Exit attach | runsc start | Push entered | Enforcing attach | From runsc start | Apply returned | Apply took | Waited for it | Exit offered the policy | Answer |\n")
	fmt.Printf("|---|---|---|---|---|---|---|---|---|---|---|\n")

	var exitAttach, attachDelays, applyTook []time.Duration
	waited, offered, acknowledged := 0, 0, 0

	for _, r := range records {
		exitAttach = append(exitAttach, r.tExitAttach)
		attachDelays = append(attachDelays, r.helperFromRunsc)
		applyTook = append(applyTook, r.tPushDone-r.tPush)
		if r.waited() {
			waited++
		}
		if r.exitOffered {
			offered++
		}
		if r.applied {
			acknowledged++
		}
		fmt.Printf("| %02d | %s | %s | %s | %s | %s | %s | %s | %v | %v | %s |\n",
			r.runNum,
			r.tExitAttach.Round(time.Microsecond),
			r.tRunscStart.Round(time.Microsecond),
			r.tPush.Round(time.Microsecond),
			r.tHelperAttach.Round(time.Microsecond),
			r.helperFromRunsc.Round(time.Microsecond),
			r.tPushDone.Round(time.Microsecond),
			(r.tPushDone - r.tPush).Round(time.Microsecond),
			r.waited(), r.exitOffered, r.answer)
	}

	stats("Exit attachment statistics (the host listening -> the exit's attach message, role network)", exitAttach)
	stats("Attachment statistics (runsc start -> the enforcing attachment on the socket)", attachDelays)
	stats("Apply statistics (Host.Apply entered -> Host.Apply returned)", applyTook)

	fmt.Printf("\nPush outcome:\n")
	fmt.Printf("  Entered before the enforcing attachment: %d / %d\n", waited, len(records))
	fmt.Printf("  Offered to the exit (a network client): %d / %d\n", offered, len(records))
	fmt.Printf("  Acknowledged by the enforcing sandbox:  %d / %d\n", acknowledged, len(records))
}

// stats prints one set of percentiles. p50 is the middle element of the sorted
// slice and p90 the one nine tenths along, both by index and neither
// interpolated, which is what the notes beside this file must say they are.
func stats(what string, of []time.Duration) {
	d := append([]time.Duration(nil), of...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	var sum time.Duration
	for _, one := range d {
		sum += one
	}
	fmt.Printf("\n%s, over %d runs:\n", what, len(d))
	fmt.Printf("  Min:    %v\n", d[0].Round(time.Microsecond))
	fmt.Printf("  p50:    %v\n", d[len(d)/2].Round(time.Microsecond))
	fmt.Printf("  Mean:   %v\n", (sum / time.Duration(len(d))).Round(time.Microsecond))
	fmt.Printf("  p90:    %v\n", d[int(float64(len(d))*0.9)].Round(time.Microsecond))
	fmt.Printf("  Max:    %v\n", d[len(d)-1].Round(time.Microsecond))
}
