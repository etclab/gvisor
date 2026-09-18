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

// The ticket's other workload: Claude Code itself, unmodified, inside the same
// sandbox that adapter_test.go puts agent-probe in.
//
// What is being asked of this run is narrow and it is worth saying so before
// anything else. **It starts, and the list of hosts it asked for is recorded.**
// Task completion is not required and its absence is not a failure — a shipped
// agent runtime that boots inside the sandbox and names its two destinations
// has already answered the question ticket 25 has about it, which is whether an
// in-sentry name table is being built for a program that can run there at all.
//
// # Why this is a different rootfs and the same everything else
//
// agent-probe is one static file. Claude Code is a 232 MB dynamically linked
// ELF that forks git, re-execs itself as ripgrep, listens on an AF_UNIX socket,
// writes a HOME and reads a few dozen paths under /proc and /sys (spike E4,
// docs/snp/evidence/ticket25/spikes/E4/notes.md). So the rootfs has a loader,
// six libraries, git and a writable HOME, and the tunnelds, the exit, the
// table, the capture and the key handling are the ones next door.
//
// # The variables E4 stripped
//
// E4 ran from a shell that was itself a Claude Code session and had to strip
// CLAUDECODE, CLAUDE_CODE_MESSAGING_SOCKET and their friends, because
// CLAUDE_CODE_MESSAGING_SOCKET in particular would have added an AF_UNIX
// destination that is an artefact of the harness. Here the environment is
// built from nothing — four variables, listed below — so they are stripped by
// construction rather than by a list that has to be kept in step.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// claudeEnv is the third thing this test needs: the ELF itself. It is not
	// in the tree and never will be.
	claudeEnv = "AGENT_PROBE_CLAUDE"

	// The second name E4 found, which is the one a table built from
	// agent-probe alone would have missed. It is contacted on a fresh HOME,
	// with no opt-in, on every run.
	intakeHost = "http-intake.logs.us5.datadoghq.com"

	// The cheapest model and the shortest prompt there is, because what is
	// being measured is the boot and the host list and not the answer.
	smokeModel  = "claude-haiku-4-5-20251001"
	smokePrompt = "Reply with exactly the word OK."

	// smokeCap is the spend this run is allowed. E4's four runs cost $0.044
	// between them, so one run is two orders of magnitude inside it; the check
	// is here because a cap nobody checks is a sentence in a ticket.
	smokeCap = 0.50
)

// The loader and the libraries `ldd` lists for the ELF, plus the two NSS
// modules glibc may still dlopen. On glibc 2.34 and later files and dns are
// compiled into libc, so the two are insurance and not a dependency; a rootfs
// that has them cannot fail for want of them.
var (
	claudeLibs = []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/x86_64-linux-gnu/librt.so.1",
		"/lib/x86_64-linux-gnu/libpthread.so.0",
		"/lib/x86_64-linux-gnu/libdl.so.2",
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/lib/x86_64-linux-gnu/libnss_files.so.2",
		"/lib/x86_64-linux-gnu/libnss_dns.so.2",
	}

	// git is forked four times before the first model call, so it is worth the
	// two extra libraries. A host without it does not stop the run: the finding
	// is then what the agent does without it, which is degrade quietly.
	gitLibs = []string{
		"/lib/x86_64-linux-gnu/libpcre2-8.so.0",
		"/lib/x86_64-linux-gnu/libz.so.1",
	}
)

func TestClaudeCodeSmoke(t *testing.T) {
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a runsc and the Claude Code ELF: set %s=1, %s and %s", liveEnv, runscEnv, claudeEnv)
	}
	runsc := os.Getenv(runscEnv)
	if info, err := os.Stat(runsc); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not a runsc this test can start: %v", runscEnv, runsc, err)
	}
	elf := os.Getenv(claudeEnv)
	if info, err := os.Stat(elf); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not the Claude Code binary: %v", claudeEnv, elf, err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatalf("%s=1 and no ANTHROPIC_API_KEY in the environment: the CLI inside the sandbox needs it", liveEnv)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	l := newLoopback(t, ctx, out, runsc, proof{
		title: "Claude Code inside the sandbox",
		preamble: "One runsc sandbox. The workload is Claude Code itself, unmodified — the " +
			"`" + smokeModel + "` model, the prompt `" + smokePrompt + "`, `--output-format json`, in an empty " +
			"working directory with a HOME that has never been used. What is asked of the run is that it starts " +
			"and that the hosts it asks for are recorded; task completion is not required and its absence is not " +
			"a failure.",
		allow: modelHost + ":443," + intakeHost + ":443",
		under: "ticket25/claude-smoke",
	})
	l.buildClaudeRootfs(t, elf)

	r := l.sandbox(t, "claude", map[string]int{modelHost: tunnelledPort, intakeHost: tunnelledPort}, workload{
		args: []string{"/usr/local/bin/claude", "-p", smokePrompt, "--output-format", "json", "--model", smokeModel},
		// Four variables and no more. Everything E4 had to strip is absent
		// because nothing here inherits an environment.
		env: []string{
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"HOME=/home/agent",
			"SSL_CERT_FILE=" + anchors,
		},
		cwd: "/work",
		// The rootfs is writable. The CLI wants a HOME it can create
		// .claude/ in, an atomic rename and a mkdir lock beside it, and a
		// directory it can bind an AF_UNIX socket in; a read-only root with
		// tmpfs patches over each of those would be three guesses about which
		// paths it picks, and it picked one this harness had not predicted
		// (see the README the run writes).
		writable: true,
		mounts: []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
			// E4 saw reads of /sys/devices/system/cpu/online, the NUMA nodes
			// and three levels of cgroup files. They are all read-and-shrug,
			// but a sysfs costs nothing and a missing one would be a
			// difference between this run and a bare host.
			map[string]any{"destination": "/sys", "type": "sysfs", "source": "sysfs",
				"options": []string{"nosuid", "noexec", "nodev", "ro"}},
		},
	})

	// The one assertion. It started: the sentry traced syscalls made by a
	// process called claude.
	if !ranAs(r, "claude") {
		t.Errorf("the sentry traced no syscalls from a process called claude, so the ELF did not run; what ran was %v", r.comms)
	}

	// Everything else is recorded and nothing else is required. A run that
	// completed says what it cost; a run that did not says that it did not.
	said := l.said(r.stdout)
	res, ok := claudeJSON(said)
	switch {
	case !ok:
		out.logf("\nFINDING the CLI printed no JSON result object. Task completion is not required here, so this is recorded and is not a failure.")
	case res.IsError:
		out.logf("\nFINDING the CLI ran to a result and the result is an error: %q. Recorded, not a failure.", res.Result)
	default:
		out.logf("\nFINDING the CLI completed the task: %q in %d turn(s), $%.6f.", res.Result, res.NumTurns, res.TotalCost)
	}
	if res.TotalCost > smokeCap {
		t.Errorf("this run cost $%.6f, and the cap for the smoke is $%.2f", res.TotalCost, smokeCap)
	}

	l.record(t, l.smokeNotes(r, res, ok), r)
}

// ranAs reports whether the sentry traced a process of that name, which is the
// whole of "it started": the first process is exec'd by the sentry itself, so
// there is no execve line for it, and its name on its syscall lines is the
// evidence that instead.
func ranAs(r *sandboxRun, name string) bool {
	for _, comm := range r.comms {
		if comm == name {
			return true
		}
	}
	return false
}

// ===== the rootfs =====

// buildClaudeRootfs is E4's filesystem list, built. Everything that comes from
// the host is copied rather than linked, so that nothing the sandbox does can
// reach the operator's own install.
func (l *loopback) buildClaudeRootfs(t *testing.T, elf string) {
	t.Helper()
	l.root = filepath.Join(l.scratch, "rootfs")
	for _, dir := range []string{
		"usr/local/bin", "usr/bin", "lib64", "lib/x86_64-linux-gnu", "etc/ssl/certs",
		// A HOME it can write, a cwd with nothing in it, a /tmp, and the
		// directory E4 predicted the AF_UNIX socket would be in.
		"home/agent", "work", "tmp", "run/user/0/cc-socks",
		// The two mount points, which have to exist in a rootfs that is not
		// an image with them already in it.
		"proc", "sys",
	} {
		if err := os.MkdirAll(filepath.Join(l.root, dir), 0o755); err != nil {
			t.Fatalf("the rootfs: %v", err)
		}
	}
	if err := os.Chmod(filepath.Join(l.root, "tmp"), 0o1777); err != nil {
		t.Fatalf("/tmp in the rootfs: %v", err)
	}

	l.carry(t, 0o755, "/usr/local/bin/claude="+elf, "/lib64/ld-linux-x86-64.so.2")
	l.carry(t, 0o644, claudeLibs...)
	if haveAll(append([]string{"/usr/bin/git"}, gitLibs...)) {
		l.carry(t, 0o755, "/usr/bin/git")
		l.carry(t, 0o644, gitLibs...)
	} else {
		l.out.logf("no /usr/bin/git on this host: the rootfs has none, and what the CLI does without it is the finding")
	}
	l.carry(t, 0o644, anchors)

	// /etc, written rather than copied: a resolver that asks 127.0.0.53 is the
	// whole point, and the host's own /etc/resolv.conf is about the host.
	for name, text := range map[string]string{
		"etc/resolv.conf":   "nameserver 127.0.0.53\noptions timeout:5 attempts:2\n",
		"etc/nsswitch.conf": "hosts: files dns\npasswd: files\ngroup: files\n",
		"etc/hosts":         "127.0.0.1\tlocalhost\n::1\tlocalhost\n",
		// A passwd and a group entry for uid 0, because a program that asks
		// who it is should get an answer rather than an error.
		"etc/passwd": "root:x:0:0:root:/home/agent:/bin/sh\n",
		"etc/group":  "root:x:0:\n",
	} {
		if err := os.WriteFile(filepath.Join(l.root, name), []byte(text), 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	l.out.logf("the rootfs is %s: the Claude Code ELF at /usr/local/bin/claude, its loader and libraries, a writable /home/agent and an empty /work", l.root)
}

// carry copies host files into the rootfs. A path on its own keeps the place it
// has on the host; "inside=outside" puts it somewhere else. Everything the
// rootfs takes from the host goes through here, so a host that has not got one
// of them skips the test naming the file rather than failing inside the
// sandbox with a loader error.
func (l *loopback) carry(t *testing.T, mode os.FileMode, paths ...string) {
	t.Helper()
	for _, path := range paths {
		inside, outside, moved := strings.Cut(path, "=")
		if !moved {
			outside = inside
		}
		src, err := os.Open(outside)
		if err != nil {
			t.Skipf("the sandbox needs %s and this host has not got it: %v", outside, err)
		}
		dst, err := os.OpenFile(filepath.Join(l.root, inside), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err == nil {
			_, err = io.Copy(dst, src)
			dst.Close()
		}
		src.Close()
		if err != nil {
			t.Fatalf("copying %s into the rootfs: %v", outside, err)
		}
	}
}

// haveAll reports whether every path is on this host.
func haveAll(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

// ===== the result =====

// A claudeResult is the part of `--output-format json` this record needs. The
// object carries a great deal more; these are the fields a reader of the
// evidence asks about.
type claudeResult struct {
	IsError     bool    `json:"is_error"`
	Subtype     string  `json:"subtype"`
	Result      string  `json:"result"`
	TotalCost   float64 `json:"total_cost_usd"`
	NumTurns    int     `json:"num_turns"`
	DurationMs  int64   `json:"duration_ms"`
	DurationAPI int64   `json:"duration_api_ms"`
}

// claudeJSON is the result object on the CLI's stdout, if there is one. It is
// the last line that begins a JSON object, because a run that printed a warning
// first is still a run that printed a result.
func claudeJSON(said string) (claudeResult, bool) {
	var res claudeResult
	found := false
	for _, line := range strings.Split(said, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var one claudeResult
		if json.Unmarshal([]byte(line), &one) == nil {
			res, found = one, true
		}
	}
	return res, found
}

// smokeNotes is this test's own section of the README the harness writes: what
// started, what it asked the network for, what it cost, and the two things the
// harness cannot see from outside.
func (l *loopback) smokeNotes(r *sandboxRun, res claudeResult, completed bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Did it start\n\n")
	fmt.Fprintf(&b, "The sentry traced syscalls from: `%s`. The first process is exec'd by the sentry itself, so "+
		"there is no `execve` line for it; the name on its syscall lines is the evidence that it ran. Its children "+
		"— `git`, and the binary re-exec'd as `rg` — do have `execve` lines, and they are in `strace-digest.txt` "+
		"with every syscall that failed and every bind.\n\n", strings.Join(r.comms, "`, `"))

	fmt.Fprintf(&b, "## The hosts it asked for\n\n")
	dialed := r.at.matching("EXIT dialed")
	if len(dialed) == 0 {
		fmt.Fprintf(&b, "No `CONNECT` reached the exit, so this run names no host through the tunnel.\n\n")
	} else {
		fmt.Fprintf(&b, "Every `CONNECT` the exit read, in order. This is the host list by **name**: the sandbox "+
			"never had an address of its own to give, and the exit resolves what the stream named.\n\n```\n%s\n```\n\n",
			strings.Join(dialed, "\n"))
	}
	fmt.Fprintf(&b, "**The names the resolver was asked for are not in `--strace`.** gVisor's strace formats "+
		"`sendto`'s buffer argument as a pointer (`pkg/sentry/strace/linux64_amd64.go`: `makeSyscallInfo(\"sendto\", "+
		"FD, Hex, Hex, Hex, SockAddr, Hex)`), so a DNS query's payload never reaches the log. What the log gives is "+
		"the count of datagrams to `127.0.0.53:53`, which is in `strace-digest.txt`. The query names are visible only "+
		"to the responder inside the sentry, so that responder has to log them — one line per query — or the "+
		"asked-for list cannot be recorded at all. The list above is the **connect** list, which is a different "+
		"question: E4 saw three to four resolutions and seven to ten connections per name per run.\n\n")

	// The one thing about the rootfs that a prediction got wrong, taken from
	// the run rather than from the prediction.
	var unix []string
	for _, line := range strings.Split(l.said(r.digest), "\n") {
		if strings.Contains(line, "AF_UNIX") && strings.Contains(line, "bind(") {
			unix = append(unix, strings.TrimSpace(line))
		}
	}
	if len(unix) != 0 {
		fmt.Fprintf(&b, "## The socket it binds\n\n```\n%s\n```\n\n"+
			"E4 predicted `/run/user/<uid>/cc-socks/<pid>.sock` and this rootfs provides that directory; the path "+
			"above is the one this run chose. With no `XDG_RUNTIME_DIR` in the environment the choice is the "+
			"CLI's own fallback, and whichever directory it lands in has to be writable — which is the reason the "+
			"rootfs here is read-write rather than read-only with a tmpfs over each path somebody guessed.\n\n",
			strings.Join(unix, "\n"))
	}

	fmt.Fprintf(&b, "## What it cost\n\n")
	switch {
	case !completed:
		fmt.Fprintf(&b, "The CLI printed no JSON result object, so this run has no cost to report. Task completion "+
			"is not required here and its absence is not a failure.\n\n")
	case res.IsError:
		fmt.Fprintf(&b, "The CLI ran to a result and the result is an error: `%s`. Reported cost $%.6f over %d "+
			"turn(s), %d ms wall, %d ms of it API. Recorded, not a failure.\n\n",
			res.Result, res.TotalCost, res.NumTurns, res.DurationMs, res.DurationAPI)
	default:
		fmt.Fprintf(&b, "`%s` — %d turn(s), $%.6f, %d ms wall, %d ms of it API. The cap for this smoke is $%.2f.\n\n",
			res.Result, res.NumTurns, res.TotalCost, res.DurationMs, res.DurationAPI, smokeCap)
	}
	return b.String()
}
