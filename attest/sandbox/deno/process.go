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

package deno

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// stopGrace is how long a process gets to end on SIGTERM before it is killed.
// Two seconds is long enough for a runtime to run whatever it runs on the way
// out and short enough that a push waiting behind it is still a push: the
// pusher's own timeout is ten seconds (docs/policy-push.md).
const stopGrace = 2 * time.Second

// A process is one Deno run: the command, the first line it said on stderr,
// and how it ended.
//
// Nothing here is guarded by a lock, and the reason is done. It is closed
// after os/exec has reaped the process, which is after Wait has joined the
// goroutine copying the child's stderr, so a reader that has seen done closed
// has seen everything either of them wrote — exit status and first line both —
// and a reader that has not seen it closed has nothing final to read.
type process struct {
	cmd   *exec.Cmd
	first *firstLine
	began time.Time
	done  chan struct{}
}

// start execs Deno under the flags the atoms render to and returns as soon as
// it is running. `run --no-prompt` is not decoration: `deno eval` ignores
// permission flags entirely, and without --no-prompt a missing capability is an
// interactive question rather than a refusal (E3's install record).
func (s *Sandbox) start(atoms []string) (*process, error) {
	args := append([]string{"run", "--no-prompt"}, flagsOf(atoms)...)
	args = append(args, s.cfg.Script)
	args = append(args, s.cfg.Args...)
	first := &firstLine{to: s.cfg.Stderr}
	cmd := exec.Command(s.cfg.Binary, args...)
	cmd.Dir = s.cfg.Dir
	cmd.Env = childEnviron(atoms)
	cmd.Stdout, cmd.Stderr = s.cfg.Stdout, first
	p := &process{cmd: cmd, first: first, began: time.Now(), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go p.reap(s.logf)
	return p, nil
}

// childEnviron is the environment the policy grants and no more: the variables
// `e` names, copied from this process's, plus PATH and HOME for Deno's own
// needs — it resolves its cache and its configuration against HOME and it
// looks up what it runs on PATH.
//
// E4's adapter passed os.Environ() and let --allow-env decide what the script
// could read, which put the API key in the child under every policy and made
// the flag a read gate on a secret the sandbox had already handed over. A
// variable this process does not have is left out rather than passed empty, so
// that the child can tell "not granted" from "granted and empty".
func childEnviron(atoms []string) []string {
	var env []string
	seen := map[string]bool{}
	for _, name := range append([]string{"PATH", "HOME"}, granted(atoms, "env:")...) {
		if seen[name] {
			continue
		}
		seen[name] = true
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// granted is the values of the atoms of one kind, in the set's own order.
func granted(atoms []string, prefix string) []string {
	var values []string
	for _, a := range atoms {
		if value, ok := strings.CutPrefix(a, prefix); ok {
			values = append(values, value)
		}
	}
	return values
}

// reap waits for the process and says how it ended. The console line is
// written before done is closed, so that whoever wakes on done cannot outrun
// the sentence that explains it.
func (p *process) reap(logf func(string, ...any)) {
	_ = p.cmd.Wait()
	logf("SANDBOX deno exited status=%d", p.cmd.ProcessState.ExitCode())
	close(p.done)
}

// settle waits for the process to be still running, which is the strongest
// thing Apply can say before it acknowledges. Deno validates its flags after
// exec and dies 36–43 ms later when they are wrong (E4 case iv), so a wait of
// that order turns the failure this contract has no second message for into an
// ordinary refusal. It ends early when the process ends, so it costs a run
// that fails and not a run that works.
func (p *process) settle(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-p.done:
		code, _ := p.exited()
		return refuse("the process started and was gone %s later with status %d: %s",
			time.Since(p.began).Round(time.Millisecond), code, p.first.line())
	case <-ctx.Done():
		return refuse("the push was abandoned while the process was settling: %v", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// stop ends the process: SIGTERM, then a wait bounded by the caller's context
// or by stopGrace, then SIGKILL. It returns only once the process has been
// reaped, because a policy is applied by starting a process and two of them at
// once would be two policies.
func (p *process) stop(ctx context.Context) {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(unix.SIGTERM)
	timer := time.NewTimer(stopGrace)
	defer timer.Stop()
	select {
	case <-p.done:
		return
	case <-ctx.Done():
	case <-timer.C:
	}
	_ = p.cmd.Process.Kill()
	<-p.done
}

// ended is the channel closed when this run is over. A nil process is a
// sandbox that has not started one, and the channel is closed for it because
// "nothing is running" is already true — the nil case lives here beside stop's
// for the same reason, that the caller asking about a run is the one place
// that should not have to know whether there has been one.
func (p *process) ended() <-chan struct{} {
	if p == nil {
		return noProcess
	}
	return p.done
}

// exited is the status and whether there is one yet. It reads os/exec's own
// record rather than a copy of it, so there is one answer rather than two that
// could disagree.
func (p *process) exited() (int, bool) {
	if p == nil {
		return 0, false
	}
	select {
	case <-p.done:
		return p.cmd.ProcessState.ExitCode(), true
	default:
		return 0, false
	}
}

// A firstLine keeps the first line a process wrote to stderr and forwards
// everything to the writer the configuration named, if it named one. The first
// line is kept whatever that writer is, because a process that dies during the
// settle has to say something for itself in the refusal, and a sandbox
// configured to discard its workload's output would otherwise refuse without a
// reason.
//
// One goroutine writes it — os/exec's, copying the child's stderr — and line
// is read after [process.done] is closed, which is after Wait has joined that
// goroutine. That is the whole of the synchronisation, and it is why there is
// no lock here to get wrong.
type firstLine struct {
	to io.Writer

	kept []byte
	full bool
}

// keepAtMost bounds what a process with no newline in it can make this hold.
const keepAtMost = 4 << 10

func (f *firstLine) Write(p []byte) (int, error) {
	if !f.full {
		line, _, ended := strings.Cut(string(p), "\n")
		f.kept = append(f.kept, line...)
		if len(f.kept) >= keepAtMost {
			f.kept, f.full = f.kept[:keepAtMost], true
		}
		f.full = f.full || ended
	}
	if f.to == nil {
		return len(p), nil
	}
	return f.to.Write(p)
}

func (f *firstLine) line() string { return strings.TrimSpace(string(f.kept)) }
