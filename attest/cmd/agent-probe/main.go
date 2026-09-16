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

// agent-probe is ticket 23's agent: the smallest tool-calling agent that does
// a fixed task against the Claude API, and which can be made to run behind the
// sandbox contract without being told that it is.
//
//	agent-probe [-network direct|null|socket] [-task summarize|delegate] [-peer NAME]
//	            [-sandbox-socket PATH] [-dir PATH] [-timeout D]
//	agent-probe -exit -network socket -sandbox-socket PATH -allow host:port,...
//
// It is one binary with two roles because they are two ends of one thing. The
// agent role runs the loop and asks for streams; the exit role accepts streams
// and dials what they name. The spikes ran both as throwaway test files
// (docs/snp/evidence/ticket23/spikes/E2 and E4); this is those files with the
// throwaway parts taken out, and the loop itself is E1's, promoted unchanged.
//
// # What -network selects
//
// direct is an http.Transport with nothing in front of it: E1's arrangement,
// and the measurement every other mode is compared against.
//
// socket is the real one. sandbox.Dial connects to the socket tunneld listens
// on, every dial becomes Open to -peer, and a second process running -exit on
// the far side reads the destination off the stream and dials it. A pushed
// policy is acknowledged by a null sandbox over the same client, which records
// its digest and enforces nothing — enforcement of a destination lives in the
// exit's -allow list, and enforcement of a workload's own resources lives in
// the sandbox that starts it (attest/sandbox/deno).
//
// null is the awkward one and it has to be said plainly. The null sandbox is a
// Sandbox over a Network, and the Network in the real arrangement is tunneld,
// which cannot serve on a workstation: there is no /sys/kernel/config/tsm/report
// to acquire evidence from, so there is no tunnel (ticket 22's spike E4). So
// in this binary -network null means the contract path with a trivial local
// exit at the end of it: sandbox.NewNull over a Network whose Open hands back
// one end of a socketpair, with this binary's own exit reading the CONNECT
// line off the other end and plainly dialing it. Open, the net.Conn adapter,
// the CONNECT line, the deadlines and the half-close are all the real ones and
// all exercised; the tunnel is what is missing, and with it everything the
// tunnel decides. A null run is therefore a measurement of the contract's
// shape and not of its cost.
//
// # The key
//
// ANTHROPIC_API_KEY comes from the environment on every run. It is never
// written to a file, never printed in a transcript and never passed as a flag,
// which is what makes the logs under docs/snp/evidence/ticket23/agent-probe
// committable.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

func main() {
	var c config
	c.flags(flag.CommandLine)
	flag.Parse()

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	role := runAgent
	if c.exit {
		role = runExit
	}
	if err := role(ctx, c, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// config is the command line. It is one struct so that the two roles take one
// argument each and the flags are declared where their reasons are.
type config struct {
	network string
	task    string
	peer    string
	socket  string
	allow   string
	dir     string
	exit    bool
	timeout time.Duration
}

func (c *config) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.network, "network", "direct",
		"how the agent reaches the network: direct, null (the contract with a local exit), or socket (tunneld)")
	fs.StringVar(&c.task, "task", "summarize",
		"which of the two fixed tasks to run: summarize (spike E1's) or delegate (ask -peer for its task)")
	fs.StringVar(&c.peer, "peer", "b",
		"the peer name every Open asks for, and the peer the delegate task is told to ask")
	fs.StringVar(&c.socket, "sandbox-socket", "",
		"the AF_UNIX socket tunneld serves the contract on, for -network socket and for -exit")
	fs.StringVar(&c.allow, "allow", "",
		"the exit's destinations, host:port comma separated; empty refuses every CONNECT")
	fs.StringVar(&c.dir, "dir", ".",
		"where write_file puts a relative path, so that a run leaves nothing in the tree")
	fs.BoolVar(&c.exit, "exit", false,
		"be the exit instead of the agent: accept streams and dial what their first line names")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Minute,
		"the whole run's deadline, which is also the deadline every dial gets")
}

// runAgent is the first role: the loop, over whatever -network built.
func runAgent(ctx context.Context, c config, out *record) error {
	w, err := wire(c, out.logf)
	if err != nil {
		return err
	}
	defer w.close()
	task, tools, err := chosen(c, w)
	if err != nil {
		return err
	}
	res, err := Run(ctx, w.client, task, tools, out)
	if err != nil {
		return err
	}
	if res.ToolError {
		out.logf("a tool told the model it had failed; the transcript above says which")
	}
	return nil
}

// chosen is -task: which prompt, and which tools go with it.
func chosen(c config, w *wiring) (Task, Tools, error) {
	switch c.task {
	case "summarize":
		return Summarize(), Tools{FetchURL: true, WriteDir: c.dir}, nil
	case "delegate":
		if w.delegate == nil {
			return Task{}, Tools{}, errors.New("agent-probe: -task delegate needs a peer that runs an agent of its own, which is -network socket")
		}
		// The delegating agent has one tool and no network of its own: what it
		// can reach is one peer, and what that peer may reach is the far
		// side's business and its sandbox's.
		return Delegate(c.peer), Tools{Delegate: w.delegate}, nil
	}
	return Task{}, Tools{}, fmt.Errorf("agent-probe: -task %q is neither summarize nor delegate", c.task)
}

// runExit is the second role: accept streams and dial what they name.
func runExit(ctx context.Context, c config, out *record) error {
	if c.network != "socket" {
		return errors.New("agent-probe: -exit accepts streams, which needs a tunneld to accept them from: -network socket")
	}
	allow, err := parseAllow(c.allow)
	if err != nil {
		return err
	}
	box, client, err := socketSandbox(c.socket, out.logf)
	if err != nil {
		return err
	}
	defer client.Close()
	return ServeExit(ctx, box, allow, out.logf)
}

// wiring is what -network decides: the client the loop runs on, the peer the
// delegate tool may open a stream to, and how to put it all down.
type wiring struct {
	client   *http.Client
	delegate func(ctx context.Context, peer string) (sandbox.Stream, error)
	close    func()
}

func wire(c config, logf func(string, ...any)) (*wiring, error) {
	switch c.network {
	case "direct":
		// E1's client, and the only mode in which this process resolves a name
		// or opens a socket of its own.
		return &wiring{client: &http.Client{}, close: func() {}}, nil

	case "null":
		w := behindTheContract(sandbox.NewNull(&localExit{logf: logf}, logf), c.peer, logf)
		// There is nobody to delegate to: the far end of a null stream is this
		// binary's own exit, and an exit runs no agent.
		w.delegate = nil
		return w, nil

	case "socket":
		box, client, err := socketSandbox(c.socket, logf)
		if err != nil {
			return nil, err
		}
		w := behindTheContract(box, c.peer, logf)
		inner := w.close
		w.close = func() { inner(); client.Close() }
		return w, nil
	}
	return nil, fmt.Errorf("agent-probe: -network %q is none of direct, null or socket", c.network)
}

// behindTheContract is the client for both modes that have a contract in the
// path, and the two things E2 found that a caller must not forget.
//
// ForceAttemptHTTP2 is the first: a Transport with a DialContext of its own
// does not configure HTTP/2 unless it is told to, so an agent moved behind the
// contract would otherwise have quietly changed its wire protocol and the
// number of streams it opens (E2, break 4).
//
// The second is that nothing else is different. The loop is handed an
// *http.Client and cannot tell which of the three it got.
func behindTheContract(box sandbox.Network, peer string, logf func(string, ...any)) *wiring {
	t := &http.Transport{DialContext: dialThrough(box, peer, logf), ForceAttemptHTTP2: true}
	return &wiring{
		client:   &http.Client{Transport: t},
		delegate: box.Open,
		close:    t.CloseIdleConnections,
	}
}

// socketSandbox is client.go's own example: a sandbox in another process
// composes sandbox.Dial with the null sandbox, so that a policy pushed down
// the socket is acknowledged and its digest recorded while streams pass
// through untouched.
//
// The knot is that Dial takes the function which answers a push before the
// thing that answers it exists, and it starts reading the socket at once. So
// the answer reaches the sandbox through a pointer stored afterwards, and a
// push that wins that race is refused rather than acknowledged: a sandbox that
// acknowledged a policy it had not recorded would be making the
// acknowledgement mean nothing.
func socketSandbox(path string, logf func(string, ...any)) (*sandbox.Null, *sandbox.Client, error) {
	if path == "" {
		return nil, nil, errors.New("agent-probe: -sandbox-socket is the path tunneld serves the contract on, and it is empty")
	}
	var ready atomic.Pointer[sandbox.Null]
	client, err := sandbox.Dial(path, func(ctx context.Context, policy []byte) error {
		box := ready.Load()
		if box == nil {
			return errors.New("agent-probe: a policy arrived before this sandbox was ready to record it")
		}
		return box.Apply(ctx, policy)
	})
	if err != nil {
		return nil, nil, err
	}
	box := sandbox.NewNull(client, logf)
	ready.Store(box)
	return box, client, nil
}

// record is this binary's one sink. The loop prints its transcript to it, and
// the dialer, the exit and the sandbox print their lines to it from their own
// goroutines, so it has to serialise — and a log.Logger already does, which is
// why there is no lock here. One line is one Print, so two goroutines cannot
// tear each other's sentences in half.
type record struct {
	to *log.Logger
}

func newRecord(w io.Writer) *record {
	return &record{to: log.New(w, "", 0)}
}

// Write is the io.Writer the loop is given. fmt writes a whole line at a time
// and log.Logger ends every line itself, so the newline fmt added is taken off
// again rather than doubled.
func (r *record) Write(p []byte) (int, error) {
	r.to.Print(string(bytes.TrimSuffix(p, []byte("\n"))))
	return len(p), nil
}

func (r *record) logf(format string, a ...any) {
	r.to.Printf(format, a...)
}
