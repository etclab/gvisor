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
	"io"

	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The sandbox this command puts beside its tunneld (ticket 22,
// docs/sandbox-contract.md).
//
// It is the null sandbox: it asks tunneld for streams, answers the streams
// peers open, and records a pushed policy without enforcing anything. The
// exercise runs inside it and is the first client of the local contract — where
// it used to hold a *tunneld.Channel and call Exchange, it now holds a
// [sandbox.Sandbox] and opens a stream per exchange. The figures it prints keep
// their shape, and what changed underneath them is that nothing in the exercise
// can see a tunnel any more.
//
// Milestone 4 replaces this file's sandbox, not this file's contract: a runsc
// sandbox in another process attaches over the unix socket instead
// ([sandbox.Host]), and the exercise's half of it goes away with the exercise.

// conventionalSandboxSocket is where a sandbox in another process would look
// for this tunneld: under the run directory, one socket per tunneld.
//
// It is a convention and not the default. A tunneld with nobody to attach would
// otherwise create a socket at every start, including inside the measured image
// where there is no second process and the root filesystem may not take one,
// and every recorded scenario would carry a line about it. The flag is what
// turns it on.
const conventionalSandboxSocket = "/run/tunneld/sandbox.sock"

// attachSandbox builds the sandbox beside this tunneld and returns it with the
// function that takes it down.
//
// Two things are wired here. The null sandbox is always built, wrapped in the
// envelope check tunneld makes on a pushed policy before a sandbox sees it, and
// it is what the exercise is handed. The socket is built when a path was given,
// and it is the same contract with a process boundary in it.
//
// Which of the two answers incoming streams is a choice, because there is one
// queue of them and two possible sandboxes. The rule is that a sandbox in
// another process is *the* sandbox: with a socket configured, this command's own
// echo stands down and the attached sandbox accepts. Without one, the echo
// answers, which is what every recorded scenario runs.
//
// The same choice decides where a *pushed* policy goes, and it is
// [tunneld.Tunneld.Attach] that says so. Without a socket the in-process null
// sandbox is told; with one the [sandbox.Host] is, so a push crosses the process
// boundary to whatever attached and comes back as that sandbox's answer — and a
// host with nobody attached refuses it, which is the honest reply to a peer
// asking whether its policy landed.
func attachSandbox(ctx context.Context, td *tunneld.Tunneld, socket, sandboxID string, logf func(string, ...any)) (sandbox.Sandbox, func()) {
	null := sandbox.NewNull(td, logf)
	box := tunneld.PolicyChecked(null)
	answerInProcess := func() (sandbox.Sandbox, func()) {
		td.Attach(null)
		answering, stop := context.WithCancel(ctx)
		go answer(answering, box, sandboxID, logf)
		return box, stop
	}
	if socket == "" {
		return answerInProcess()
	}
	host, err := sandbox.Listen(socket, td, logf)
	if err != nil {
		// Not fatal: a tunneld whose socket could not be created still dials,
		// answers exchanges and exercises its peers. What it cannot do is hand
		// a stream to a sandbox beside it, and the console says so.
		logf("sandbox socket %s: %v; no sandbox in another process can attach", socket, err)
		return answerInProcess()
	}
	td.Attach(host)
	logf("sandbox socket %s: a sandbox in another process opens and accepts streams here; this tunneld answers none itself, and a pushed policy is passed to it", socket)
	return box, func() { host.Close() }
}

// answer is the sandbox's serving half: every stream a peer opens is read to
// its end and echoed back with this sandbox's identifier in front of it, which
// is the same answer [echo] gives an exchange and is what lets a caller tell
// which of two guests served it.
//
// One line is logged per distinct peer rather than per stream. What it says is
// the whole of what a sandbox is told about who is at the other end — a name, a
// vendor, a measurement and a policy digest — and saying it once per peer is
// what keeps a console readable while a run puts hundreds of streams through.
func answer(ctx context.Context, box sandbox.Sandbox, sandboxID string, logf func(string, ...any)) {
	prefix := []byte(sandboxID + ":")
	seen := map[sandbox.Attested]bool{}
	for {
		stream, who, err := box.Accept(ctx)
		if err != nil {
			return
		}
		if !seen[who] {
			seen[who] = true
			logf("SANDBOX stream from peer=%q vendor=%s measurement=%s policy_digest=%s",
				who.Peer, who.Vendor, abbreviate(who.Measurement), abbreviate(who.PolicyDigest))
		}
		go echoStream(stream, prefix)
	}
}

// echoStream answers one stream. The peer half-closes when its request is
// complete, so reading to end-of-file is reading the request; half-closing back
// is what tells the peer its answer is complete.
func echoStream(s sandbox.Stream, prefix []byte) {
	defer s.Close()
	request, err := io.ReadAll(s)
	if err != nil {
		return
	}
	if _, err := s.Write(append(append([]byte(nil), prefix...), request...)); err != nil {
		return
	}
	s.CloseWrite()
}
