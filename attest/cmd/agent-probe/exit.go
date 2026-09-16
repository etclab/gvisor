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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/attest/sandbox"
)

// The exit is the far end of the CONNECT line, and it is where N is enforced
// for an agent behind the contract.
//
// The agent cannot name a destination: Open takes a peer name, and nothing in
// attest/sandbox carries a host and a port (spike E2, break 2). E2's shim
// invented a first line on the stream to say where the bytes were going; this
// is the other side of that invention, and it is the only place in the
// arrangement that sees a destination at all. The agent's own process decides
// nothing about where it may go — it asks for the one peer it has and says
// what it wanted — and -allow is the list the decision is made from. An empty
// list refuses everything, which is the honest default for a process whose
// whole job is to be the place a destination is checked.
//
// The protocol, in full:
//
//	→ CONNECT host:port\n
//	← OK host:port\n        then bytes both ways, each half-close carried
//	← REFUSED host:port\n   then the stream closes
//
// The OK line is this binary's one addition to E2's sketch, and it is there
// because a refusal has to be told apart from a destination that is merely
// slow to speak. A TLS client sends a ClientHello and then waits, so an exit
// that answered only when it had refused would leave the agent reading a
// stream that may never say anything — and a dial that cannot fail is a dial
// that cannot report N.
//
// A refused destination and an unreachable one are the same line on purpose.
// Which of the two it was is the exit's business and the operator's log; the
// agent gets a dial error, which is the local form of the rule that a sandbox
// is told a stream did not happen and never why.

// An allowList is the destinations an exit will dial: -allow, parsed.
type allowList struct {
	// all is the local exit's state and no flag's: -network null puts this
	// binary's own exit behind the null sandbox to close the contract path on
	// a workstation, and that exit is not the enforcement point being studied.
	all bool

	names map[string]bool
}

// parseAllow reads the -allow flag: host:port, comma separated. An empty flag
// is an empty list and refuses everything.
func parseAllow(s string) (*allowList, error) {
	a := &allowList{names: map[string]bool{}}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(entry); err != nil {
			return nil, fmt.Errorf("agent-probe: -allow %q: a destination is host:port: %w", entry, err)
		}
		a.names[entry] = true
	}
	return a, nil
}

// allowAnything is the local exit's list, which is not a list.
func allowAnything() *allowList { return &allowList{all: true} }

// permits reports whether this exit will dial the destination, by the name the
// agent wrote and not by the address it resolves to. That is the same rule
// Deno's --allow-net turned out to use (spike E3), and for the same reason: an
// agent names a host, and a check against an address is a check against
// something nobody in this path chose.
func (a *allowList) permits(target string) bool {
	return a.all || a.names[target]
}

// String is what the -allow list says it is in the log, so that a refused run
// says what it was holding.
func (a *allowList) String() string {
	if a.all {
		return "anything"
	}
	if len(a.names) == 0 {
		return "nothing"
	}
	names := make([]string, 0, len(a.names))
	for n := range a.names {
		names = append(names, n)
	}
	return strings.Join(names, ",")
}

// ServeExit accepts streams from n and serves each one until ctx is done. It
// is a package-level function rather than a method so that an in-process
// harness runs exactly what -exit runs.
func ServeExit(ctx context.Context, n sandbox.Network, allow *allowList, logf func(string, ...any)) error {
	logf("EXIT serving, allow=%s", allow)
	for {
		s, who, err := n.Accept(ctx)
		if err != nil {
			return err
		}
		// The two identities go in at full width, as sandbox.Attested says
		// they must: the whole use of either is comparing it with a number an
		// operator wrote down somewhere else, and a truncated one is a number
		// an attacker gets to choose collisions in.
		logf("EXIT accepted a stream from peer=%q vendor=%s measurement=%s policy_digest=%s",
			who.Peer, who.Vendor, who.Measurement, who.PolicyDigest)
		go serveConnect(s, allow, logf)
	}
}

// serveConnect reads one destination, checks it, dials it and pumps.
func serveConnect(s sandbox.Stream, allow *allowList, logf func(string, ...any)) {
	defer s.Close()
	// The reader is kept for the pump: a line reader that buffered past the
	// newline already holds the first bytes of the client's ClientHello.
	br := bufio.NewReader(s)
	line, err := br.ReadString('\n')
	if err != nil {
		logf("EXIT could not read the destination: %v", err)
		return
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(line), "CONNECT ")
	if !ok {
		refuse(s, strings.TrimSpace(line), logf, "it is not a destination")
		return
	}
	if !allow.permits(target) {
		refuse(s, target, logf, "it is not in -allow="+allow.String())
		return
	}
	remote, err := net.Dial("tcp", target)
	if err != nil {
		refuse(s, target, logf, err.Error())
		return
	}
	defer remote.Close()
	if _, err := fmt.Fprintf(s, "OK %s\n", target); err != nil {
		logf("EXIT could not answer for %s: %v", target, err)
		return
	}
	logf("EXIT dialed %s -> %s", target, remote.RemoteAddr())
	pump(s, br, remote)
	logf("EXIT %s ended", target)
}

// refuse answers the one line a refused CONNECT gets and says locally which of
// the two kinds of refusal it was.
func refuse(s sandbox.Stream, target string, logf func(string, ...any), why string) {
	logf("EXIT refused %q: %s", target, why)
	fmt.Fprintf(s, "REFUSED %s\n", target)
	s.CloseWrite()
}

// pump copies bytes both ways and carries each half-close, which is what
// attest/sandbox/socket.go's pump does between a stream and a socketpair. It
// is written out again rather than imported: that one is unexported, and a
// command that reached into the sandbox package for it would be asking the
// package that must import nothing to export something.
//
// from is the reader that read the CONNECT line, not the stream, because it
// may hold bytes that arrived behind it.
func pump(s sandbox.Stream, from io.Reader, remote net.Conn) {
	ended := make(chan struct{}, 2)
	go carry(remote, from, func() { closeWrite(remote) }, ended)
	go carry(s, remote, func() { s.CloseWrite() }, ended)
	<-ended
	<-ended
}

// carry is one direction of the pump: everything the source has, and then the
// half-close that says there is no more of it. The two directions end
// independently, which is what carrying a half-close each way means.
func carry(dst io.Writer, src io.Reader, end func(), ended chan<- struct{}) {
	io.Copy(dst, src)
	end()
	ended <- struct{}{}
}

// closeWrite ends this side of the TCP connection, so that a client which has
// finished sending is seen to have finished by the server it reached.
func closeWrite(c net.Conn) {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
		return
	}
	c.Close()
}

// localExit is the Network that -network null needs and a workstation cannot
// have.
//
// The null sandbox is a Sandbox over a Network, and in the real arrangement
// that Network is tunneld — which cannot serve here: this workstation has no
// /sys/kernel/config/tsm/report, so there is no tunnel for a stream to be on
// (ticket 22's spike E4, and E2's reason for running in-process). What
// -network null means in this binary is therefore the contract path and
// nothing else: Open hands back one end of a socketpair with this binary's own
// exit on the other, and that exit plainly dials the destination named in the
// CONNECT line. Every line the agent runs on is the real one — Open, the
// net.Conn adapter, the CONNECT line, the deadlines, the half-close — and the
// only thing missing from the middle is the tunnel.
type localExit struct {
	logf func(string, ...any)

	// allow is the list the exit behind these streams decides from. A nil one
	// is -network null's own, which is no list at all: the enforcement point
	// this study is about is the exit in the other process, and a local exit
	// that refused things would be a second one nobody pushed a policy to. A
	// test hands it a list to watch a refusal arrive at the agent without a
	// tunneld to carry it.
	allow *allowList
}

var _ sandbox.Network = (*localExit)(nil)

// Open gives back one end of a socketpair with an exit on the other. The peer
// name is not used, because there is no peer: it is in the log line and
// nowhere else, which is itself the finding E2 recorded — a peer name is the
// only thing Open takes and it says nothing about where anything is going.
func (l *localExit) Open(_ context.Context, peer string) (sandbox.Stream, error) {
	near, far, err := streamPair()
	if err != nil {
		return nil, err
	}
	l.logf("OPEN a local stream for peer=%q", peer)
	go serveConnect(far, l.list(), l.logf)
	return near, nil
}

// list is this exit's allow list, which by default allows anything.
func (l *localExit) list() *allowList {
	if l.allow == nil {
		return allowAnything()
	}
	return l.allow
}

// Accept has nobody to accept from. A workstation exit is not a peer and
// nothing dials it.
func (l *localExit) Accept(context.Context) (sandbox.Stream, sandbox.Attested, error) {
	return nil, sandbox.Attested{}, errors.New("agent-probe: -network null has no peers, so nothing opens a stream to it")
}

// streamPair is two ends of one AF_UNIX SOCK_STREAM socketpair, which is the
// same object tunneld hands a sandbox in another process. A *net.UnixConn
// satisfies sandbox.Stream as it stands — read, write, CloseWrite and the
// three deadlines — which is the contract's own argument for its shape.
func streamPair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("agent-probe: socketpair: %w", err)
	}
	// net.FileConn dups the descriptor it is given, so both files are closed
	// here whatever happens and only the connections are kept.
	near, far := os.NewFile(uintptr(fds[0]), "near"), os.NewFile(uintptr(fds[1]), "far")
	defer near.Close()
	defer far.Close()
	var ends []*net.UnixConn
	for _, f := range []*os.File{near, far} {
		c, err := net.FileConn(f)
		u, ok := c.(*net.UnixConn)
		if !ok {
			for _, made := range ends {
				made.Close()
			}
			return nil, nil, fmt.Errorf("agent-probe: the %s end of the socketpair is a %T: %v", f.Name(), c, err)
		}
		ends = append(ends, u)
	}
	return ends[0], ends[1], nil
}
