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

// The tunnel helper: the one process outside the sandbox that the adapter's
// bytes pass through.
//
// It is a urpc server on a socketpair whose other end the sentry holds, and a
// client of tunneld's local socket. On TunnelHelper.Open it asks tunneld for a
// stream to the named peer, says on that stream where the bytes are going, and
// hands the descriptor back if the far exit agrees to dial it. That is the
// whole of it: the helper is not a proxy and does not pump, because the stream
// tunneld hands over is a socketpair end that the sentry can read and write
// itself.
//
// It never decides anything. The table is the sentry's and was checked before
// the call arrived; the far end's own allow list is ticket 23's and is checked
// where the dial happens. The helper's one judgement is telling a refusal from
// an outage, because the sandbox is told a different errno for each.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	controlclient "gvisor.dev/gvisor/pkg/control/client"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// TunnelHelperCmd implements subcommands.Command for the tunnel helper. The
// urpc object it serves is TunnelHelper below, and the two are separate types
// because urpc names a method after the type that carries it.
type TunnelHelperCmd struct {
	util.InternalSubCommand

	sockFD        int
	sandboxSocket string
	controlSocket string
}

// Name implements subcommands.Command.Name.
func (*TunnelHelperCmd) Name() string {
	return "tunnel-helper"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*TunnelHelperCmd) Synopsis() string {
	return "runs the process that turns the sandbox's requests into tunneld streams"
}

// Usage implements subcommands.Command.Usage.
func (*TunnelHelperCmd) Usage() string {
	return "tunnel-helper -sock-fd=<socket fd> -sandbox-socket=<path> -control-socket=<path>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (h *TunnelHelperCmd) SetFlags(f *flag.FlagSet) {
	f.IntVar(&h.sockFD, "sock-fd", -1, "FD of a Unix domain socket that is connected to the sentry")
	f.StringVar(&h.sandboxSocket, "sandbox-socket", "", "path of tunneld's sandbox socket")
	f.StringVar(&h.controlSocket, "control-socket", "", "path of the sentry's control socket, where a pushed policy is forwarded as Policy.Narrow")
}

// Execute implements subcommands.Command.Execute.
func (h *TunnelHelperCmd) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if h.sockFD < 0 || h.sandboxSocket == "" {
		f.Usage()
		return subcommands.ExitUsageError
	}
	sock, err := unet.NewSocket(h.sockFD)
	if err != nil {
		util.Fatalf("Failed to construct unet.Socket on fd %d: %v", h.sockFD, err)
	}
	applier := newPolicyApplier(h.controlSocket)
	client, err := dialTunneld(h.sandboxSocket, tunneldRoleEnforcing, applier.apply, log.Warningf)
	if err != nil {
		util.Fatalf("%v", err)
	}
	defer client.Close()
	applier.attach(client)
	log.Infof("Tunnel helper connected to tunneld at %q, control socket %q", h.sandboxSocket, h.controlSocket)

	// The server closes each descriptor it handed out as soon as the reply
	// carrying it has gone: urpc does not do it, and a helper that kept a
	// reference to every stream would keep the far exit's TCP connection open
	// long after the sandbox closed its own end — tunneld's pump only sees the
	// end of a stream when the last descriptor for it is gone.
	helper := &TunnelHelper{client: client}
	server := urpc.NewServerWithCallback(helper.handedOver)
	server.Register(helper)
	// Handle blocks: the helper's life is the socketpair's, and the
	// socketpair's end is the sentry going away. A tunneld that goes away
	// instead is not the end of the helper — every later Open simply answers
	// "unavailable", which the sandbox sees as ENETUNREACH and the sentry
	// records.
	if err := server.Handle(sock); err != nil {
		log.Debugf("Tunnel helper: the sentry channel ended: %v", err)
	}
	log.Infof("Tunnel helper exiting: the sentry closed the channel")
	return subcommands.ExitSuccess
}

// tunneldPulse is how often a sandbox that has acknowledged a policy says it is
// still enforcing it. It mirrors sandbox.DefaultPulse, which is the constant
// tunneld's side of the contract counts misses against; the two are written
// twice for the reason this whole file is (attest is another module), and a
// change to either is a change to both.
const tunneldPulse = 1 * time.Second

// policyApplier is the helper's answer to a pushed policy: forward it to the
// sentry, return the sentry's verdict, and — once a policy is in force — keep
// saying so.
//
// It decides nothing. The subset check, the table and the exec list are the
// sentry's; this dials the control socket, makes one call and carries the
// sentence back. That is deliberate: the helper is outside the measured
// boundary, so a helper that could decide anything would be a helper that could
// decide it wrongly and have nobody notice.
type policyApplier struct {
	controlSocket string

	// ready is closed once the client is set. A push cannot be answered before
	// the socket it arrived on exists, but the callback is installed by
	// dialTunneld before it returns, so this closes the window.
	ready  chan struct{}
	client *tunneldClient

	mu sync.Mutex
	// digest is the policy in force, which is what each alive carries.
	digest string
	// ticking says the one alive goroutine is already running. A later
	// narrowing retargets it rather than starting a second.
	ticking bool
}

func newPolicyApplier(controlSocket string) *policyApplier {
	return &policyApplier{controlSocket: controlSocket, ready: make(chan struct{})}
}

// attach hands the applier the client its alive messages go out on.
func (a *policyApplier) attach(cl *tunneldClient) {
	a.client = cl
	close(a.ready)
}

// apply answers one policy push: the sentry's error verbatim, or nil once the
// sandbox is enforcing it.
func (a *policyApplier) apply(policy []byte) error {
	<-a.ready
	start := time.Now()
	digest, err := a.narrow(policy)
	if err != nil {
		log.Warningf("Tunnel helper: the sentry refused a policy push of %d bytes after %v: %v", len(policy), time.Since(start), err)
		return err
	}
	log.Infof("Tunnel helper: the sentry is enforcing a policy of %d bytes, sha256=%s, in %v", len(policy), digest, time.Since(start))
	a.live(digest)
	return nil
}

// narrow is the one call. The control socket is dialled per apply and not held:
// the sentry's control server only listens once the sandbox is up, which is
// long after this process starts, and a policy arrives a handful of times in a
// sandbox's life.
func (a *policyApplier) narrow(policy []byte) (string, error) {
	if a.controlSocket == "" {
		return "", fmt.Errorf("policy refused: this sandbox's helper was given no control socket, so a policy cannot reach its sentry")
	}
	conn, err := controlclient.ConnectTo(a.controlSocket)
	if err != nil {
		return "", fmt.Errorf("policy refused: reaching the sentry at %s: %v", a.controlSocket, err)
	}
	defer conn.Close()
	var result boot.PolicyNarrowResult
	if err := conn.Call(boot.PolicyNarrow, &boot.PolicyNarrowArgs{Policy: policy}, &result); err != nil {
		if re, ok := err.(urpc.RemoteError); ok {
			// The sentry's own sentence, carried back word for word: it is what
			// the peer that pushed the policy is told, and a helper that
			// rephrased it would be a helper writing refusals.
			return "", errors.New(re.Message)
		}
		return "", fmt.Errorf("policy refused: asking the sentry to narrow: %v", err)
	}
	if result.Digest == "" {
		return "", fmt.Errorf("policy refused: the sentry accepted the policy and named no digest")
	}
	return result.Digest, nil
}

// live starts the one alive goroutine, or retargets it at a newer policy.
//
// The first alive goes out HERE, synchronously, before apply returns and so
// before the acknowledgement this narrowing is answered with. That ordering is
// not decoration. The far side starts watching a digest the moment its Apply
// returns, and the last thing it heard from this sandbox before that was the
// previous policy's digest — so a ticker whose first tick is a second away
// leaves a one-second window in which the watch sees a stale digest and calls
// it a mismatch. The adapter check measured exactly that: a watch on the new
// policy lost after 250 ms, naming the digest of the policy it had just
// replaced. One pulse ahead of the ack closes the window, because the socket
// delivers them in the order they were written.
func (a *policyApplier) live(digest string) {
	a.mu.Lock()
	a.digest = digest
	start := !a.ticking
	a.ticking = true
	a.mu.Unlock()
	if err := a.client.send(tunneldMessage{ID: 0, Type: tunneldMsgAlive, Digest: digest}, -1); err != nil {
		log.Warningf("Tunnel helper: the first alive for %s did not go out: %v", digest, err)
	}
	if !start {
		return
	}
	go a.pulse()
}

// pulse says, once a second, which policy this sandbox is enforcing. It carries
// the digest rather than a bare "still here" because an acknowledgement is a
// claim about the past: the far side has to be able to tell a sandbox enforcing
// the policy it pushed from one enforcing something else.
//
// It ends when the client does, which is when the sentry closes the channel,
// which is when the workload exits. Nothing else stops it: a sandbox that is
// running is a sandbox that is enforcing.
func (a *policyApplier) pulse() {
	t := time.NewTicker(tunneldPulse)
	defer t.Stop()
	for {
		select {
		case <-a.client.done:
			log.Infof("Tunnel helper: the tunneld socket is gone, so the sandbox stops saying it is alive")
			return
		case <-t.C:
			a.mu.Lock()
			digest := a.digest
			a.mu.Unlock()
			if err := a.client.send(tunneldMessage{ID: 0, Type: tunneldMsgAlive, Digest: digest}, -1); err != nil {
				log.Debugf("Tunnel helper: an alive did not go out: %v", err)
				return
			}
		}
	}
}

// TunnelHelper is the object the sentry calls. Its one method is
// TunnelHelper.Open, and urpc takes that name from this type — which is also
// why handedOver below is unexported: urpc registers every exported method of
// the object it is given, and would reject one that is not an RPC.
type TunnelHelper struct {
	client *tunneldClient

	mu sync.Mutex
	// sent holds the descriptors the last call put in its reply. urpc's server
	// marshals a result's files and then forgets them, so this is where they
	// are remembered until the reply is on the wire.
	sent []*os.File
}

// handedOver runs after each RPC, once urpc has sent the reply and the
// descriptors that went with it. RPCs on one connection do not overlap, so
// whatever is here belongs to the call that just finished.
func (rpc *TunnelHelper) handedOver() {
	rpc.mu.Lock()
	sent := rpc.sent
	rpc.sent = nil
	rpc.mu.Unlock()
	for _, f := range sent {
		if err := f.Close(); err != nil {
			log.Warningf("Tunnel helper: closing a handed-over stream: %v", err)
		}
	}
}

// tunnelHelperOpenArgs names one stream.
type tunnelHelperOpenArgs struct {
	Peer     string
	HostPort string
}

// openDeadline bounds how long the helper waits for the exit's one line. A
// refusal comes back at once and a dial that is merely slow still answers; a
// stream that says nothing at all is a stream the sandbox must not be left
// blocked inside connect(2) on.
const openDeadline = 30 * time.Second

// Open asks tunneld for a stream, tells the far exit where it is going, and
// hands the descriptor back.
//
// The one line the exit answers with is the whole protocol (attest/cmd/
// agent-probe's exit): "OK host:port" means the dial happened and the bytes
// after it are the peer's, "REFUSED host:port" means it did not. The OK is
// what makes a refusal distinguishable from a destination that is merely slow
// to speak, which matters because a TLS client sends its ClientHello and then
// waits.
func (rpc *TunnelHelper) Open(args *tunnelHelperOpenArgs, result *urpc.FilePayload) error {
	f, err := rpc.client.open(args.Peer)
	if err != nil {
		return fmt.Errorf("unavailable: asking tunneld for a stream to peer %q: %v", args.Peer, err)
	}
	conn, err := unixConnFromFile(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("unavailable: %v", err)
	}
	fd, err := rpc.connect(conn, args.HostPort)
	if err != nil {
		// The stream is abandoned, so it is shut down and not merely closed:
		// a thread of tunneld's parked in read(2) on the other end holds a
		// reference to the socket, and without the shutdown the end of the
		// stream does not travel (spike E3, run 1: a 35 second gap).
		abandonStream(conn)
		return err
	}
	f = os.NewFile(uintptr(fd), args.HostPort)
	result.Files = []*os.File{f}
	rpc.mu.Lock()
	rpc.sent = append(rpc.sent, f)
	rpc.mu.Unlock()
	return nil
}

// connect writes the destination, reads the one line back and returns a
// descriptor for the stream on success.
func (rpc *TunnelHelper) connect(conn *net.UnixConn, hostPort string) (int, error) {
	if err := conn.SetDeadline(time.Now().Add(openDeadline)); err != nil {
		return -1, fmt.Errorf("unavailable: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s\n", hostPort); err != nil {
		return -1, fmt.Errorf("unavailable: asking the exit for %s: %v", hostPort, err)
	}
	// Exactly one line, and no buffered reader: anything read past the newline
	// would be the peer's first bytes, and this helper has nowhere to put them
	// — the sentry reads the descriptor itself from here on.
	line, err := readLine(conn)
	if err != nil {
		return -1, fmt.Errorf("unavailable: the exit did not answer for %s: %v", hostPort, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return -1, fmt.Errorf("unavailable: %v", err)
	}
	switch {
	case strings.HasPrefix(line, "OK"):
		// The descriptor handed on is a duplicate, so that the connection this
		// helper holds can be dropped without taking the stream with it.
		raw, err := conn.File()
		if err != nil {
			return -1, fmt.Errorf("unavailable: duplicating the stream for %s: %v", hostPort, err)
		}
		fd, err := unix.Dup(int(raw.Fd()))
		raw.Close()
		if err != nil {
			return -1, fmt.Errorf("unavailable: duplicating the stream for %s: %v", hostPort, err)
		}
		// Plain close, not a shutdown: the duplicate is the same open socket,
		// and a shutdown here would reach the sentry's copy of it.
		conn.Close()
		log.Infof("Tunnel helper opened %s", hostPort)
		return fd, nil
	case strings.HasPrefix(line, "REFUSED"):
		log.Infof("Tunnel helper: the exit refused %s (%q)", hostPort, line)
		return -1, fmt.Errorf("refused: %s", hostPort)
	default:
		return -1, fmt.Errorf("unavailable: the exit answered %q for %s", line, hostPort)
	}
}

// readLine reads one line and not a byte more.
func readLine(conn *net.UnixConn) (string, error) {
	var sb strings.Builder
	var b [1]byte
	for sb.Len() < 1024 {
		n, err := conn.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			sb.WriteByte(b[0])
			continue
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no newline in the first %d bytes", sb.Len())
}

// abandonStream gives up a stream this helper will not hand on.
func abandonStream(conn *net.UnixConn) {
	if raw, err := conn.File(); err == nil {
		unix.Shutdown(int(raw.Fd()), unix.SHUT_RDWR)
		raw.Close()
	}
	conn.Close()
}

// unixConnFromFile turns the descriptor tunneld sent into a connection.
// net.FileConn duplicates it, so the caller still owns f.
func unixConnFromFile(f *os.File) (*net.UnixConn, error) {
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("the descriptor tunneld sent: %w", err)
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("the descriptor tunneld sent is a %T, not a unix socket", c)
	}
	return u, nil
}
