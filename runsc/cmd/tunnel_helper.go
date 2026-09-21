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
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
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
	return "tunnel-helper -sock-fd=<socket fd> -sandbox-socket=<path>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (h *TunnelHelperCmd) SetFlags(f *flag.FlagSet) {
	f.IntVar(&h.sockFD, "sock-fd", -1, "FD of a Unix domain socket that is connected to the sentry")
	f.StringVar(&h.sandboxSocket, "sandbox-socket", "", "path of tunneld's sandbox socket")
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
	client, err := dialTunneld(h.sandboxSocket, applyFromTunneld, log.Warningf)
	if err != nil {
		util.Fatalf("%v", err)
	}
	defer client.Close()
	log.Infof("Tunnel helper connected to tunneld at %q", h.sandboxSocket)

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

// applyFromTunneld answers a policy push. Ticket 25 records it and
// acknowledges it; enforcing one is ticket 26's.
func applyFromTunneld(policy []byte) error {
	log.Infof("Tunnel helper acknowledging a policy push of %d bytes; nothing enforces it yet (ticket 26)", len(policy))
	return nil
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
