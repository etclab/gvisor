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

// The boot side of the tunnel adapter: the object that holds the table and the
// channel to the helper.
//
// Two callers reach the same method. The sentry's own connect intercept calls
// it in process, through the one-method interface pkg/sentry/socket/netstack
// declares, so that netstack gains no dependency on urpc. A supervisor outside
// the sandbox can call it over the control socket as `Tunnel.Attach`, which is
// how it is testable from the host without a workload.
//
// The table is checked here as well as at the intercept, because these are two
// different claims: the intercept decides which of the sentry's own addresses
// a socket asked for, and this decides whether the name, port and peer the
// caller ended up with are ones the operator wrote down. Spike E3 measured the
// transport this rides on: urpc plus a FilePayload over a donated socketpair,
// under the sentry's existing seccomp filter, with no new syscall allowed and
// a sub-millisecond call.

package boot

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

// TunnelAttachArgs names one stream: the tunneld peer whose exit dials it, and
// the destination that exit is to be asked for.
type TunnelAttachArgs struct {
	Peer     string
	HostPort string
}

// Tunnel is the control object the adapter is reached through.
type Tunnel struct {
	table *netstack.TunnelTable

	// mu serializes calls on the channel to the helper, which is one socket.
	mu sync.Mutex
	// +checklocks:mu
	client *urpc.Client
}

// newTunnel reads the table from tableFD and builds the channel to the helper
// on tunnelFD. It takes ownership of both descriptors.
func newTunnel(tunnelFD, tableFD int) (*Tunnel, error) {
	tableFile := os.NewFile(uintptr(tableFD), "tunnel-table")
	defer tableFile.Close()
	data, err := io.ReadAll(tableFile)
	if err != nil {
		return nil, fmt.Errorf("reading the tunnel table: %w", err)
	}
	table, err := netstack.ParseTunnelTable(data)
	if err != nil {
		return nil, err
	}
	sock, err := unet.NewSocket(tunnelFD)
	if err != nil {
		return nil, fmt.Errorf("the tunnel helper channel on fd %d: %w", tunnelFD, err)
	}
	return &Tunnel{table: table, client: urpc.NewClient(sock)}, nil
}

// Attach implements the control method. The descriptor comes back as the one
// file of the payload.
func (tn *Tunnel) Attach(args *TunnelAttachArgs, result *urpc.FilePayload) error {
	fd, err := tn.open(args.Peer, args.HostPort)
	if err != nil {
		return err
	}
	result.Files = []*os.File{os.NewFile(uintptr(fd), args.HostPort)}
	return nil
}

// tunnelAttacher is *Tunnel seen from inside the sentry. It is a separate type
// because urpc registers every exported method of the object it is given, and
// the in-process signature is not a urpc one.
type tunnelAttacher struct {
	tunnel *Tunnel
}

// Attach implements netstack.TunnelAttacher.Attach.
func (a tunnelAttacher) Attach(peer, hostPort string) (int, error) {
	return a.tunnel.open(peer, hostPort)
}

// open checks the request against the table and asks the helper for the
// stream.
func (tn *Tunnel) open(peer, hostPort string) (int, error) {
	if err := tn.permits(peer, hostPort); err != nil {
		return -1, err
	}
	var result urpc.FilePayload
	tn.mu.Lock()
	err := tn.client.Call("TunnelHelper.Open", &TunnelAttachArgs{Peer: peer, HostPort: hostPort}, &result)
	tn.mu.Unlock()
	if err != nil {
		for _, f := range result.Files {
			f.Close()
		}
		return -1, tunnelCallError(hostPort, err)
	}
	if len(result.Files) != 1 {
		for _, f := range result.Files {
			f.Close()
		}
		return -1, fmt.Errorf("TunnelHelper.Open(%s): wanted one descriptor, got %d", hostPort, len(result.Files))
	}
	// The descriptor the endpoint keeps has to be one this side owns outright.
	// Client.Call hands the received files to the result, so the explicit
	// Close below is what keeps this from leaking one per stream; the
	// duplicate is what survives it.
	//
	// The duplicate is a plain dup(2), which is also what this tree's own
	// fd.NewFromFile does. It drops no flag: urpc's transport does not ask for
	// MSG_CMSG_CLOEXEC and unet's ExtractFDs does not set FD_CLOEXEC, so the
	// descriptor arrives without it. A CLOEXEC-preserving duplicate is not
	// available here in any case — the sentry's own seccomp filter allows
	// fcntl only for F_GETFL, F_SETFL and F_GETFD — and the sentry execs
	// nothing after boot, so the flag would be inert. Recorded as a leftover.
	fd, dupErr := unix.Dup(int(result.Files[0].Fd()))
	result.Files[0].Close()
	if dupErr != nil {
		return -1, fmt.Errorf("TunnelHelper.Open(%s): duplicating the descriptor: %w", hostPort, dupErr)
	}
	return fd, nil
}

// tunnelCallError turns the helper's answer into the one distinction the
// sentry acts on: a destination the far exit itself refused, which the sandbox
// is told as ECONNREFUSED, against everything else, which is ENETUNREACH and a
// recorded refusal.
func tunnelCallError(hostPort string, err error) error {
	re, ok := err.(urpc.RemoteError)
	if !ok {
		// Not a refusal at all: a dead helper answers with a raw errno from
		// the write of the request, not a RemoteError (spike E3, finding 5).
		return fmt.Errorf("TunnelHelper.Open(%s): %w", hostPort, err)
	}
	if strings.HasPrefix(re.Message, "refused: ") {
		return fmt.Errorf("%w: %s", netstack.ErrTunnelRefused, strings.TrimPrefix(re.Message, "refused: "))
	}
	return fmt.Errorf("TunnelHelper.Open(%s): %s", hostPort, re.Message)
}

// permits is the table check: the name, the port and the peer must all be the
// ones the table names, or no stream is asked for at all.
func (tn *Tunnel) permits(peer, hostPort string) error {
	i := strings.LastIndex(hostPort, ":")
	if i < 0 {
		return fmt.Errorf("the tunnel table names no destination %q", hostPort)
	}
	host, portText := hostPort[:i], hostPort[i+1:]
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("the tunnel table names no destination %q", hostPort)
	}
	entry, ok := tn.table.Names[strings.ToLower(strings.TrimSuffix(host, "."))]
	if !ok {
		return fmt.Errorf("the tunnel table does not name %q", host)
	}
	if entry.Port != port {
		return fmt.Errorf("the tunnel table permits %q on port %d and not %d", host, entry.Port, port)
	}
	if want := tn.table.PeerFor(entry); want != peer {
		return fmt.Errorf("the tunnel table has %q dialled by peer %q and not %q", host, want, peer)
	}
	return nil
}

// setupTunnel reads the table and takes the channel to the helper, at the time
// the loader is built, so that a table that cannot be enforced fails the boot
// rather than surfacing as a sandbox that quietly reaches nothing.
//
// It does not install the adapter in the sentry: the sandbox's loopback NIC is
// created later, by a control message from runsc, and the ceiling check has
// nothing to look at until it exists. installTunnel is the second half.
func setupTunnel(l *Loader, tunnelFD, tableFD int) error {
	tn, err := newTunnel(tunnelFD, tableFD)
	if err != nil {
		return err
	}
	l.tunnel = tn
	log.Infof("Tunnel table read: %d names, helper channel on fd %d", len(tn.table.Names), tunnelFD)
	return nil
}

// installTunnel puts the adapter in the sentry, once the stack is the one the
// sandbox will actually run with. It is the second of the two places the
// ceiling is enforced: the first is runsc's own flag validation, and this one
// holds even if the sentry were started by hand.
func (l *Loader) installTunnel() error {
	if l.tunnel == nil {
		return nil
	}
	st, ok := l.k.RootNetworkNamespace().Stack().(*netstack.Stack)
	if !ok {
		return fmt.Errorf("the tunnel adapter requires --network=none and this sandbox's stack is a %T", l.k.RootNetworkNamespace().Stack())
	}
	if err := netstack.InstallTunnel(st, l.tunnel.table, tunnelAttacher{tunnel: l.tunnel}); err != nil {
		return err
	}
	log.Infof("Tunnel adapter installed with %d names", len(l.tunnel.table.Names))
	return nil
}
