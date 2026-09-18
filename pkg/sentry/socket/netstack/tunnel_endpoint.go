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

// The endpoint half of the tunnel adapter: a tcpip.Endpoint over a host
// descriptor, so that an unmodified runtime inside the sandbox is served by
// the stream the helper handed in rather than by a TCP connection the sentry
// does not have.
//
// Spike E1 measured what a runtime actually demands of a connected socket, on
// the host with injected failures and then inside the sandbox with both
// runtimes. Four answers are load-bearing and everything else may be refused:
//
//   - getsockopt(SOL_SOCKET, SO_ERROR) must return 0 from a zeroed int. Refuse
//     it and Go's dial fails cleanly while libuv reads an uninitialised stack
//     variable and reports a garbage errno. It comes for free from owning a
//     tcpip.SocketOptions whose handler has a nil LastError.
//   - getpeername must answer the synthetic destination. Refusing it wedges
//     net.Dial for ever inside WaitWrite, with no further syscall to show for
//     it, because the edge-triggered EPOLLOUT is already spent.
//   - getsockname must answer an AF_INET address that differs from the peer's,
//     or Go's selfConnect heuristic closes the connection and dials twice more
//     — two wasted handoffs per dial.
//   - shutdown(SHUT_WR) must reach shutdown(2) on the descriptor, or a
//     half-close never becomes the peer's EOF and a request/response protocol
//     stalls until something times out.
//
// Two pieces of the endpoint's own bookkeeping are load-bearing too, and the
// spike had to get both right to pass at all: Read is handed an io.Writer with
// no declared capacity, so what a short user buffer would not take is kept in
// rbuf rather than dropped; and Write takes ownership of what it reads from
// the Payloader, so what the descriptor would not take is kept in wbuf and
// flushed from the notification path — the sandbox may be waiting for a reply
// and never write again.
//
// Readiness follows hostinet (pkg/sentry/socket/hostinet/socket.go): the
// descriptor is registered with fdnotifier for edge-triggered epoll and asked
// with a non-blocking poll for its current state. Names and options are
// answered from sentry-side state because the sentry's own seccomp filter
// permits neither getsockname nor setsockopt.

package netstack

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunnelEndpoint is a tcpip.Endpoint over a host descriptor.
type tunnelEndpoint struct {
	tcpip.DefaultSocketOptionsHandler

	fd int32

	// q is the queue fdnotifier notifies; entry forwards its events to target,
	// which is the sock's own queue and so what the sandbox's poll and the
	// sentry's blocking paths wait on.
	q      waiter.Queue
	target *waiter.Queue
	entry  waiter.Entry

	ops tcpip.SocketOptions

	mu sync.Mutex
	// +checklocks:mu
	local tcpip.FullAddress
	// +checklocks:mu
	remote tcpip.FullAddress
	// +checklocks:mu
	closed bool
	// +checklocks:mu
	shutRd bool
	// +checklocks:mu
	shutWr bool
	// rbuf holds what was read from the descriptor and the caller's buffer
	// would not take.
	// +checklocks:mu
	rbuf []byte
	// wbuf holds what the caller handed over and the descriptor would not
	// take.
	// +checklocks:mu
	wbuf []byte
	// The keepalive options are remembered so that the four setsockopt calls
	// Go makes on every connection look honoured.
	// +checklocks:mu
	keepaliveIdle, keepaliveInterval tcpip.KeepaliveIdleOption
	// +checklocks:mu
	keepaliveCount int
}

var _ tcpip.Endpoint = (*tunnelEndpoint)(nil)

// The buffer sizes reported to the sandbox. They describe nothing real — the
// transport is an AF_UNIX socketpair — but a socket that reports none at all
// is a socket some runtime will divide by.
const tunnelBufSize = 208 << 10

func tunnelSendLimits(tcpip.StackHandler) tcpip.SendBufferSizeOption {
	return tcpip.SendBufferSizeOption{Min: 4096, Default: tunnelBufSize, Max: 4 << 20}
}

func tunnelRecvLimits(tcpip.StackHandler) tcpip.ReceiveBufferSizeOption {
	return tcpip.ReceiveBufferSizeOption{Min: 4096, Default: tunnelBufSize, Max: 4 << 20}
}

// newTunnelEndpoint takes ownership of fd and dresses it up as a connected
// AF_INET stream socket between local and remote. It closes fd on failure.
func newTunnelEndpoint(fd int, local, remote tcpip.FullAddress, target *waiter.Queue) (*tunnelEndpoint, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setting O_NONBLOCK on the attached descriptor: %w", err)
	}
	e := &tunnelEndpoint{
		fd:     int32(fd),
		target: target,
		local:  local,
		remote: remote,
	}
	e.ops.InitHandler(e, nil /* stack */, tunnelSendLimits, tunnelRecvLimits)
	e.ops.SetSendBufferSize(tunnelBufSize, false)
	e.ops.SetReceiveBufferSize(tunnelBufSize, false)

	// One persistent entry covering everything, so fdnotifier always has a
	// non-zero mask and therefore always keeps the descriptor in its epoll set.
	e.entry = waiter.NewFunctionEntry(
		waiter.EventIn|waiter.EventOut|waiter.EventErr|waiter.EventHUp|waiter.EventRdHUp|waiter.ReadableEvents|waiter.WritableEvents,
		func(mask waiter.EventMask) {
			// A backed-up write can only be drained here.
			if mask&waiter.WritableEvents != 0 {
				e.mu.Lock()
				e.flushLocked()
				e.mu.Unlock()
			}
			e.target.Notify(mask)
		})
	e.q.EventRegister(&e.entry)
	if err := fdnotifier.AddFD(int32(fd), &e.q); err != nil {
		e.q.EventUnregister(&e.entry)
		unix.Close(fd)
		return nil, fmt.Errorf("registering the attached descriptor for notifications: %w", err)
	}
	fdnotifier.UpdateFD(int32(fd))
	return e, nil
}

// tunnelMapErr turns a host errno into the tcpip error the socket layer knows.
func tunnelMapErr(err error) tcpip.Error {
	switch err {
	case unix.EAGAIN:
		return &tcpip.ErrWouldBlock{}
	case unix.EPIPE:
		return &tcpip.ErrClosedForSend{}
	case unix.ECONNRESET:
		return &tcpip.ErrConnectionReset{}
	case unix.ENOTCONN:
		return &tcpip.ErrNotConnected{}
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}
}

// Close implements tcpip.Endpoint.Close.
func (e *tunnelEndpoint) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	fd := e.fd
	e.mu.Unlock()
	fdnotifier.RemoveFD(fd)
	e.q.EventUnregister(&e.entry)
	unix.Close(int(fd))
	log.Debugf("tunnel: host fd %d closed", fd)
}

// Abort implements tcpip.Endpoint.Abort.
func (e *tunnelEndpoint) Abort() { e.Close() }

// Read implements tcpip.Endpoint.Read.
func (e *tunnelEndpoint) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
	}
	if len(e.rbuf) == 0 {
		if e.shutRd {
			return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
		}
		buf := make([]byte, 64<<10)
		n, err := unix.Read(int(e.fd), buf)
		if err != nil {
			return tcpip.ReadResult{}, tunnelMapErr(err)
		}
		if n == 0 {
			// The socketpair's EOF, which the sandbox must see as a clean end
			// of stream.
			return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
		}
		e.rbuf = buf[:n]
	}
	n, werr := w.Write(e.rbuf)
	if n == 0 && werr != nil {
		return tcpip.ReadResult{}, &tcpip.ErrBadBuffer{}
	}
	res := tcpip.ReadResult{Count: n, Total: n, RemoteAddr: e.remote}
	if !opts.Peek {
		e.rbuf = e.rbuf[n:]
		if len(e.rbuf) == 0 {
			e.rbuf = nil
		}
	}
	return res, nil
}

// flushLocked drains whatever the descriptor would not take earlier.
// +checklocks:e.mu
func (e *tunnelEndpoint) flushLocked() tcpip.Error {
	for len(e.wbuf) > 0 {
		n, err := unix.Write(int(e.fd), e.wbuf)
		if n > 0 {
			e.wbuf = e.wbuf[n:]
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return tunnelMapErr(err)
		}
		if n == 0 {
			break
		}
	}
	if len(e.wbuf) == 0 {
		e.wbuf = nil
	}
	return nil
}

// tunnelMaxWrite caps what one Write takes out of the Payloader, so that a
// caller offering a great deal at once cannot make the backlog unbounded.
const tunnelMaxWrite = 1 << 20

// Write implements tcpip.Endpoint.Write.
func (e *tunnelEndpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.shutWr {
		return 0, &tcpip.ErrClosedForSend{}
	}
	// Drain the backlog first, and do not touch the Payloader until it is
	// gone: Write takes ownership of what it reads, so a partial host write
	// after a partial read would lose bytes.
	if err := e.flushLocked(); err != nil {
		return 0, err
	}
	want := p.Len()
	if want == 0 {
		return 0, nil
	}
	if want > tunnelMaxWrite {
		want = tunnelMaxWrite
	}
	buf := make([]byte, want)
	if _, err := io.ReadFull(p, buf); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}
	written := 0
	for written < want {
		n, err := unix.Write(int(e.fd), buf[written:])
		if n > 0 {
			written += n
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			// Keep the rest; the notification path will flush it.
			e.wbuf = append(e.wbuf, buf[written:]...)
			written = want
			break
		}
		if err != nil {
			if written > 0 {
				return int64(written), nil
			}
			return 0, tunnelMapErr(err)
		}
		if n == 0 {
			break
		}
	}
	return int64(written), nil
}

// Connect implements tcpip.Endpoint.Connect. The stream is up before the
// endpoint exists, so there is nothing left to do and nothing to wait for.
func (e *tunnelEndpoint) Connect(tcpip.FullAddress) tcpip.Error { return nil }

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *tunnelEndpoint) Disconnect() tcpip.Error { return &tcpip.ErrNotSupported{} }

// Shutdown implements tcpip.Endpoint.Shutdown.
func (e *tunnelEndpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return &tcpip.ErrNotConnected{}
	}
	var how int
	switch {
	case flags&tcpip.ShutdownRead != 0 && flags&tcpip.ShutdownWrite != 0:
		how, e.shutRd, e.shutWr = unix.SHUT_RDWR, true, true
	case flags&tcpip.ShutdownWrite != 0:
		how, e.shutWr = unix.SHUT_WR, true
	case flags&tcpip.ShutdownRead != 0:
		how, e.shutRd = unix.SHUT_RD, true
	default:
		e.mu.Unlock()
		return &tcpip.ErrInvalidEndpointState{}
	}
	e.flushLocked()
	fd := e.fd
	e.mu.Unlock()
	if err := unix.Shutdown(int(fd), how); err != nil {
		return tunnelMapErr(err)
	}
	return nil
}

// Listen implements tcpip.Endpoint.Listen.
func (e *tunnelEndpoint) Listen(int) tcpip.Error { return &tcpip.ErrNotSupported{} }

// Accept implements tcpip.Endpoint.Accept.
func (e *tunnelEndpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

// Bind implements tcpip.Endpoint.Bind.
func (e *tunnelEndpoint) Bind(tcpip.FullAddress) tcpip.Error { return &tcpip.ErrNotSupported{} }

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (e *tunnelEndpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.local, nil
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (e *tunnelEndpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.remote, nil
}

// Readiness implements tcpip.Endpoint.Readiness. The host is asked with a
// non-blocking poll, and anything already buffered in the sentry is added,
// because the descriptor no longer holds it.
func (e *tunnelEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := fdnotifier.NonBlockingPoll(e.fd, mask)
	e.mu.Lock()
	if len(e.rbuf) > 0 {
		ready |= waiter.ReadableEvents & mask
	}
	e.mu.Unlock()
	return ready
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *tunnelEndpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch v := opt.(type) {
	case *tcpip.KeepaliveIdleOption:
		e.keepaliveIdle = *v
		return nil
	case *tcpip.KeepaliveIntervalOption:
		e.keepaliveInterval = tcpip.KeepaliveIdleOption(*v)
		return nil
	default:
		log.Debugf("tunnel: SetSockOpt(%T) refused", opt)
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *tunnelEndpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch opt {
	case tcpip.KeepaliveCountOption:
		e.keepaliveCount = v
		return nil
	case tcpip.MaxSegOption, tcpip.IPv4TOSOption:
		return nil
	default:
		log.Debugf("tunnel: SetSockOptInt(%d, %d) refused", opt, v)
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *tunnelEndpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch v := opt.(type) {
	case *tcpip.KeepaliveIdleOption:
		*v = e.keepaliveIdle
		return nil
	case *tcpip.KeepaliveIntervalOption:
		*v = tcpip.KeepaliveIntervalOption(e.keepaliveInterval)
		return nil
	default:
		log.Debugf("tunnel: GetSockOpt(%T) refused", opt)
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *tunnelEndpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch opt {
	case tcpip.KeepaliveCountOption:
		return e.keepaliveCount, nil
	case tcpip.ReceiveQueueSizeOption:
		return len(e.rbuf), nil
	case tcpip.SendQueueSizeOption:
		return len(e.wbuf), nil
	case tcpip.MaxSegOption:
		return 1460, nil
	default:
		log.Debugf("tunnel: GetSockOptInt(%d) refused", opt)
		return 0, &tcpip.ErrUnknownProtocolOption{}
	}
}

// State implements tcpip.Endpoint.State: the stream is up for as long as the
// endpoint exists.
func (e *tunnelEndpoint) State() uint32 { return uint32(linux.TCP_ESTABLISHED) }

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *tunnelEndpoint) ModerateRecvBuf(int) {}

// The protocol numbers the endpoint claims in Info. They are spelled out
// rather than imported so that this file does not pull the ipv4 and tcp
// protocol packages in for two constants.
const (
	tunnelNetProtoV4    = 0x0800 // ipv4.ProtocolNumber
	tunnelTransProtoTCP = 6      // tcp.ProtocolNumber
)

// Info implements tcpip.Endpoint.Info.
func (e *tunnelEndpoint) Info() tcpip.EndpointInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &stack.TransportEndpointInfo{
		NetProto:   tunnelNetProtoV4,
		TransProto: tunnelTransProtoTCP,
		ID: stack.TransportEndpointID{
			LocalAddress:  e.local.Addr,
			LocalPort:     e.local.Port,
			RemoteAddress: e.remote.Addr,
			RemotePort:    e.remote.Port,
		},
	}
}

// Stats implements tcpip.Endpoint.Stats.
func (e *tunnelEndpoint) Stats() tcpip.EndpointStats { return &tcpip.TransportEndpointStats{} }

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *tunnelEndpoint) SetOwner(tcpip.PacketOwner) {}

// LastError implements tcpip.Endpoint.LastError: always nil, which is what
// makes getsockopt(SOL_SOCKET, SO_ERROR) answer 0.
func (e *tunnelEndpoint) LastError() tcpip.Error { return nil }

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (e *tunnelEndpoint) SocketOptions() *tcpip.SocketOptions { return &e.ops }

// Preflight implements tcpip.Endpoint.Preflight.
func (e *tunnelEndpoint) Preflight(tcpip.WriteOptions) tcpip.Error { return nil }
