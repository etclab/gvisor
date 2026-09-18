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

// The tunnel adapter: the sentry's half of ticket 25.
//
// A sandbox booted with --network=none has one NIC, lo, and nothing it sends
// to any other address can leave. The adapter gives it exactly one way out and
// no other: a table of host names, one permitted TCP port each, resolved by a
// responder inside the sentry to addresses that exist nowhere but here, and a
// connect to one of those addresses answered with a descriptor a helper on the
// host handed in. Every other destination is refused where it is named, with
// ENETUNREACH and a sentry/egress_refused event, before a byte is written.
//
// The three pieces live in three files:
//   - this one: the table, the name/address bindings, the connect intercept
//     and the refusal event;
//   - tunnel_dns.go: the responder bound at 127.0.0.53:53 on the loopback
//     stack, which is what turns a name into one of those addresses;
//   - tunnel_endpoint.go: the tcpip.Endpoint over the descriptor.
//
// Nothing here knows about urpc or runsc: the host side arrives as a
// TunnelAttacher, a one-method interface runsc/boot implements.

package netstack

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// TunnelAttacher is the host side of the handoff as this package sees it. It
// is an interface with one method so that netstack gains no dependency on
// urpc, unet or anything else runsc/boot is made of; runsc/boot registers the
// implementation at boot with InstallTunnel.
type TunnelAttacher interface {
	// Attach asks for a stream to hostPort through the named tunneld peer and
	// returns a host descriptor that carries it. The caller owns the
	// descriptor. An error wrapping ErrTunnelRefused means the far exit said
	// no; any other error means the stream did not happen for a reason on this
	// side of it.
	Attach(peer, hostPort string) (int, error)
}

// ErrTunnelRefused marks the one error the far exit produces itself: the
// destination was refused by whoever dials it, which the sandbox is told as
// ECONNREFUSED and which is not this sentry's refusal to record.
var ErrTunnelRefused = errors.New("the far exit refused the destination")

// TunnelEntry is one row of the table: the single TCP port a name may be
// reached on, and the tunneld peer whose exit dials it.
type TunnelEntry struct {
	Port int    `json:"port"`
	Peer string `json:"peer,omitempty"`
}

// TunnelTable is the document --tunnel-table names. Keys of Names are exact
// host names, matched case-insensitively; there are no wildcards and no
// addresses.
type TunnelTable struct {
	DefaultExit string                 `json:"default_exit"`
	Names       map[string]TunnelEntry `json:"names"`
}

// ParseTunnelTable reads a table and checks it, so that a table that cannot be
// enforced is rejected at boot rather than halfway through a run.
func ParseTunnelTable(data []byte) (*TunnelTable, error) {
	var t TunnelTable
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("tunnel table: %w", err)
	}
	if len(t.Names) == 0 {
		return nil, fmt.Errorf("tunnel table: no names, so nothing could ever leave")
	}
	names := make(map[string]TunnelEntry, len(t.Names))
	for name, e := range t.Names {
		lower := strings.ToLower(strings.TrimSuffix(name, "."))
		if lower == "" {
			return nil, fmt.Errorf("tunnel table: an empty name")
		}
		if strings.ContainsAny(lower, "*?") {
			return nil, fmt.Errorf("tunnel table: %q looks like a pattern, and names are exact", name)
		}
		if e.Port <= 0 || e.Port > 65535 {
			return nil, fmt.Errorf("tunnel table: %q has port %d, which is not a port", name, e.Port)
		}
		if e.Peer == "" && t.DefaultExit == "" {
			return nil, fmt.Errorf("tunnel table: %q names no peer and there is no default_exit", name)
		}
		if _, dup := names[lower]; dup {
			return nil, fmt.Errorf("tunnel table: %q appears twice once case is folded", name)
		}
		names[lower] = e
	}
	t.Names = names
	return &t, nil
}

// PeerFor returns the tunneld peer that dials a name, which is the entry's own
// when it has one and the table's default exit otherwise.
func (t *TunnelTable) PeerFor(e TunnelEntry) string {
	if e.Peer != "" {
		return e.Peer
	}
	return t.DefaultExit
}

// A tunnelBinding is one name once the adapter has given it an address.
type tunnelBinding struct {
	name string
	addr tcpip.Address
	port uint16
	peer string
}

// tunnelSyntheticBase is where the addresses handed out for names start.
// 100.64.0.0/10 is RFC 6598 shared address space: it is not a public address,
// it is not routed anywhere, and nothing inside a --network=none sandbox can
// reach it any other way, so an address in it reaching connect() is always the
// adapter's and never a pre-existing success (spike E2).
var tunnelSyntheticBase = [4]byte{100, 64, 1, 0}

// tunnelLocalAddr is the address getsockname answers for every attached
// socket. It is below the first name's address and so differs from every
// remote, which is what keeps Go's selfConnect heuristic from closing the
// connection and dialling twice more (spike E1a, run 07).
var tunnelLocalAddr = tcpip.AddrFrom4([4]byte{100, 64, 0, 1})

// maxTunnelNames is the number of names the address range set aside here
// holds: 100.64.1.0 through 100.64.255.255.
const maxTunnelNames = 255 * 256

// adapter is the installed tunnel, or nil when runsc passed no --tunnel-*.
type adapter struct {
	table    *TunnelTable
	attacher TunnelAttacher

	byName map[string]*tunnelBinding
	byAddr map[tcpip.Address]*tunnelBinding

	// mu guards localPort only. The maps are written once, before the adapter
	// is published, and read-only afterwards.
	mu sync.Mutex
	// +checklocks:mu
	localPort uint16
}

var (
	tunnelMu sync.Mutex
	// tunnel is read on every connect(), so it is published once under
	// tunnelMu and read without it; a torn read is impossible for a pointer.
	tunnel *adapter
)

// currentTunnel returns the installed adapter, or nil.
func currentTunnel() *adapter {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	return tunnel
}

// InstallTunnel builds the adapter over st and starts the DNS responder. It
// refuses a stack that is anything but the loopback-only one: the adapter is
// the sandbox's only way out, which is a claim about the whole stack and not
// about one socket, and it is not true of a stack that has a route of its own.
func InstallTunnel(st *Stack, table *TunnelTable, attacher TunnelAttacher) error {
	if st == nil || st.Stack == nil {
		return fmt.Errorf("the tunnel adapter needs a netstack stack")
	}
	if attacher == nil {
		return fmt.Errorf("the tunnel adapter needs a host side to attach through")
	}
	if err := tunnelCheckCeiling(st); err != nil {
		return err
	}
	if len(table.Names) > maxTunnelNames {
		return fmt.Errorf("the tunnel table has %d names and the address range holds %d", len(table.Names), maxTunnelNames)
	}

	names := make([]string, 0, len(table.Names))
	for name := range table.Names {
		names = append(names, name)
	}
	// Sorted, so a table produces the same addresses on every boot and the
	// evidence of one run can be read against another.
	sort.Strings(names)

	a := &adapter{
		table:     table,
		attacher:  attacher,
		byName:    make(map[string]*tunnelBinding, len(names)),
		byAddr:    make(map[tcpip.Address]*tunnelBinding, len(names)),
		localPort: 40000,
	}
	for i, name := range names {
		e := table.Names[name]
		b := &tunnelBinding{
			name: name,
			addr: tunnelSyntheticAddr(i),
			port: uint16(e.Port),
			peer: table.PeerFor(e),
		}
		a.byName[name] = b
		a.byAddr[b.addr] = b
		log.Infof("tunnel: %s:%d is %s, dialled by peer %q", b.name, b.port, b.addr.String(), b.peer)
	}

	tunnelMu.Lock()
	if tunnel != nil {
		tunnelMu.Unlock()
		return fmt.Errorf("the tunnel adapter is already installed")
	}
	tunnel = a
	tunnelMu.Unlock()

	if err := startTunnelResolver(st, a); err != nil {
		tunnelMu.Lock()
		tunnel = nil
		tunnelMu.Unlock()
		return err
	}
	log.Infof("tunnel: installed with %d names, resolver on %s:%d", len(names), tunnelResolverAddr.String(), tunnelResolverPort)
	return nil
}

// tunnelSyntheticAddr is the address of the i'th name, counting from
// 100.64.1.0.
func tunnelSyntheticAddr(i int) tcpip.Address {
	b := tunnelSyntheticBase
	b[2] += byte(i / 256)
	b[3] += byte(i % 256)
	return tcpip.AddrFrom4(b)
}

// tunnelCheckCeiling is the boot-time refusal to install over a stack that can
// route on its own.
func tunnelCheckCeiling(st *Stack) error {
	nics := st.Stack.NICInfo()
	if len(nics) == 0 {
		return fmt.Errorf("the tunnel adapter needs the loopback stack and this one has no NIC")
	}
	for id, info := range nics {
		if !info.Flags.Loopback {
			return fmt.Errorf("the tunnel adapter requires --network=none: NIC %d (%q) is not a loopback interface", id, info.Name)
		}
	}
	return nil
}

// lookupName returns the binding for a name, matched case-insensitively.
func (a *adapter) lookupName(name string) (*tunnelBinding, bool) {
	b, ok := a.byName[strings.ToLower(strings.TrimSuffix(name, "."))]
	return b, ok
}

// lookupAddr returns the binding an address belongs to.
func (a *adapter) lookupAddr(addr tcpip.Address) (*tunnelBinding, bool) {
	b, ok := a.byAddr[addr]
	return b, ok
}

// nextLocal hands out the local address a newly attached socket answers
// getsockname with. One port per connection, because two sockets that agree on
// both ends look to Go like a socket connected to itself.
func (a *adapter) nextLocal() tcpip.FullAddress {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.localPort++
	if a.localPort == 0 {
		a.localPort = 40000
	}
	return tcpip.FullAddress{Addr: tunnelLocalAddr, Port: a.localPort}
}

// ===== classifying a destination =====

// tunnelIsLoopback reports whether addr is the sandbox's own loopback, which
// is not egress and which the adapter leaves exactly as --network=none has it.
// The unspecified address counts: connect(0.0.0.0) reaches localhost.
func tunnelIsLoopback(addr tcpip.Address) bool {
	switch addr.Len() {
	case 0:
		return true
	case 4:
		b := addr.As4()
		return b[0] == 127 || b == [4]byte{0, 0, 0, 0}
	case 16:
		b := addr.As16()
		if b == ([16]byte{}) {
			return true
		}
		if b == ([16]byte{15: 1}) {
			return true
		}
		// A v4-mapped v6 address carries a v4 address in its last four bytes.
		if b[10] == 0xff && b[11] == 0xff {
			var v4 [4]byte
			copy(v4[:], b[12:])
			var zeros [10]byte
			if [10]byte(b[0:10]) == zeros {
				return v4[0] == 127 || v4 == [4]byte{0, 0, 0, 0}
			}
		}
	}
	return false
}

// ===== the connect intercept =====

// tunnelConnect is sock.Connect's one hook. It reports whether it answered the
// call, and with what. Everything it does not answer is left to netstack, which
// under --network=none means loopback and nothing else.
func tunnelConnect(t *kernel.Task, s *sock, addr tcpip.FullAddress) (bool, *syserr.Error) {
	a := currentTunnel()
	if a == nil {
		return false, nil
	}
	if _, attached := s.Endpoint.(*tunnelEndpoint); attached {
		// A socket that already holds a stream is connected, and connect(2) on
		// a connected TCP socket is EISCONN. Answering anything else would let
		// a second call ask for a second stream and drop the first.
		return true, syserr.ErrAlreadyConnected
	}
	if tunnelIsLoopback(addr.Addr) {
		return false, nil
	}
	proto := "tcp"
	if s.skType != linux.SOCK_STREAM {
		proto = "udp"
	}
	b, bound := a.lookupAddr(addr.Addr)
	switch {
	case !bound:
		// Nothing the sentry allocated, so nothing a name resolves to.
		return true, a.refuse(t, proto, addr, "", tunnelReasonNotInTable)
	case s.family != linux.AF_INET || s.skType != linux.SOCK_STREAM:
		// A name's address is a TCP destination and only that: a datagram sent
		// to one has no stream to be handed, and there is nothing to attach.
		return true, a.refuse(t, proto, addr, b.name, tunnelReasonNotStream)
	case addr.Port != b.port:
		return true, a.refuse(t, proto, addr, b.name, tunnelReasonWrongPort)
	}

	hostPort := fmt.Sprintf("%s:%d", b.name, b.port)
	start := time.Now()
	fd, err := a.attacher.Attach(b.peer, hostPort)
	if err != nil {
		if errors.Is(err, ErrTunnelRefused) {
			// The far exit's own list said no. That refusal is ticket 23's and
			// is recorded there; this sentry refused nothing, so it records
			// nothing and answers the way a closed port answers.
			log.Infof("tunnel attach: %s -> peer %q: refused by the far exit in %v (%v)", hostPort, b.peer, time.Since(start), err)
			return true, syserr.ErrConnectionRefused
		}
		log.Infof("tunnel attach: %s -> peer %q: unavailable in %v (%v)", hostPort, b.peer, time.Since(start), err)
		return true, a.refuse(t, proto, addr, b.name, tunnelReasonUnavailable)
	}

	local := a.nextLocal()
	ep, epErr := newTunnelEndpoint(fd, local, addr, s.Queue)
	if epErr != nil {
		log.Infof("tunnel attach: %s -> peer %q: the endpoint would not start after %v (%v)", hostPort, b.peer, time.Since(start), epErr)
		return true, a.refuse(t, proto, addr, b.name, tunnelReasonUnavailable)
	}
	old := s.Endpoint
	s.Endpoint = ep
	old.Close()
	log.Infof("tunnel attach: %s -> peer %q: ok in %v, host fd %d, local %s:%d", hostPort, b.peer, time.Since(start), fd, local.Addr.String(), local.Port)
	// Synchronously successful: the stream is already up by the time connect
	// returns, so there is nothing for the caller to wait for (spike E1b, §4).
	return true, nil
}

// tunnelSendTo is sock.SendMsg's hook, for the sendto(2) style of client that
// names its destination on every datagram. A connected datagram socket never
// reaches here — its address was given at connect(2), which is the hook above
// (spike E2, finding 2).
func tunnelSendTo(t *kernel.Task, s *sock, addr tcpip.FullAddress) *syserr.Error {
	a := currentTunnel()
	if a == nil || tunnelIsLoopback(addr.Addr) {
		return nil
	}
	// A name's address refused here is refused for being a datagram
	// destination; anything else is refused for not being in the table at all,
	// which is the same reason the connect path gives it.
	if b, ok := a.lookupAddr(addr.Addr); ok {
		return a.refuse(t, "udp", addr, b.name, tunnelReasonNotStream)
	}
	return a.refuse(t, "udp", addr, "", tunnelReasonNotInTable)
}

// ===== the refusal event =====

const (
	tunnelReasonNotInTable  = "not-in-table"
	tunnelReasonWrongPort   = "wrong-port"
	tunnelReasonNotStream   = "not-a-tcp-stream"
	tunnelReasonUnavailable = "unavailable"
	tunnelReasonUnknownName = "unknown-name"
	tunnelReasonUnknownType = "unknown-type"
)

// refuse records one refusal and returns the errno the sandbox sees. It is
// always ENETUNREACH: that is what a --network=none sandbox already answers for
// an address it has no route to, so a workload cannot tell the adapter's
// refusal from the absence of a network, which is the point.
func (a *adapter) refuse(t *kernel.Task, proto string, addr tcpip.FullAddress, name, reason string) *syserr.Error {
	emitEgressRefused(t, proto, addr.Addr.String(), uint32(addr.Port), name, reason)
	return syserr.ErrNetworkUnreachable
}

// emitEgressRefused sends one sentry/egress_refused point. t may be nil: the
// resolver answers on its own goroutine and has no task to speak of, and the
// event is still worth having with only the time on it.
func emitEgressRefused(t *kernel.Task, proto, address string, port uint32, name, reason string) {
	log.Infof("tunnel: refused %s %s:%d name=%q reason=%s", proto, address, port, name, reason)
	if !seccheck.Global.Enabled(seccheck.PointEgressRefused) {
		return
	}
	info := &pb.EgressRefused{
		Protocol: proto,
		Address:  address,
		Port:     port,
		Name:     name,
		Reason:   reason,
	}
	fields := seccheck.Global.GetFieldSet(seccheck.PointEgressRefused)
	ctx := context.Background()
	if t != nil {
		ctx = t
		if !fields.Context.Empty() {
			info.ContextData = &pb.ContextData{}
			kernel.LoadSeccheckData(t, fields.Context, info.ContextData)
		}
	} else if fields.Context.Contains(seccheck.FieldCtxtTime) {
		info.ContextData = &pb.ContextData{TimeNs: tunnelNowNanos()}
	}
	seccheck.Global.SentToSinks(func(c seccheck.Sink) error {
		return c.EgressRefused(ctx, fields, info)
	})
}

// tunnelNowNanos is the wall clock an event uses when there is no task to take
// one from. The resolver answers on its own goroutine, which has none.
func tunnelNowNanos() int64 { return time.Now().UnixNano() }
