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

package netstack

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ===== the table =====

func TestParseTunnelTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string // a substring of the error, or "" for a table that parses
	}{
		{
			name: "the interface note's example",
			text: `{"default_exit":"b","names":{"api.anthropic.com":{"port":443},"www.rfc-editor.org":{"port":443,"peer":"b"}}}`,
		},
		{
			name: "no default exit is fine when every name has a peer",
			text: `{"names":{"a.example":{"port":443,"peer":"b"}}}`,
		},
		{
			name: "a name with no peer needs a default exit",
			text: `{"names":{"a.example":{"port":443}}}`,
			want: "no default_exit",
		},
		{
			name: "no names at all",
			text: `{"default_exit":"b","names":{}}`,
			want: "no names",
		},
		{
			name: "a port that is not a port",
			text: `{"default_exit":"b","names":{"a.example":{"port":0}}}`,
			want: "which is not a port",
		},
		{
			name: "a port above the range",
			text: `{"default_exit":"b","names":{"a.example":{"port":70000}}}`,
			want: "which is not a port",
		},
		{
			name: "a wildcard is not a name",
			text: `{"default_exit":"b","names":{"*.example":{"port":443}}}`,
			want: "looks like a pattern",
		},
		{
			name: "two spellings of one name",
			text: `{"default_exit":"b","names":{"A.example":{"port":443},"a.example":{"port":8443}}}`,
			want: "appears twice",
		},
		{
			name: "a field nobody wrote",
			text: `{"default_exit":"b","allow_everything":true,"names":{"a.example":{"port":443}}}`,
			want: "unknown field",
		},
		{
			name: "not JSON at all",
			text: `nope`,
			want: "tunnel table",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTunnelTable([]byte(tc.text))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("ParseTunnelTable(%s) = %v, wanted a table", tc.text, err)
			case tc.want == "":
				if len(got.Names) == 0 {
					t.Fatalf("ParseTunnelTable(%s) produced no names", tc.text)
				}
			case err == nil:
				t.Fatalf("ParseTunnelTable(%s) was accepted, wanted an error mentioning %q", tc.text, tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Fatalf("ParseTunnelTable(%s) = %v, wanted an error mentioning %q", tc.text, err, tc.want)
			}
		})
	}
}

func TestTunnelTableFoldsCaseAndTrailingDot(t *testing.T) {
	table, err := ParseTunnelTable([]byte(`{"default_exit":"b","names":{"API.Anthropic.COM.":{"port":443}}}`))
	if err != nil {
		t.Fatalf("ParseTunnelTable: %v", err)
	}
	if _, ok := table.Names["api.anthropic.com"]; !ok {
		t.Fatalf("the table's names are %v, wanted the folded spelling", table.Names)
	}
}

func TestTunnelTablePeerFor(t *testing.T) {
	table, err := ParseTunnelTable([]byte(`{"default_exit":"b","names":{"a.example":{"port":443},"c.example":{"port":443,"peer":"c"}}}`))
	if err != nil {
		t.Fatalf("ParseTunnelTable: %v", err)
	}
	if got := table.PeerFor(table.Names["a.example"]); got != "b" {
		t.Errorf("PeerFor(a.example) = %q, wanted the default exit %q", got, "b")
	}
	if got := table.PeerFor(table.Names["c.example"]); got != "c" {
		t.Errorf("PeerFor(c.example) = %q, wanted %q", got, "c")
	}
}

// ===== addresses =====

func TestTunnelSyntheticAddrCountsFromTheBase(t *testing.T) {
	for i, want := range map[int][4]byte{
		0:   {100, 64, 1, 0},
		1:   {100, 64, 1, 1},
		255: {100, 64, 1, 255},
		256: {100, 64, 2, 0},
		511: {100, 64, 2, 255},
	} {
		if got := tunnelSyntheticAddr(i); got.As4() != want {
			t.Errorf("tunnelSyntheticAddr(%d) = %s, wanted %v", i, got.String(), want)
		}
	}
	// Nothing the resolver hands out may equal the local address every
	// attached socket answers getsockname with: Go's selfConnect heuristic
	// closes a connection whose two ends agree (spike E1a, run 07).
	for i := 0; i < 1024; i++ {
		if tunnelSyntheticAddr(i) == tunnelLocalAddr {
			t.Fatalf("tunnelSyntheticAddr(%d) is the local address %s", i, tunnelLocalAddr.String())
		}
	}
}

func TestTunnelIsLoopback(t *testing.T) {
	v6 := func(b ...byte) tcpip.Address {
		var a [16]byte
		copy(a[16-len(b):], b)
		return tcpip.AddrFrom16(a)
	}
	for _, tc := range []struct {
		addr tcpip.Address
		want bool
	}{
		{tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), true},
		{tcpip.AddrFrom4([4]byte{127, 0, 0, 53}), true},
		{tcpip.AddrFrom4([4]byte{127, 255, 255, 255}), true},
		{tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), true},
		{tcpip.AddrFrom4([4]byte{100, 64, 1, 0}), false},
		{tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), false},
		{tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), false},
		{v6(1), true},
		{v6(0), true},
		{v6(0xff, 0xff, 127, 0, 0, 1), true},
		{v6(0xff, 0xff, 8, 8, 8, 8), false},
		{v6(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), false},
	} {
		if got := tunnelIsLoopback(tc.addr); got != tc.want {
			t.Errorf("tunnelIsLoopback(%s) = %t, wanted %t", tc.addr.String(), got, tc.want)
		}
	}
}

// testAdapter builds an adapter with the bindings InstallTunnel would produce,
// without a stack, a responder or a host side.
func testAdapter(t *testing.T, text string) *adapter {
	t.Helper()
	table, err := ParseTunnelTable([]byte(text))
	if err != nil {
		t.Fatalf("ParseTunnelTable: %v", err)
	}
	a := &adapter{
		table:     table,
		byName:    map[string]*tunnelBinding{},
		byAddr:    map[tcpip.Address]*tunnelBinding{},
		localPort: 40000,
	}
	names := make([]string, 0, len(table.Names))
	for name := range table.Names {
		names = append(names, name)
	}
	// InstallTunnel sorts; so does this, by the same rule.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for i, name := range names {
		e := table.Names[name]
		b := &tunnelBinding{name: name, addr: tunnelSyntheticAddr(i), port: uint16(e.Port), peer: table.PeerFor(e)}
		a.byName[name] = b
		a.byAddr[b.addr] = b
	}
	return a
}

func TestTunnelLookupIsCaseInsensitiveAndStable(t *testing.T) {
	a := testAdapter(t, `{"default_exit":"b","names":{"www.rfc-editor.org":{"port":443},"api.anthropic.com":{"port":443}}}`)
	// Sorted, so api.anthropic.com is the first name and www.rfc-editor.org
	// the second, on this boot and every other one.
	api, ok := a.lookupName("API.Anthropic.com.")
	if !ok {
		t.Fatalf("lookupName did not find api.anthropic.com")
	}
	if got, want := api.addr.As4(), [4]byte{100, 64, 1, 0}; got != want {
		t.Errorf("api.anthropic.com is %v, wanted %v", got, want)
	}
	rfc, ok := a.lookupName("www.rfc-editor.org")
	if !ok {
		t.Fatalf("lookupName did not find www.rfc-editor.org")
	}
	if got, want := rfc.addr.As4(), [4]byte{100, 64, 1, 1}; got != want {
		t.Errorf("www.rfc-editor.org is %v, wanted %v", got, want)
	}
	back, ok := a.lookupAddr(rfc.addr)
	if !ok || back.name != "www.rfc-editor.org" {
		t.Errorf("lookupAddr(%s) = %v, %t; wanted www.rfc-editor.org", rfc.addr.String(), back, ok)
	}
	if _, ok := a.lookupName("evil.example"); ok {
		t.Errorf("lookupName found a name the table does not carry")
	}
}

func TestTunnelLocalPortDiffersPerConnection(t *testing.T) {
	a := testAdapter(t, `{"default_exit":"b","names":{"a.example":{"port":443}}}`)
	seen := map[uint16]bool{}
	for i := 0; i < 100; i++ {
		local := a.nextLocal()
		if local.Addr != tunnelLocalAddr {
			t.Fatalf("nextLocal gave address %s, wanted %s", local.Addr.String(), tunnelLocalAddr.String())
		}
		if seen[local.Port] {
			t.Fatalf("nextLocal repeated port %d", local.Port)
		}
		seen[local.Port] = true
	}
}

// ===== the endpoint =====

// testEndpoint builds an endpoint over one end of a socketpair and returns it
// with the other end.
func testEndpoint(t *testing.T) (*tunnelEndpoint, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	var q waiter.Queue
	local := tcpip.FullAddress{Addr: tunnelLocalAddr, Port: 40001}
	remote := tcpip.FullAddress{Addr: tunnelSyntheticAddr(0), Port: 443}
	ep, err := newTunnelEndpoint(fds[0], local, remote, &q)
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatalf("newTunnelEndpoint: %v", err)
	}
	t.Cleanup(func() {
		ep.Close()
		unix.Close(fds[1])
	})
	return ep, fds[1]
}

func TestTunnelEndpointAnswersTheFourCallsThatMatter(t *testing.T) {
	ep, _ := testEndpoint(t)

	// 1. SO_ERROR is read from the options handler's LastError, and it must be
	// nil: refusing it fails Go's dial and makes libuv read an uninitialised
	// int (spike E1a, runs 10, 11, 16, 17).
	if err := ep.LastError(); err != nil {
		t.Errorf("LastError() = %v, wanted nil so that SO_ERROR answers 0", err)
	}
	if ep.SocketOptions() == nil {
		t.Errorf("SocketOptions() is nil")
	}

	// 2 and 3. The two names, and they must differ.
	local, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("GetLocalAddress: %v", err)
	}
	remote, err := ep.GetRemoteAddress()
	if err != nil {
		t.Fatalf("GetRemoteAddress: %v", err)
	}
	if local.Addr == remote.Addr && local.Port == remote.Port {
		t.Errorf("getsockname and getpeername agree (%s:%d), which trips Go's selfConnect heuristic", local.Addr.String(), local.Port)
	}
	if local.Addr.Len() != 4 || remote.Addr.Len() != 4 {
		t.Errorf("the two names must be AF_INET, got %d and %d byte addresses", local.Addr.Len(), remote.Addr.Len())
	}

	// 4. Connect is synchronously successful; the stream is already up.
	if err := ep.Connect(remote); err != nil {
		t.Errorf("Connect() = %v, wanted synchronous success", err)
	}
	if got, want := ep.State(), uint32(linux.TCP_ESTABLISHED); got != want {
		t.Errorf("State() = %d, wanted %d", got, want)
	}
}

func TestTunnelEndpointOptionAnswers(t *testing.T) {
	ep, _ := testEndpoint(t)

	// The four setsockopt calls Go makes on every connection. TCP_NODELAY and
	// SO_KEEPALIVE are SocketOptions fields the generic layer handles; the
	// keepalive triple reaches the endpoint and is remembered, so the sandbox
	// sees them honoured.
	idle := tcpip.KeepaliveIdleOption(15 << 9)
	if err := ep.SetSockOpt(&idle); err != nil {
		t.Errorf("SetSockOpt(TCP_KEEPIDLE) = %v", err)
	}
	interval := tcpip.KeepaliveIntervalOption(7 << 9)
	if err := ep.SetSockOpt(&interval); err != nil {
		t.Errorf("SetSockOpt(TCP_KEEPINTVL) = %v", err)
	}
	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, 9); err != nil {
		t.Errorf("SetSockOptInt(TCP_KEEPCNT) = %v", err)
	}
	var gotIdle tcpip.KeepaliveIdleOption
	if err := ep.GetSockOpt(&gotIdle); err != nil || gotIdle != idle {
		t.Errorf("GetSockOpt(TCP_KEEPIDLE) = %v, %v; wanted %v", gotIdle, err, idle)
	}
	var gotInterval tcpip.KeepaliveIntervalOption
	if err := ep.GetSockOpt(&gotInterval); err != nil || gotInterval != interval {
		t.Errorf("GetSockOpt(TCP_KEEPINTVL) = %v, %v; wanted %v", gotInterval, err, interval)
	}
	if n, err := ep.GetSockOptInt(tcpip.KeepaliveCountOption); err != nil || n != 9 {
		t.Errorf("GetSockOptInt(TCP_KEEPCNT) = %d, %v; wanted 9", n, err)
	}

	// Anything else is refused, and refusing it is safe: neither runtime asks
	// (spike E1b, where the count of refusals in every run was zero).
	var cork tcpip.TCPUserTimeoutOption
	if err := ep.GetSockOpt(&cork); err == nil {
		t.Errorf("GetSockOpt(TCP_USER_TIMEOUT) was accepted, wanted a refusal")
	}
	if err := ep.SetSockOptInt(tcpip.IPv4TTLOption, 4); err == nil {
		t.Errorf("SetSockOptInt(IPv4 TTL) was accepted, wanted a refusal")
	}

	// The queue sizes are answered from the endpoint's own buffers.
	if n, err := ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err != nil || n != 0 {
		t.Errorf("GetSockOptInt(SIOCINQ) = %d, %v; wanted 0", n, err)
	}
	if _, err := ep.GetSockOptInt(tcpip.SendQueueSizeOption); err != nil {
		t.Errorf("GetSockOptInt(SIOCOUTQ) = %v", err)
	}
}

func TestTunnelEndpointCarriesBytesAndTheHalfClose(t *testing.T) {
	ep, peer := testEndpoint(t)

	// Write reaches the peer.
	if n, err := ep.Write(&payload{b: []byte("hello\n")}, tcpip.WriteOptions{}); err != nil || n != 6 {
		t.Fatalf("Write = %d, %v; wanted 6, nil", n, err)
	}
	buf := make([]byte, 16)
	n, rerr := unix.Read(peer, buf)
	if rerr != nil || string(buf[:n]) != "hello\n" {
		t.Fatalf("the peer read %q, %v; wanted %q", buf[:n], rerr, "hello\n")
	}

	// A short user buffer must not lose the rest of a host read: that is what
	// the endpoint's leftover buffer is for.
	if _, err := unix.Write(peer, []byte("0123456789")); err != nil {
		t.Fatalf("writing to the peer: %v", err)
	}
	var first, second shortWriter
	first.limit = 4
	if _, err := ep.Read(&first, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	second.limit = 100
	if _, err := ep.Read(&second, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(first.got) + string(second.got); got != "0123456789" {
		t.Errorf("two reads gave %q, wanted %q: the leftover buffer dropped bytes", got, "0123456789")
	}

	// SHUT_WR must reach shutdown(2), or the peer never sees the end.
	if err := ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Shutdown(SHUT_WR): %v", err)
	}
	n, rerr = unix.Read(peer, buf)
	if rerr != nil || n != 0 {
		t.Errorf("after SHUT_WR the peer read %d bytes, %v; wanted a clean end of file", n, rerr)
	}
}

// payload is a tcpip.Payloader over a byte slice.
type payload struct {
	b []byte
}

func (p *payload) Len() int { return len(p.b) }

func (p *payload) Read(b []byte) (int, error) {
	n := copy(b, p.b)
	p.b = p.b[n:]
	return n, nil
}

// shortWriter is the io.Writer Endpoint.Read is handed: one that takes only so
// much, which is the case the leftover buffer exists for.
type shortWriter struct {
	limit int
	got   []byte
}

func (w *shortWriter) Write(b []byte) (int, error) {
	n := len(b)
	if n > w.limit {
		n = w.limit
	}
	w.got = append(w.got, b[:n]...)
	return n, nil
}
