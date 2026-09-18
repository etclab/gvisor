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

// The resolver half of the tunnel adapter.
//
// The workload's /etc/resolv.conf says `nameserver 127.0.0.53` and this binds
// a UDP endpoint there on the sandbox's own loopback stack. Spike E2 measured
// that every client style reaches it — unconnected sendto, connect+write and
// Go's net.DialUDP — with no route, no NIC and no intercept, which is a
// strictly smaller change than hooking two syscalls for DNS.
//
// It answers three ways and no others. A name in the table, asked for as A,
// gets the address the adapter allocated for it. The same name asked for as
// AAAA gets NOERROR and no records, because an agent runtime asks AAAA first,
// every time, and a hang there costs one connection per lookup (spike E4,
// surprise 3). Anything else is NXDOMAIN and a refusal event: a name the table
// does not carry never gets an address, so there is no address for a connect
// to then be refused at.

package netstack

import (
	"bytes"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	// tunnelResolverAddr is systemd-resolved's stub address, which is what a
	// stock /etc/resolv.conf on the workstation and in the workload image
	// already names.
	tunnelResolverAddr = tcpip.AddrFrom4([4]byte{127, 0, 0, 53})
	// tunnelResolverPort is 53.
	tunnelResolverPort uint16 = 53
)

// DNS record types and classes, as many as this responder has opinions about.
const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsClassIN  = 1
)

// DNS response codes.
const (
	dnsRcodeNoError  = 0
	dnsRcodeFormErr  = 1
	dnsRcodeNXDomain = 3
)

// dnsHeaderLen is the fixed part of a DNS message.
const dnsHeaderLen = 12

// dnsTTL is the lifetime given to the one record this responder produces. The
// bindings last as long as the sandbox does, so the only thing a short TTL
// costs is a few more queries, and what it buys is a resolver that notices a
// restarted sandbox.
const dnsTTL = 60

// startTunnelResolver binds the responder and serves it until the stack goes.
func startTunnelResolver(st *Stack, a *adapter) error {
	var wq waiter.Queue
	ep, terr := st.Stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return &tcpipError{op: "creating the resolver endpoint", err: terr}
	}
	bind := tcpip.FullAddress{Addr: tunnelResolverAddr, Port: tunnelResolverPort}
	if terr := ep.Bind(bind); terr != nil {
		ep.Close()
		return &tcpipError{op: "binding the resolver to 127.0.0.53:53", err: terr}
	}
	go serveTunnelResolver(ep, &wq, a)
	return nil
}

// tcpipError carries a tcpip.Error out as an ordinary error, so that boot can
// report why the adapter did not install.
type tcpipError struct {
	op  string
	err tcpip.Error
}

func (e *tcpipError) Error() string { return e.op + ": " + e.err.String() }

// serveTunnelResolver is the responder's loop.
func serveTunnelResolver(ep tcpip.Endpoint, wq *waiter.Queue, a *adapter) {
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&e)
	defer wq.EventUnregister(&e)
	defer ep.Close()
	for {
		var buf bytes.Buffer
		res, terr := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
		if terr != nil {
			if _, ok := terr.(*tcpip.ErrWouldBlock); ok {
				<-ch
				continue
			}
			log.Warningf("tunnel resolver: read failed, the responder is going away: %v", terr)
			return
		}
		ans := a.answerDNS(buf.Bytes())
		if len(ans) == 0 {
			continue
		}
		to := res.RemoteAddr
		if _, terr := ep.Write(bytes.NewReader(ans), tcpip.WriteOptions{To: &to}); terr != nil {
			log.Warningf("tunnel resolver: answering %s:%d failed: %v", to.Addr.String(), to.Port, terr)
		}
	}
}

// answerDNS turns one query into the bytes to send back, or nil to say
// nothing at all.
func (a *adapter) answerDNS(q []byte) []byte {
	if len(q) < dnsHeaderLen {
		return nil
	}
	// A response is not a query; ignore anything with QR set, and anything
	// that is not a standard query.
	if q[2]&0x80 != 0 {
		return nil
	}
	opcode := (q[2] >> 3) & 0x0f
	qdcount := int(q[4])<<8 | int(q[5])
	if opcode != 0 || qdcount != 1 {
		return dnsReply(q, dnsRcodeFormErr, dnsHeaderLen, nil)
	}
	name, qend, ok := dnsQuestionName(q)
	if !ok || qend+4 > len(q) {
		return dnsReply(q, dnsRcodeFormErr, dnsHeaderLen, nil)
	}
	qtype := int(q[qend])<<8 | int(q[qend+1])
	qclass := int(q[qend+2])<<8 | int(q[qend+3])
	qend += 4

	b, bound := a.lookupName(name)
	switch {
	case !bound || qclass != dnsClassIN:
		emitEgressRefused(nil, "dns", "", 0, name, tunnelReasonUnknownName)
		return dnsReply(q, dnsRcodeNXDomain, qend, nil)
	case qtype == dnsTypeA:
		v4 := b.addr.As4()
		answer := []byte{
			0xc0, 0x0c, // the question's name, which always starts at offset 12
			0x00, dnsTypeA,
			0x00, dnsClassIN,
			0x00, 0x00, 0x00, dnsTTL,
			0x00, 0x04,
			v4[0], v4[1], v4[2], v4[3],
		}
		return dnsReply(q, dnsRcodeNoError, qend, answer)
	case qtype == dnsTypeAAAA:
		// The name exists and has no v6 address. NOERROR with no records is
		// what says so; NXDOMAIN here would deny the name itself and make the
		// A query that follows pointless.
		return dnsReply(q, dnsRcodeNoError, qend, nil)
	default:
		emitEgressRefused(nil, "dns", "", 0, name, tunnelReasonUnknownType)
		return dnsReply(q, dnsRcodeNXDomain, qend, nil)
	}
}

// dnsQuestionName reads the single question's name, and returns the offset
// just past it. Compression is not accepted in a question: there is nothing
// before it to point at.
func dnsQuestionName(q []byte) (string, int, bool) {
	var sb strings.Builder
	i := dnsHeaderLen
	for {
		if i >= len(q) {
			return "", 0, false
		}
		n := int(q[i])
		if n == 0 {
			return sb.String(), i + 1, true
		}
		if n&0xc0 != 0 {
			return "", 0, false
		}
		if i+1+n > len(q) || sb.Len()+n+1 > 255 {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(bytes.ToLower(q[i+1 : i+1+n]))
		i += 1 + n
	}
}

// dnsReply assembles a response: the query's header and question, this
// responder's flags, and whatever answer there is. Anything the query carried
// past the question — an EDNS OPT record, most often — is dropped, which is
// the plain way of saying this responder speaks no EDNS.
func dnsReply(q []byte, rcode byte, qend int, answer []byte) []byte {
	if qend > len(q) {
		qend = dnsHeaderLen
	}
	out := make([]byte, 0, qend+len(answer))
	out = append(out, q[:qend]...)
	out[2] = 0x80 | (q[2] & 0x78) | (q[2] & 0x01) // QR, the query's opcode and RD
	out[2] |= 0x04                                // AA: these names are this responder's own
	out[3] = 0x80 | rcode                         // RA, and the verdict
	if qend == dnsHeaderLen {
		out[4], out[5] = 0, 0
	} else {
		out[4], out[5] = 0, 1
	}
	if len(answer) > 0 {
		out[6], out[7] = 0, 1
	} else {
		out[6], out[7] = 0, 0
	}
	out[8], out[9] = 0, 0   // no authority records
	out[10], out[11] = 0, 0 // and no additional ones, OPT included
	return append(out, answer...)
}
