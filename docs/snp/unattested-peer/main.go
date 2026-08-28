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

// unattested-peer dials a tunneld with nothing to say for itself (ticket 14).
//
//	unattested-peer -addr HOST:PORT [-timeout 20s]
//
// It speaks the transport correctly and presents a certificate correctly. What
// it does not present is evidence: the certificate carries no attestation
// payload, because this process runs on an ordinary machine that has none to
// give. That is exactly what a non-confidential VM looks like at a handshake,
// and the point of running it against a real tunneld is that the refusal has
// to happen on the wire, from a peer that had already got as far as being
// asked for a certificate.
//
// It is deliberately not built from ratls. A peer built from this design's own
// certificate code would be refused by this design's own reading of it, which
// proves less than a peer built the way anybody else would build one: a QUIC
// dial, TLS 1.3, the right ALPN, a self-signed key. Everything here is what a
// stranger would have written.
//
// Expected: this is refused, exits 0, and the tunneld's console names the
// reason it did not tell this program — ReasonNoEvidence. It exits 1 if it is
// admitted, which would be the finding.
//
// # Refused is not the same as unreachable
//
// A program that exits 0 whenever anything goes wrong reports "refused" for a
// peer it never reached, and a harness that greps its output then records a
// refusal that never happened. So the two are separated and given different
// statuses. Once the dial returns a connection the peer is reachable by
// construction, and every failure after that point is its decision; at the
// dial itself, an error the peer originated (a transport or application close
// it sent us — a TLS alert carried as CRYPTO_ERROR is one) is a refusal, while
// a timeout with nothing heard, or a network error, is not evidence about what
// the peer would have done.
//
//	0  refused — the expected answer
//	1  admitted — the finding
//	2  usage
//	3  never reached it; says nothing about the peer
//	4  a failure this program could not classify, which is also not evidence
//
// "Refused" is not the same as "the dial failed", and this program is where
// that stops being a subtlety. TLS 1.3 lets a client finish its handshake
// before the server has processed the client's certificate, so the dial here
// returns a connection: the refusal is decided on the far side and arrives
// afterwards. That is precisely why tunnel.Dial completes one empty
// application round trip before it calls a tunnel established (spec, user
// story 38) — the listener answers a stream only on a connection it admitted.
// This program does the same round trip for the same reason, and reports both
// halves, because a run that stopped at the successful dial would have
// recorded the opposite of what happened.
//
// It is a harness program and lives outside the attest module for the same
// reason emit-refvals does: nothing in the module should be able to import an
// attacker.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("addr", "", "the tunneld to dial, HOST:PORT")
	timeout := flag.Duration("timeout", 20*time.Second, "how long to give the handshake")
	alpn := flag.String("alpn", "gvisor-attested-tunnel/1", "the protocol a tunneld agrees on")
	flag.Parse()
	if *addr == "" {
		flag.Usage()
		os.Exit(2)
	}
	switch verdict, err := run(*addr, *alpn, *timeout); verdict {
	case refused:
		fmt.Printf("unattested-peer: REFUSED by %s: %v\n", *addr, err)
		fmt.Println("unattested-peer: which is the answer, and note what it does not say: not which")
		fmt.Println("unattested-peer: check refused it, not what would have satisfied it, not that")
		fmt.Println("unattested-peer: evidence was the missing thing.")
	case unreachable:
		fmt.Printf("unattested-peer: NEVER REACHED %s: %v\n", *addr, err)
		fmt.Println("unattested-peer: this is not a refusal and must not be recorded as one — nothing")
		fmt.Println("unattested-peer: here says what that peer would have done with the certificate.")
		os.Exit(3)
	case unclassified:
		fmt.Printf("unattested-peer: UNCLASSIFIED failure against %s: %v\n", *addr, err)
		fmt.Println("unattested-peer: neither a refusal nor a plain unreachable peer. Not evidence.")
		os.Exit(4)
	case admitted:
		fmt.Printf("unattested-peer: ADMITTED by %s — a tunneld exchanged with a peer that presented no evidence\n", *addr)
		os.Exit(1)
	}
}

// A verdict is what this program is for. Every one of them is a different
// thing to write in a record, which is why they are not an error and a nil.
type verdict int

const (
	refused verdict = iota
	unreachable
	unclassified
	admitted
)

func run(addr, alpn string, timeout time.Duration) (verdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cert, err := selfSigned()
	if err != nil {
		return unclassified, err
	}
	fmt.Printf("unattested-peer: dialing %s with a certificate carrying no attestation payload\n", addr)
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // this end judges nothing; the tunneld's judgement is the experiment
		NextProtos:         []string{alpn},
	}, &quic.Config{})
	if err != nil {
		return classifyDial(err), err
	}
	defer conn.CloseWithError(0, "")
	fmt.Println("unattested-peer: the dial returned a connection — TLS 1.3 lets a client finish")
	fmt.Println("unattested-peer: before the server has judged its certificate, so this proves nothing yet")

	// The establishment round trip, done the way tunnel.Dial does it: open a
	// stream, close it, and read the listener's reply to end of stream. A
	// listener answers only on a connection it admitted.
	//
	// Everything below this line is past the point where the peer proved it is
	// there, so a failure is its decision and not the network's.
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return refused, fmt.Errorf("the connection was gone before a stream could be opened: %w", err)
	}
	if err := s.Close(); err != nil {
		return refused, fmt.Errorf("the connection was gone before the stream could be closed: %w", err)
	}
	if err := s.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return unclassified, err
	}
	reply, err := io.ReadAll(s)
	if err != nil {
		return refused, fmt.Errorf("no application round trip: %w", err)
	}
	fmt.Printf("unattested-peer: the listener answered %d bytes\n", len(reply))
	return admitted, nil
}

// classifyDial decides whether a dial that failed failed because the peer said
// no or because it was never there.
//
// The distinction is the peer's own bytes. A transport or application close
// this end *received* is the peer speaking — a TLS alert reaches us as
// CRYPTO_ERROR inside a transport close, and "bad certificate" is what a
// tunneld's refusal looks like from out here. A handshake that timed out
// having heard nothing, and any error from the socket underneath, is the
// network and not a verdict.
func classifyDial(err error) verdict {
	var transport *quic.TransportError
	if errors.As(err, &transport) && transport.Remote {
		return refused
	}
	var application *quic.ApplicationError
	if errors.As(err, &application) && application.Remote {
		return refused
	}
	var handshakeTimeout *quic.HandshakeTimeoutError
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &handshakeTimeout) || errors.As(err, &idleTimeout) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return unreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return unreachable
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return unreachable
	}
	return unclassified
}

// selfSigned is an ordinary throwaway certificate: no extensions, nothing
// under any private arc, nothing a tunneld reads except that it exists.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unattested-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
