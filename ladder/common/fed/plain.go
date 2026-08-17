// plain.go - what a federated deployment is WITHOUT --ladder-fed, which is BASELINE.
//
// Rung 5a's baseline is not a strawman someone built to be knocked over. It is rungs 3
// and 4 exactly as they shipped, with the second hop moved to another machine -- and
// rung 4's own threat-model section already predicted what happens: "Cross-host
// anything... Two hosts running this patch would believe each other's stamps for no
// reason at all."
//
// So this file carries the SAME frame -- same magic, same envelope struct, same sentry
// stamp inside it, same one-exchange-per-connection discipline -- over plain TCP, and
// omits exactly four things:
//
//	no registry     anyone who can reach the port is a peer
//	no signature    the envelope is unauthenticated, so anyone can write one
//	no binding      nothing ties an envelope to the channel it arrived on
//	no replay/role  nothing is fresh, nothing is bounded by the receiving service's role
//
// Everything the RUNTIME contributes is still present and still true: the sentry stamp
// is there, it says taint=0 or taint=1 honestly, the sending agent could not have
// written it. That is the point of the block. The stamp is unforgeable BY THE SENDING
// AGENT and worth nothing against anyone standing between the two hosts, because
// "unforgeable" was only ever a statement about one process boundary.
//
// The MITM in the demo reads and rewrites these bytes. It can, and that is the finding.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func (p *Proxy) sendPlain(ctx context.Context, req gatewayRequest, stamp []byte, addr string, start time.Time) gatewayReply {
	env := &Envelope{
		V:        EnvelopeVersion,
		FromHost: p.cfg.Host,
		FromPeer: req.From,
		ToHost:   req.ToHost,
		ToPeer:   req.ToPeer,
		Seq:      p.nextSeq(req.ToHost, req.From),
		Exp:      time.Now().Add(EnvelopeTTL).Unix(),
		// No binding: there is no handshake to export from. The field is left empty
		// rather than filled with something meaningless, so a reader of a captured
		// baseline envelope can see the absence.
		Binding:    "",
		Stamp:      base64.StdEncoding.EncodeToString(stamp),
		Claim:      req.Claim,
		BodySHA256: BodyDigest([]byte(req.Body)),
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		p.log("send from=%s to=%s@%s decision=deny reason=connect: %v (plain tcp, --ladder-fed off)",
			req.From, req.ToPeer, req.ToHost, err)
		return gatewayReply{Reason: err.Error(), Code: "connect-failed"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// The signature slot is present and EMPTY. Keeping the frame shape identical is
	// deliberate: it means the only difference between the two blocks is whether
	// anything checks, not whether the wire format changed.
	if err := WriteFrame(conn, env, nil, []byte(req.Body)); err != nil {
		return gatewayReply{Reason: err.Error(), Code: "write-failed"}
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	var ack gatewayReply
	raw, _ := io.ReadAll(io.LimitReader(conn, MaxFrame))
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &ack)
	}
	elapsed := time.Since(start)
	p.mu.Lock()
	p.stats.Sent++
	p.stats.Exchanges = append(p.stats.Exchanges, elapsed)
	p.mu.Unlock()
	p.log("send from=%s to=%s@%s seq=%d delivered=%v rtt=%s transport=plain-tcp unauthenticated=yes stamp=%q",
		req.From, req.ToPeer, req.ToHost, env.Seq, ack.Delivered,
		elapsed.Round(time.Microsecond), StampSummary(stamp))
	return ack
}

func (p *Proxy) serveInboundPlain(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	p.log("listening tcp=%s host=%s services=%v transport=plain-tcp registry=IGNORED signature=NOT-CHECKED "+
		"binding=NONE replay=NOT-TRACKED role=NOT-ENFORCED", ln.Addr(), p.cfg.Host, p.serviceNames())
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.servePlainConn(conn)
	}
}

func (p *Proxy) servePlainConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	frame, err := ReadFrame(conn)
	if err != nil {
		// Even the baseline rejects a frame it cannot parse. That is not a security
		// check, it is a parser, and the demo does not count it as one.
		writeJSON(conn, gatewayReply{Reason: err.Error(), Code: CodeOf(err)})
		return
	}
	env := frame.Envelope

	// This is the entire admission policy of the baseline, and it is worth reading
	// slowly, because it is what a reasonable engineer writes when the transport is
	// "the other host's proxy" and nobody has asked who that is:
	//
	//   - is the service named here?
	//
	// That is all. No registry lookup, so an impostor is a peer. No signature check, so
	// the from_host field is whatever the sender typed. No binding, so an envelope
	// captured anywhere works everywhere. No replay window, so a captured privileged
	// request is a reusable one. No role scope, so the capability claim in the envelope
	// is believed in full.
	p.mu.Lock()
	svc := p.services[env.ToPeer]
	p.mu.Unlock()
	if svc == nil {
		writeJSON(conn, gatewayReply{Reason: "no such service", Code: CodeUnknownService})
		return
	}

	stamp, _ := frame.StampBytes()
	reply, derr := p.deliver(env, stamp, frame.Body)
	if derr != nil {
		writeJSON(conn, gatewayReply{Reason: derr.Error(), Code: "ingest-failed"})
		return
	}
	if reply.Delivered {
		p.mu.Lock()
		p.stats.Delivered++
		p.mu.Unlock()
	}
	p.log("deliver to=%s from=%s@%s seq=%d delivered=%v transport=plain-tcp checks=none stamp=%q",
		env.ToPeer, env.FromPeer, env.FromHost, env.Seq, reply.Delivered, StampSummary(stamp))
	writeJSON(conn, reply)
}

// ---------------------------------------------------------------- the MITM position

// MITMConfig configures the man in the middle the demo puts between the two hosts.
type MITMConfig struct {
	Listen  string
	Forward string
	Mode    string // "tcp" (baseline) or "udp" (enforced)
	// Rewrite is applied to the payload AND to the capability claim, because in the
	// baseline neither is authenticated and a man in the middle that can edit one can
	// edit the other. Rewriting only the payload would understate the attack and would
	// leave rung 4's host-side key check catching it -- which it does, and which would
	// make the baseline look like a defence rather than like the gap it is.
	Rewrite []string
	LogPath string
}

// RunMITM relays traffic and reports what it could see and do.
//
// This IS the packet capture the spec asks for, and it is a better one than tcpdump
// would be: it needs no root, and it sits in the position the threat model actually
// names rather than next to it. In tcp mode it parses the frame, prints the plaintext
// body, and can rewrite it. In udp mode it forwards QUIC datagrams blind and prints what
// it managed to read out of them, which is the evidence line for "the capture shows
// ciphertext".
func RunMITM(ctx context.Context, cfg MITMConfig) error {
	logf := mitmLogger(cfg.LogPath)
	if cfg.Mode == "udp" {
		return runMITMUDP(ctx, cfg, logf)
	}
	return runMITMTCP(ctx, cfg, logf)
}

func mitmLogger(path string) func(string, ...any) {
	var fh *os.File
	if path != "" {
		fh, _ = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	var mu sync.Mutex
	return func(format string, args ...any) {
		line := fmt.Sprintf("MITM %.3f %s", float64(time.Now().UnixNano())/1e9,
			fmt.Sprintf(format, args...))
		mu.Lock()
		defer mu.Unlock()
		fmt.Println(line)
		os.Stdout.Sync()
		if fh != nil {
			fmt.Fprintln(fh, line)
			fh.Sync()
		}
	}
}

func runMITMTCP(ctx context.Context, cfg MITMConfig, logf func(string, ...any)) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	logf("listening tcp=%s forwarding=%s mode=tcp rewrites=%d", ln.Addr(), cfg.Forward, len(cfg.Rewrite))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(down net.Conn) {
			defer down.Close()
			_ = down.SetDeadline(time.Now().Add(30 * time.Second))
			raw, _ := io.ReadAll(io.LimitReader(down, 4*MaxFrame))

			frame, perr := ParseFrame(raw)
			if perr == nil {
				// Read. This is claim (i) of the baseline: the message is in the clear.
				stamp, _ := frame.StampBytes()
				logf("read from=%s@%s to=%s seq=%d stamp=%q body=%q",
					frame.Envelope.FromPeer, frame.Envelope.FromHost, frame.Envelope.ToPeer,
					frame.Envelope.Seq, StampSummary(stamp), truncate(string(frame.Body), 320))
				if len(cfg.Rewrite) > 0 {
					// Alter. Claim (ii): a privileged request is rewritten in flight and
					// the receiver has no way to know. The body hash is recomputed --
					// which is the honest version of the attack, since nothing checks a
					// signature over it.
					body, claim := string(frame.Body), string(frame.Envelope.Claim)
					for _, rule := range cfg.Rewrite {
						old, new, found := strings.Cut(rule, "=")
						if !found || old == "" {
							continue
						}
						if b := strings.ReplaceAll(body, old, new); b != body {
							logf("rewrite payload %q -> %q (the receiver will act on this)", old, new)
							body = b
						}
						if c := strings.ReplaceAll(claim, old, new); c != claim {
							logf("rewrite capability claim %q -> %q (nothing signed it either)", old, new)
							claim = c
						}
					}
					frame.Body = []byte(body)
					frame.Envelope.BodySHA256 = BodyDigest(frame.Body)
					if claim != "" {
						frame.Envelope.Claim = json.RawMessage(claim)
					}
					var buf bytes.Buffer
					if err := WriteFrame(&buf, frame.Envelope, frame.Sig, frame.Body); err == nil {
						raw = buf.Bytes()
					}
				}
			} else {
				logf("read %d bytes, could not parse a frame: %v", len(raw), perr)
			}

			up, err := net.DialTimeout("tcp", cfg.Forward, 10*time.Second)
			if err != nil {
				logf("forward failed: %v", err)
				return
			}
			defer up.Close()
			_ = up.SetDeadline(time.Now().Add(30 * time.Second))
			_, _ = up.Write(raw)
			if tcp, ok := up.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			reply, _ := io.ReadAll(io.LimitReader(up, MaxFrame))
			_, _ = down.Write(reply)
		}(conn)
	}
}

// runMITMUDP relays QUIC blind. It is the same position on the network and it learns
// nothing: the demo asserts that no ladder token appears in anything it forwarded.
func runMITMUDP(ctx context.Context, cfg MITMConfig, logf func(string, ...any)) error {
	laddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", cfg.Forward)
	if err != nil {
		return err
	}
	down, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer down.Close()
	logf("listening udp=%s forwarding=%s mode=udp (quic: relaying datagrams blind)", down.LocalAddr(), raddr)
	go func() { <-ctx.Done(); down.Close() }()

	type client struct {
		up   *net.UDPConn
		last time.Time
	}
	clients := map[string]*client{}
	var mu sync.Mutex
	buf := make([]byte, 65535)
	seen, printable := 0, 0

	for {
		n, from, err := down.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		payload := append([]byte(nil), buf[:n]...)
		seen++
		if hasLadderToken(payload) {
			printable++
			logf("PLAINTEXT LEAK: datagram %d carries a ladder token", seen)
		}
		if seen%25 == 1 {
			logf("relayed=%d datagrams bytes=%d readable-ladder-tokens=%d sample=%q",
				seen, n, printable, printableRun(payload, 48))
		}

		mu.Lock()
		c := clients[from.String()]
		if c == nil {
			up, derr := net.DialUDP("udp", nil, raddr)
			if derr != nil {
				mu.Unlock()
				continue
			}
			c = &client{up: up, last: time.Now()}
			clients[from.String()] = c
			go func(src *net.UDPAddr, up *net.UDPConn) {
				rbuf := make([]byte, 65535)
				for {
					rn, rerr := up.Read(rbuf)
					if rerr != nil {
						return
					}
					_, _ = down.WriteToUDP(rbuf[:rn], src)
				}
			}(from, up)
		}
		c.last = time.Now()
		mu.Unlock()
		_, _ = c.up.Write(payload)
	}
}

// hasLadderToken is the confidentiality assertion, and it is deliberately crude: if any
// of these strings appears anywhere in what the MITM relayed, the transport did not
// encrypt. Crude is right here -- a subtle test would be a test that could pass by
// accident.
func hasLadderToken(b []byte) bool {
	for _, tok := range LadderTokens {
		if bytes.Contains(b, []byte(tok)) {
			return true
		}
	}
	return false
}

// LadderTokens is what "readable" means for the confidentiality check, in one place so
// the demo and the MITM cannot drift apart about it.
var LadderTokens = []string{
	"LADDER-STAMP", "LADDER-CAP", "LADDER-INSTRUCTION", "LFED1",
	"write_config", "auth_disabled", "cache_size", "reader", "hosta", "hostb",
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// printableRun renders the longest readable-looking run of a datagram, so the transcript
// shows what an eavesdropper actually had rather than asserting that it had nothing.
func printableRun(b []byte, n int) string {
	var best, cur []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
			if len(cur) > len(best) {
				best = append([]byte(nil), cur...)
			}
			continue
		}
		cur = cur[:0]
	}
	if len(best) > n {
		best = best[:n]
	}
	if len(best) == 0 {
		return "(no printable run)"
	}
	return string(best)
}
