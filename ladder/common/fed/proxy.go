// proxy.go - the federation proxy: the only licensed off-host path.
//
// Rung 5a. One of these runs per host, on the HOST, outside every sandbox -- like the
// broker, the postbox and the capability authority before it. The invariants section 2
// carries forward and this file has to keep:
//
//   - the tunnel terminates HERE, never inside a sandbox. Agents hold no transport key,
//     no connection and no registry. An agent's entire vocabulary for the network is
//     "send this to ops@hostb" on a unix socket its own kernel stamps.
//   - this is the only route off the box. Rung 0's per-task --internal networks give a
//     sandbox no IP path anywhere except its own proxy, which is what makes that true;
//     it is topology, not this process, and the demo probes it rather than claiming it.
//
// # What --ladder-fed gates
//
// With the flag ON: QUIC, TLS 1.3, mutually authenticated against the enrollment
// registry, one exchange per stream, every envelope signed and bound to its channel,
// every arrival checked before the postbox is contacted.
//
// With the flag OFF: the same framing over plain TCP with no registry, no signature, no
// binding, no replay window and no role check. That is not a strawman -- it is exactly
// what rungs 3 and 4 amount to when the second hop is on another machine, and rung 4's
// own threat-model section says so: "Two hosts running this patch would believe each
// other's stamps for no reason at all." BASELINE runs that sentence.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// EnvelopeTTL is how long an envelope is worth anything. Section 2 says "expiry
// (minutes)"; five is short enough that a captured envelope is stale before an operator
// could act on it and long enough that clock skew between two hosts is not a bug report.
const EnvelopeTTL = 5 * time.Minute

// Service is one standing agent this host fronts.
type Service struct {
	Name string
	Role *RoleScope

	mu        sync.Mutex
	started   time.Time
	exchanges int
	tainted   bool
	recycles  int
	// recycleWanted latches once a threshold trips, so the launcher polling the
	// recycle log sees one request rather than one per message.
	recycleWanted bool
	recycleReason string
}

// ProxyConfig is everything `ladder-fed serve` was told.
type ProxyConfig struct {
	Host         string
	KeyPath      string
	RegistryPath string
	Listen       string
	Gateway      string // unix socket this proxy accepts postbox sends on
	Ingest       string // the postbox's socket this proxy delivers arrivals to
	LogPath      string

	// Fed is --ladder-fed. False means plain TCP and no checks; see the package comment.
	Fed bool

	Services map[string]string // service name -> role scope file
	Peers    map[string]string // host name -> address override

	RecycleMaxExchanges int
	RecycleMaxAge       time.Duration
	RecycleOnTaint      bool
	RecycleLog          string
}

// Proxy is the running thing.
type Proxy struct {
	cfg ProxyConfig
	id  *Identity
	reg *Registry

	dial   *Dialer
	replay *ReplayCache

	mu       sync.Mutex
	services map[string]*Service
	seq      map[string]int64
	stats    proxyStats

	logmu sync.Mutex
	logfh *os.File
}

type proxyStats struct {
	Sent      int
	Delivered int
	Rejected  map[string]int
	// Timing, for the latency table CONTROL prints.
	ColdHandshakes []time.Duration
	Exchanges      []time.Duration
}

// NewProxy builds a proxy from its config, loading the key, the registry and the roles.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	id, _, _, err := LoadIdentity(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading this host's key: %w", err)
	}
	if id.Host != cfg.Host {
		return nil, fmt.Errorf("keyfile %s is for host %q, --host says %q", cfg.KeyPath, id.Host, cfg.Host)
	}
	reg, err := LoadRegistry(cfg.RegistryPath)
	if err != nil {
		return nil, fmt.Errorf("loading the enrollment registry: %w", err)
	}
	p := &Proxy{
		cfg:      cfg,
		id:       id,
		reg:      reg,
		dial:     NewDialer(id, reg),
		replay:   NewReplayCache(),
		services: map[string]*Service{},
		seq:      map[string]int64{},
		stats:    proxyStats{Rejected: map[string]int{}},
	}
	for name, rolePath := range cfg.Services {
		svc := &Service{Name: name, started: time.Now()}
		if rolePath != "" && rolePath != "-" {
			role, err := LoadRoleScope(rolePath)
			if err != nil {
				return nil, fmt.Errorf("service %q: %w", name, err)
			}
			svc.Role = role
		}
		p.services[name] = svc
	}
	if cfg.LogPath != "" {
		fh, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		p.logfh = fh
	}
	return p, nil
}

func (p *Proxy) log(format string, args ...any) {
	line := fmt.Sprintf("FED %.3f %s", float64(time.Now().UnixNano())/1e9, fmt.Sprintf(format, args...))
	p.logmu.Lock()
	defer p.logmu.Unlock()
	fmt.Println(line)
	os.Stdout.Sync()
	if p.logfh != nil {
		fmt.Fprintln(p.logfh, line)
		p.logfh.Sync()
	}
}

func (p *Proxy) countReject(code string) {
	p.mu.Lock()
	p.stats.Rejected[code]++
	p.mu.Unlock()
}

// ---------------------------------------------------------------- the gateway (outbound)

// gatewayRequest is what postbox.py sends.
type gatewayRequest struct {
	Op     string          `json:"op"`
	From   string          `json:"from"`
	ToHost string          `json:"to_host"`
	ToPeer string          `json:"to_peer"`
	Stamp  string          `json:"stamp"`
	Body   string          `json:"body"`
	Claim  json.RawMessage `json:"claim"`
}

type gatewayReply struct {
	Delivered bool   `json:"delivered"`
	Reason    string `json:"reason,omitempty"`
	Code      string `json:"code,omitempty"`
	To        string `json:"to,omitempty"`
}

// ServeGateway accepts sends from this host's postbox.
func (p *Proxy) ServeGateway(ctx context.Context) error {
	_ = os.Remove(p.cfg.Gateway)
	ln, err := net.Listen("unix", p.cfg.Gateway)
	if err != nil {
		return err
	}
	// 0600: the postbox runs as this user and no sandbox mounts this directory. Compare
	// the broker's socket, which is 0777 because a sandboxed agent has to reach it. An
	// agent that could reach THIS socket could ask the proxy to send anything anywhere,
	// which is why it is the one socket in the system with no path into a sandbox.
	_ = os.Chmod(p.cfg.Gateway, 0o600)
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.handleGatewayConn(ctx, conn)
	}
}

func (p *Proxy) handleGatewayConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, MaxFrame)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req gatewayRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, gatewayReply{Reason: "malformed json", Code: CodeBadFrame})
		return
	}
	switch req.Op {
	case "send":
		writeJSON(conn, p.send(ctx, req))
	case "status":
		writeJSON(conn, p.Status())
	case "reborn":
		// The launcher telling the proxy it has actually replaced the sandbox. The
		// proxy does not do this to itself on request: it asks for a recycle and waits
		// to be told one happened, so the counters can never claim a rebirth the world
		// did not get.
		ok := p.Reborn(req.From)
		writeJSON(conn, gatewayReply{Delivered: ok, To: req.From,
			Reason: map[bool]string{true: "counters reset; taint cleared by rebirth",
				false: "no such service"}[ok]})
	default:
		writeJSON(conn, gatewayReply{Reason: "unknown op " + req.Op, Code: CodeBadFrame})
	}
}

func writeJSON(w io.Writer, v any) {
	blob, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = w.Write(append(blob, '\n'))
}

// send is one outbound exchange: one stream on a warm connection to one peer host.
func (p *Proxy) send(ctx context.Context, req gatewayRequest) gatewayReply {
	start := time.Now()
	stamp, err := base64.StdEncoding.DecodeString(req.Stamp)
	if err != nil {
		return gatewayReply{Reason: "stamp is not base64", Code: CodeBadFrame}
	}

	// The recycle policy watches OUTBOUND traffic, because that is where the runtime's
	// verdict on the local service arrives: a stamp with taint=1 is the sending
	// sentry's word that this sandbox has read something untrusted. The proxy did not
	// decide it and could not.
	p.noteExchange(req.From, stamp)

	entry, known := p.reg.ByHost(req.ToHost)
	addr := p.cfg.Peers[req.ToHost]
	if addr == "" {
		addr = entry.Address
	}
	if addr == "" {
		return gatewayReply{Reason: fmt.Sprintf("no address known for host %q", req.ToHost),
			Code: "unknown-host"}
	}
	if p.cfg.Fed && !known {
		// Refused before a packet is sent. The registry is consulted on the way out as
		// well as on the way in, so this host does not leak a stamped message to
		// somewhere an operator never enrolled.
		p.countReject("unenrolled-destination")
		p.log("send from=%s to=%s@%s decision=deny reason=destination-not-enrolled enrolled=%v",
			req.From, req.ToPeer, req.ToHost, p.reg.Hosts())
		return gatewayReply{Reason: fmt.Sprintf("host %q is not in this host's enrollment registry", req.ToHost),
			Code: "unenrolled-destination"}
	}

	if !p.cfg.Fed {
		return p.sendPlain(ctx, req, stamp, addr, start)
	}

	conn, dialRes, err := p.dial.Get(ctx, req.ToHost, addr)
	if err != nil {
		p.log("send from=%s to=%s@%s decision=deny reason=connect: %v", req.From, req.ToPeer, req.ToHost, err)
		return gatewayReply{Reason: err.Error(), Code: "connect-failed"}
	}
	if !dialRes.Reused {
		p.mu.Lock()
		p.stats.ColdHandshakes = append(p.stats.ColdHandshakes, dialRes.Handshake)
		p.mu.Unlock()
		p.log("connect to=%s addr=%s handshake=%s confirm=%s peer=%s alpn=%s 0rtt=off",
			req.ToHost, addr, dialRes.Handshake.Round(time.Microsecond),
			dialRes.Confirm.Round(time.Microsecond), Fingerprint(conn.PeerKey), ALPN)
	}

	env := &Envelope{
		V:          EnvelopeVersion,
		FromHost:   p.cfg.Host,
		FromPeer:   req.From,
		ToHost:     req.ToHost,
		ToPeer:     req.ToPeer,
		Seq:        p.nextSeq(req.ToHost, req.From),
		Exp:        time.Now().Add(EnvelopeTTL).Unix(),
		Binding:    base64.StdEncoding.EncodeToString(conn.Binding),
		Stamp:      base64.StdEncoding.EncodeToString(stamp),
		Claim:      req.Claim,
		BodySHA256: BodyDigest([]byte(req.Body)),
	}
	sig, err := env.Sign(p.id.Priv)
	if err != nil {
		return gatewayReply{Reason: err.Error(), Code: "sign-failed"}
	}

	st, err := conn.quic.OpenStreamSync(ctx)
	if err != nil {
		return gatewayReply{Reason: err.Error(), Code: "stream-failed"}
	}
	if err := WriteFrame(st, env, sig, []byte(req.Body)); err != nil {
		st.CancelWrite(1)
		return gatewayReply{Reason: err.Error(), Code: "write-failed"}
	}
	// Stream.Close is CloseWrite in quic-go: it shuts the send direction only. The
	// receiver's "read to EOF, then reject trailing bytes" depends on it, and so does
	// "one exchange per stream" being a fact rather than a convention.
	if err := st.Close(); err != nil {
		return gatewayReply{Reason: err.Error(), Code: "write-failed"}
	}

	var ack gatewayReply
	raw, err := io.ReadAll(io.LimitReader(st, MaxFrame))
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &ack)
	}
	elapsed := time.Since(start)
	p.mu.Lock()
	p.stats.Sent++
	p.stats.Exchanges = append(p.stats.Exchanges, elapsed)
	p.mu.Unlock()
	p.log("send from=%s to=%s@%s seq=%d exp=%ds delivered=%v code=%s rtt=%s stamp=%q",
		req.From, req.ToPeer, req.ToHost, env.Seq, int(EnvelopeTTL.Seconds()),
		ack.Delivered, ack.Code, elapsed.Round(time.Microsecond), StampSummary(stamp))
	return ack
}

func (p *Proxy) nextSeq(host, peer string) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := host + "/" + peer
	p.seq[k] = NextSeq(p.seq[k])
	return p.seq[k]
}

// ---------------------------------------------------------------- the listener (inbound)

// ServeInbound accepts connections from other hosts.
func (p *Proxy) ServeInbound(ctx context.Context) error {
	if !p.cfg.Fed {
		return p.serveInboundPlain(ctx)
	}
	ln, err := ListenQUIC(p.id, p.reg, p.cfg.Listen, func(rej error) {
		p.countReject("handshake-refused")
		p.log("handshake decision=deny reason=%v", rej)
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	p.log("listening quic=%s host=%s enrolled=%v services=%v 0rtt=off alpn=%s",
		ln.Addr(), p.cfg.Host, p.reg.Hosts(), p.serviceNames(), ALPN)
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, peerHost, peerKey, binding, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A refused handshake never becomes a connection at all -- quic-go does
			// not surface it here -- so the evidence line is written by the pin
			// check's onReject hook above, not by this loop.
			continue
		}
		p.log("accepted from=%s key=%s remote=%s", peerHost, Fingerprint(peerKey), conn.RemoteAddr())
		go p.serveConn(ctx, conn, peerHost, peerKey, binding)
	}
}

func (p *Proxy) serveConn(ctx context.Context, conn *quic.Conn, peerHost string, peerKey []byte, binding []byte) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go p.serveStream(ctx, st, peerHost, peerKey, binding)
	}
}

func (p *Proxy) serveStream(ctx context.Context, st *quic.Stream, peerHost string, peerKey []byte, binding []byte) {
	defer st.Close()

	raw, rerr := io.ReadAll(io.LimitReader(st, 4*MaxFrame+64))
	if rerr != nil && len(raw) == 0 {
		return
	}
	// The post-handshake confirmation exchange is not a frame. It is answered here and
	// nowhere else, so nothing downstream has to know it exists.
	if bytes.Equal(bytes.TrimSpace(raw), pingPayload) {
		_, _ = st.Write([]byte("ok"))
		return
	}

	frame, err := ParseFrame(raw)
	if err != nil {
		code := CodeOf(err)
		p.countReject(code)
		p.log("reject from=%s code=%s reason=%v", peerHost, code, err)
		writeJSON(st, gatewayReply{Reason: err.Error(), Code: code})
		return
	}

	if err := frame.Verify(VerifyOpts{
		PeerKey:  peerKey,
		PeerHost: peerHost,
		Binding:  binding,
		SelfHost: p.cfg.Host,
		Now:      time.Now(),
	}); err != nil {
		code := CodeOf(err)
		p.countReject(code)
		p.log("reject from=%s peer=%s code=%s reason=%v", peerHost, frame.Envelope.FromPeer, code, err)
		writeJSON(st, gatewayReply{Reason: err.Error(), Code: code})
		return
	}

	env := frame.Envelope
	if err := p.replay.Accept(env.FromHost, env.FromPeer, env.Seq); err != nil {
		p.countReject(CodeReplayed)
		p.log("reject from=%s peer=%s code=%s reason=%v", peerHost, env.FromPeer, CodeReplayed, err)
		writeJSON(st, gatewayReply{Reason: err.Error(), Code: CodeReplayed})
		return
	}

	reply := p.admit(frame)
	writeJSON(st, reply)
}

// admit is everything between "this envelope is authentic" and "the postbox has it":
// the service must exist here, and the capability the sender claims must be inside that
// service's deploy-time role. Section 4.4, and section 7's "substrate rejections happen
// in the proxy before any agent sees bytes".
func (p *Proxy) admit(frame *Frame) gatewayReply {
	env := frame.Envelope

	p.mu.Lock()
	svc := p.services[env.ToPeer]
	p.mu.Unlock()
	if svc == nil {
		p.countReject(CodeUnknownService)
		p.log("reject from=%s@%s code=%s reason=this host fronts no service named %q (fronts: %v)",
			env.FromPeer, env.FromHost, CodeUnknownService, env.ToPeer, p.serviceNames())
		return gatewayReply{Reason: fmt.Sprintf("this host fronts no service named %q", env.ToPeer),
			Code: CodeUnknownService}
	}

	if svc.Role != nil {
		claimed, err := ClaimTools(env.Claim)
		if err != nil {
			p.countReject(CodeOutsideRole)
			return gatewayReply{Reason: "capability claim is not parseable: " + err.Error(),
				Code: CodeOutsideRole}
		}
		if ok, why := Subset(claimed, svc.Role.Tools); !ok {
			p.countReject(CodeOutsideRole)
			p.log("reject from=%s@%s to=%s code=%s reason=%s",
				env.FromPeer, env.FromHost, env.ToPeer, CodeOutsideRole, why)
			return gatewayReply{Reason: why, Code: CodeOutsideRole}
		}
	}

	stamp, _ := frame.StampBytes()
	reply, err := p.deliver(env, stamp, frame.Body)
	if err != nil {
		p.log("deliver to=%s from=%s@%s decision=deny reason=postbox: %v",
			env.ToPeer, env.FromPeer, env.FromHost, err)
		return gatewayReply{Reason: err.Error(), Code: "ingest-failed"}
	}
	if reply.Delivered {
		p.mu.Lock()
		p.stats.Delivered++
		p.mu.Unlock()
		p.log("deliver to=%s from=%s@%s seq=%d stamp=%q role=ok",
			env.ToPeer, env.FromPeer, env.FromHost, env.Seq, StampSummary(stamp))
	} else {
		p.log("deliver to=%s from=%s@%s seq=%d decision=deny reason=%s",
			env.ToPeer, env.FromPeer, env.FromHost, env.Seq, reply.Code)
	}
	return reply
}

// ingestRequest is what this proxy hands the local postbox.
type ingestRequest struct {
	Op       string         `json:"op"`
	FromHost string         `json:"from_host"`
	FromPeer string         `json:"from_peer"`
	ToPeer   string         `json:"to_peer"`
	Stamp    string         `json:"stamp"`
	Body     string         `json:"body"`
	Envelope ingestEnvelope `json:"envelope"`
}

type ingestEnvelope struct {
	Seq     int64           `json:"seq"`
	Exp     int64           `json:"exp"`
	PeerKey string          `json:"peer_key"`
	Claim   json.RawMessage `json:"claim,omitempty"`
}

func (p *Proxy) deliver(env *Envelope, stamp, body []byte) (gatewayReply, error) {
	entry, _ := p.reg.ByHost(env.FromHost)
	req := ingestRequest{
		Op:       "deliver",
		FromHost: env.FromHost,
		FromPeer: env.FromPeer,
		ToPeer:   env.ToPeer,
		Stamp:    base64.StdEncoding.EncodeToString(stamp),
		Body:     string(body),
		Envelope: ingestEnvelope{
			Seq: env.Seq, Exp: env.Exp,
			PeerKey: entry.Key,
			Claim:   env.Claim,
		},
	}
	conn, err := net.DialTimeout("unix", p.cfg.Ingest, 5*time.Second)
	if err != nil {
		return gatewayReply{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	writeJSON(conn, req)
	raw, err := bufio.NewReader(io.LimitReader(conn, MaxFrame)).ReadBytes('\n')
	if err != nil && len(raw) == 0 {
		return gatewayReply{}, err
	}
	var reply gatewayReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return gatewayReply{}, err
	}
	return reply, nil
}

// ---------------------------------------------------------------- the recycle policy

// noteExchange records one outbound message from a local standing service and decides
// whether the service has to be reborn.
//
// Section 4.5, and the honest half of it: taint accumulates monotonically (rung 2), so a
// service that never exits trends toward permanently tainted. Nothing here CLEARS a
// taint bit -- it could not, the bit is in another kernel, and a proxy that could clear
// it would be a proxy that could launder it. What it can do is stop using the sandbox
// and ask the launcher for a new one.
func (p *Proxy) noteExchange(name string, stamp []byte) {
	p.mu.Lock()
	svc := p.services[name]
	p.mu.Unlock()
	if svc == nil {
		return
	}
	svc.mu.Lock()
	svc.exchanges++
	if StampTainted(stamp) && !svc.tainted {
		svc.tainted = true
		p.log("taint service=%s source=runtime-stamp exchanges=%d origin=%q",
			name, svc.exchanges, StampField(stamp, "origin"))
	}
	age := time.Since(svc.started)
	reason := ""
	switch {
	case p.cfg.RecycleOnTaint && svc.tainted:
		reason = "taint"
	case p.cfg.RecycleMaxExchanges > 0 && svc.exchanges >= p.cfg.RecycleMaxExchanges:
		reason = "exchange-count"
	case p.cfg.RecycleMaxAge > 0 && age >= p.cfg.RecycleMaxAge:
		reason = "age"
	}
	first := reason != "" && !svc.recycleWanted
	if first {
		svc.recycleWanted = true
		svc.recycleReason = reason
	}
	exchanges, tainted := svc.exchanges, svc.tainted
	svc.mu.Unlock()

	if first {
		p.log("recycle service=%s reason=%s exchanges=%d tainted=%v age=%s action=destroy-and-restart-from-image",
			name, reason, exchanges, tainted, age.Round(time.Millisecond))
		p.appendRecycle(name, reason, exchanges, tainted, age)
	}
}

func (p *Proxy) appendRecycle(name, reason string, exchanges int, tainted bool, age time.Duration) {
	if p.cfg.RecycleLog == "" {
		return
	}
	fh, err := os.OpenFile(p.cfg.RecycleLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	fmt.Fprintf(fh, "%s\t%s\t%d\t%v\t%s\n", name, reason, exchanges, tainted, age.Round(time.Millisecond))
}

// Reborn resets a service's counters. Called through the gateway by the launcher AFTER
// it has actually destroyed and restarted the sandbox, so the counters and the world
// cannot disagree -- and deliberately not called by the proxy itself, which has no
// business believing a sandbox was replaced because it asked for it.
func (p *Proxy) Reborn(name string) bool {
	p.mu.Lock()
	svc := p.services[name]
	p.mu.Unlock()
	if svc == nil {
		return false
	}
	svc.mu.Lock()
	svc.started = time.Now()
	svc.exchanges = 0
	svc.tainted = false
	svc.recycleWanted = false
	svc.recycleReason = ""
	svc.recycles++
	n := svc.recycles
	svc.mu.Unlock()
	p.log("reborn service=%s generation=%d taint=cleared-by-rebirth-only", name, n+1)
	return true
}

// ---------------------------------------------------------------- status

// StatusReply is what `ladder-fed status` prints and what demo.sh asserts on.
type StatusReply struct {
	Host        string           `json:"host"`
	Fed         bool             `json:"fed"`
	Enrolled    []string         `json:"enrolled"`
	Connections int              `json:"connections"`
	Services    []ServiceStatus  `json:"services"`
	Replay      string           `json:"replay"`
	Sent        int              `json:"sent"`
	Delivered   int              `json:"delivered"`
	Rejected    map[string]int   `json:"rejected"`
	Latency     map[string]int64 `json:"latency_us"`
}

// ServiceStatus is one standing service's state.
type ServiceStatus struct {
	Name          string `json:"name"`
	Exchanges     int    `json:"exchanges"`
	Tainted       bool   `json:"tainted"`
	AgeSeconds    int    `json:"age_seconds"`
	Generation    int    `json:"generation"`
	RecycleWanted bool   `json:"recycle_wanted"`
	RecycleReason string `json:"recycle_reason,omitempty"`
	Role          string `json:"role,omitempty"`
}

// Status snapshots the proxy.
func (p *Proxy) Status() StatusReply {
	p.mu.Lock()
	names := make([]string, 0, len(p.services))
	for n := range p.services {
		names = append(names, n)
	}
	sort.Strings(names)
	rejected := map[string]int{}
	for k, v := range p.stats.Rejected {
		rejected[k] = v
	}
	sent, delivered := p.stats.Sent, p.stats.Delivered
	cold := append([]time.Duration(nil), p.stats.ColdHandshakes...)
	warm := append([]time.Duration(nil), p.stats.Exchanges...)
	svcs := make([]*Service, 0, len(names))
	for _, n := range names {
		svcs = append(svcs, p.services[n])
	}
	p.mu.Unlock()

	out := StatusReply{
		Host: p.cfg.Host, Fed: p.cfg.Fed, Enrolled: p.reg.Hosts(),
		Connections: p.dial.Warm(), Replay: p.replay.Stats(),
		Sent: sent, Delivered: delivered, Rejected: rejected,
		Latency: map[string]int64{
			"handshake_median": medianMicros(cold),
			"exchange_median":  medianMicros(warm),
		},
	}
	for _, svc := range svcs {
		svc.mu.Lock()
		role := ""
		if svc.Role != nil {
			role = joinTools(svc.Role.Tools)
		}
		out.Services = append(out.Services, ServiceStatus{
			Name: svc.Name, Exchanges: svc.exchanges, Tainted: svc.tainted,
			AgeSeconds: int(time.Since(svc.started).Seconds()), Generation: svc.recycles + 1,
			RecycleWanted: svc.recycleWanted, RecycleReason: svc.recycleReason, Role: role,
		})
		svc.mu.Unlock()
	}
	return out
}

func (p *Proxy) serviceNames() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.services))
	for n := range p.services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func medianMicros(ds []time.Duration) int64 {
	if len(ds) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), ds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2].Microseconds()
}
