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

// Command fdhandoff is the ticket 22 spike E1: can a QUIC stream cross a
// process boundary as a file descriptor, and if not, what does proxying it
// through a socketpair cost?
//
// The parent process plays tunneld: it owns the QUIC connection (quic-go
// v0.59.0, the version attest/go.mod pins) and holds the streams. The child
// process plays the sandbox: it is handed one end of an AF_UNIX SOCK_STREAM
// socketpair over a unix socket with SCM_RIGHTS, turns it into a plain
// net.Conn with net.FileConn, and does its request-response through it while
// the parent pumps bytes between that socketpair and the QUIC stream.
//
// Both sides run the identical client loop over an io.ReadWriter, so the
// direct (in-process, straight on *quic.Stream) and proxied (child, through
// the socketpair) numbers differ only by the proxy.
//
// Usage:
//
//	fdhandoff -runs 5 -out results.json
//
// The child re-execs this same binary with -mode=child.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// echoLimit is the largest request the echo server buffers (and therefore
// echoes back verbatim). Anything larger is discarded and answered with the
// byte count, which is what the bulk-up phase checks.
const echoLimit = 1 << 20

// A phase is one measurement: N request-responses of the given sizes.
type phase struct {
	Name    string
	N       int
	ReqLen  int
	RespLen int
}

var phases = []phase{
	{"lat-64B", 2000, 64, 64},
	{"lat-4KiB", 1000, 4096, 4096},
	{"bulk-up-64MiB", 1, 64 << 20, 8},
	{"bulk-down-64MiB", 1, 8, 64 << 20},
}

// warmPhases run before every measured set, in both modes, so that neither is
// the one paying for slow start, a cold pump or a first page fault.
var warmPhases = []phase{
	{"warm-64B", 200, 64, 64},
	{"warm-4KiB", 100, 4096, 4096},
	{"warm-up", 1, 8 << 20, 8},
	{"warm-down", 1, 8, 8 << 20},
}

type phaseResult struct {
	Name       string  `json:"name"`
	N          int     `json:"n"`
	MedianUS   float64 `json:"median_us"`
	P90US      float64 `json:"p90_us"`
	MinUS      float64 `json:"min_us"`
	MBps       float64 `json:"mbps"`
	Mismatches int     `json:"mismatches"`
}

type runReport struct {
	Run     int           `json:"run"`
	Direct  []phaseResult `json:"direct"`
	Proxied []phaseResult `json:"proxied"`
}

type summaryRow struct {
	Phase   string  `json:"phase"`
	Metric  string  `json:"metric"`
	Direct  float64 `json:"direct"`
	Proxied float64 `json:"proxied"`
	Delta   float64 `json:"delta"`
	Ratio   float64 `json:"ratio"`
}

type report struct {
	Go       string            `json:"go"`
	QUIC     string            `json:"quic_go"`
	Kernel   string            `json:"kernel"`
	Runs     []runReport       `json:"runs"`
	Summary  []summaryRow      `json:"summary"`
	Pairwise phaseResult       `json:"socketpair_pingpong"`
	UDPProbe map[string]string `json:"udp_fd_probe"`
}

// ---------------------------------------------------------------- protocol

// exchange writes one request (an 8 byte header giving the request and the
// wanted response length, then the body) and reads the response back into
// resp. It is the whole application protocol; the same call runs on a
// *quic.Stream and on a net.Conn.
func exchange(rw io.ReadWriter, req []byte, resp []byte) error {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(req)))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(resp)))
	if _, err := rw.Write(hdr[:]); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if _, err := rw.Write(req); err != nil {
		return fmt.Errorf("writing body: %w", err)
	}
	var rh [4]byte
	if _, err := io.ReadFull(rw, rh[:]); err != nil {
		return fmt.Errorf("reading response header: %w", err)
	}
	if got := int(binary.BigEndian.Uint32(rh[:])); got != len(resp) {
		return fmt.Errorf("response length %d, wanted %d", got, len(resp))
	}
	if _, err := io.ReadFull(rw, resp); err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	return nil
}

// serveStream is the QUIC peer: it answers exchanges until the stream ends.
func serveStream(rw io.ReadWriter) error {
	pattern := make([]byte, 64<<10)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(rw, hdr); err != nil {
			return err
		}
		reqLen := int(binary.BigEndian.Uint32(hdr[0:4]))
		respLen := int(binary.BigEndian.Uint32(hdr[4:8]))
		var body []byte
		if reqLen <= echoLimit {
			body = make([]byte, reqLen)
			if _, err := io.ReadFull(rw, body); err != nil {
				return err
			}
		} else {
			n, err := io.CopyN(io.Discard, rw, int64(reqLen))
			if err != nil {
				return err
			}
			body = make([]byte, 8)
			binary.BigEndian.PutUint64(body, uint64(n))
		}
		var rh [4]byte
		binary.BigEndian.PutUint32(rh[:], uint32(respLen))
		if _, err := rw.Write(rh[:]); err != nil {
			return err
		}
		if respLen <= len(body) {
			if _, err := rw.Write(body[:respLen]); err != nil {
				return err
			}
			continue
		}
		for left := respLen; left > 0; {
			n := min(left, len(pattern))
			if _, err := rw.Write(pattern[:n]); err != nil {
				return err
			}
			left -= n
		}
	}
}

// runPhases is the client loop, run either directly on a QUIC stream or, in
// the child, on the socketpair end it was handed.
func runPhases(rw io.ReadWriter, ps []phase) ([]phaseResult, error) {
	out := make([]phaseResult, 0, len(ps))
	for _, p := range ps {
		req := make([]byte, p.ReqLen)
		resp := make([]byte, p.RespLen)
		samples := make([]float64, 0, p.N)
		mismatches := 0
		for i := 0; i < p.N; i++ {
			for j := range req {
				req[j] = byte(j + i)
			}
			start := time.Now()
			if err := exchange(rw, req, resp); err != nil {
				return nil, fmt.Errorf("%s iteration %d: %w", p.Name, i, err)
			}
			samples = append(samples, float64(time.Since(start).Nanoseconds())/1000)
			switch {
			case p.ReqLen == p.RespLen && p.ReqLen <= echoLimit:
				// Echo phase: the peer sent our own bytes back.
				if !bytes.Equal(resp, req) {
					mismatches++
				}
			case p.ReqLen > echoLimit:
				// Bulk up: the peer reports how many bytes it read.
				if binary.BigEndian.Uint64(resp) != uint64(p.ReqLen) {
					mismatches++
				}
			default:
				// Bulk down: the peer sent its pattern.
				for j := 0; j < 256; j++ {
					if resp[j] != byte(j) {
						mismatches++
						break
					}
				}
			}
		}
		sort.Float64s(samples)
		r := phaseResult{Name: p.Name, N: p.N, Mismatches: mismatches,
			MedianUS: quantile(samples, 0.5), P90US: quantile(samples, 0.9), MinUS: samples[0]}
		r.MBps = float64(max(p.ReqLen, p.RespLen)) / (r.MedianUS * 1e-6) / (1 << 20)
		out = append(out, r)
	}
	return out, nil
}

func quantile(sorted []float64, q float64) float64 {
	i := int(float64(len(sorted)-1) * q)
	return sorted[i]
}

// ------------------------------------------------------------ fd passing

// sendFD passes one descriptor plus a tag over a unix socket with SCM_RIGHTS.
func sendFD(c *net.UnixConn, fd int, tag string) error {
	_, _, err := c.WriteMsgUnix([]byte(tag), unix.UnixRights(fd), nil)
	return err
}

// recvFD is the other half: one descriptor plus its tag.
func recvFD(c *net.UnixConn) (int, string, error) {
	b := make([]byte, 64)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(b, oob)
	if err != nil {
		return -1, "", err
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) != 1 {
		return -1, "", fmt.Errorf("parsing control message: %v (%d messages)", err, len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) != 1 {
		return -1, "", fmt.Errorf("parsing rights: %v (%d fds)", err, len(fds))
	}
	return fds[0], string(b[:n]), nil
}

// connFromFD turns a received descriptor into a plain net.Conn.
func connFromFD(fd int, name string) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, errors.New("not a valid descriptor")
	}
	defer f.Close()
	return net.FileConn(f)
}

// ---------------------------------------------------------------- child

func child(ctl string) error {
	c, err := net.Dial("unix", ctl)
	if err != nil {
		return fmt.Errorf("dialing the control socket: %w", err)
	}
	uc := c.(*net.UnixConn)
	fd, tag, err := recvFD(uc)
	if err != nil {
		return fmt.Errorf("receiving the descriptor: %w", err)
	}
	fmt.Fprintf(os.Stderr, "child pid %d: received fd %d over SCM_RIGHTS, tag %q\n", os.Getpid(), fd, tag)
	enc := json.NewEncoder(uc)
	switch tag {
	case "stream":
		conn, err := connFromFD(fd, "tunnel-stream")
		if err != nil {
			return fmt.Errorf("net.FileConn: %w", err)
		}
		defer conn.Close()
		if _, err := runPhases(conn, warmPhases); err != nil {
			return fmt.Errorf("warming up: %w", err)
		}
		results, err := runPhases(conn, phases)
		if err != nil {
			return fmt.Errorf("running phases: %w", err)
		}
		return enc.Encode(results)
	case "echo":
		// The floor: what one socketpair hop costs on this host, with no
		// QUIC underneath it at all.
		conn, err := connFromFD(fd, "echo")
		if err != nil {
			return fmt.Errorf("net.FileConn: %w", err)
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn)
		return err
	case "udp":
		return enc.Encode(probeUDP(fd))
	}
	return fmt.Errorf("unknown tag %q", tag)
}

// probeUDP is step 4: the one descriptor a userspace QUIC stack does own is
// the connection's UDP socket. Hand it over and see what the receiver can do
// with it.
func probeUDP(fd int) map[string]string {
	out := map[string]string{}
	if sa, err := unix.Getsockname(fd); err == nil {
		out["getsockname"] = fmt.Sprintf("%v", sa)
	} else {
		out["getsockname_err"] = err.Error()
	}
	if typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err == nil {
		out["so_type"] = fmt.Sprintf("%d (SOCK_DGRAM=%d, SOCK_STREAM=%d)", typ, unix.SOCK_DGRAM, unix.SOCK_STREAM)
	}
	if _, err := unix.Getpeername(fd); err != nil {
		out["getpeername_err"] = err.Error()
	} else {
		out["getpeername"] = "connected"
	}
	// Try to send application bytes the way the sandbox would on a stream.
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 64)
	binary.BigEndian.PutUint32(hdr[4:8], 64)
	if n, err := unix.Write(fd, hdr[:]); err != nil {
		out["write_err"] = err.Error()
	} else {
		out["write"] = fmt.Sprintf("%d bytes accepted by the socket (as a datagram, not as stream bytes)", n)
	}
	// Try to read: whatever arrives here is a QUIC packet, and reading it
	// takes it away from the parent's QUIC stack.
	buf := make([]byte, 2048)
	if n, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
		out["recvfrom_err"] = err.Error()
	} else {
		out["recvfrom"] = fmt.Sprintf("%d bytes from %v, first bytes %x (a QUIC packet: header plus AEAD ciphertext)", n, from, buf[:min(n, 16)])
	}
	return out
}

// ---------------------------------------------------------------- parent

func parent(runs int, out string) error {
	ctx := context.Background()
	serverTLS, clientTLS, err := selfSigned()
	if err != nil {
		return err
	}

	// The QUIC peer, in this process, on a loopback UDP socket.
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	serverTr := &quic.Transport{Conn: serverUDP}
	ln, err := serverTr.Listen(serverTLS, quicConfig())
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serveStream(s)
				}
			}()
		}
	}()

	// Our own UDP socket, held explicitly so that step 4 can dup its fd.
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	clientTr := &quic.Transport{Conn: clientUDP}
	conn, err := clientTr.Dial(ctx, ln.Addr(), clientTLS, quicConfig())
	if err != nil {
		return fmt.Errorf("dialing QUIC: %w", err)
	}
	defer conn.CloseWithError(0, "")

	ctlPath := fmt.Sprintf("@ticket22-e1-%d", os.Getpid())
	ctlLn, err := net.Listen("unix", ctlPath)
	if err != nil {
		return fmt.Errorf("listening on the control socket: %w", err)
	}
	defer ctlLn.Close()

	fmt.Fprintf(os.Stderr, "parent pid %d: QUIC %s -> %s, control socket %s\n",
		os.Getpid(), clientUDP.LocalAddr(), ln.Addr(), ctlPath)
	rep := report{Go: runtime.Version(), QUIC: "quic-go v0.59.0", Kernel: uname(), UDPProbe: map[string]string{}}
	for run := 1; run <= runs; run++ {
		rr := runReport{Run: run}

		// Direct: the application is this process, on the stream itself.
		// Proxied: the application is the child, on a socketpair end this
		// process passes over to it and then pumps. The two alternate so
		// that neither is always the one on the colder connection.
		direct := func() error {
			s, err := conn.OpenStreamSync(ctx)
			if err != nil {
				return err
			}
			defer s.Close()
			if _, err := runPhases(s, warmPhases); err != nil {
				return err
			}
			rr.Direct, err = runPhases(s, phases)
			return err
		}
		proxied := func() error {
			var err error
			rr.Proxied, err = proxiedRun(ctx, conn, ctlLn, ctlPath)
			return err
		}
		order := []func() error{direct, proxied}
		if run%2 == 0 {
			order = []func() error{proxied, direct}
		}
		for _, f := range order {
			if err := f(); err != nil {
				return fmt.Errorf("run %d: %w", run, err)
			}
		}
		rep.Runs = append(rep.Runs, rr)
		fmt.Fprintf(os.Stderr, "run %d/%d done\n", run, runs)
	}

	if rep.Pairwise, err = pingPong(ctlLn, ctlPath, 2000); err != nil {
		return fmt.Errorf("socketpair ping-pong: %w", err)
	}

	// Step 4: pass the QUIC connection's UDP socket instead.
	probe, err := udpRun(clientUDP, ctlLn, ctlPath)
	if err != nil {
		return fmt.Errorf("udp fd variant: %w", err)
	}
	probe["parent_local_addr"] = clientUDP.LocalAddr().String()
	probe["parent_peer_addr"] = ln.Addr().String()
	rep.UDPProbe = probe

	rep.Summary = summarize(rep.Runs)
	printSummary(rep)
	if out != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	}
	return nil
}

// proxiedRun opens a stream, hands the child one end of a socketpair for it,
// pumps bytes both ways, and returns what the child measured.
func proxiedRun(ctx context.Context, conn *quic.Conn, ctlLn net.Listener, ctlPath string) ([]phaseResult, error) {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	local, err := connFromFD(fds[0], "pump")
	if err != nil {
		return nil, err
	}
	defer local.Close()

	cmd, ctl, err := startChild(ctlLn, ctlPath)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	if err := sendFD(ctl, fds[1], "stream"); err != nil {
		return nil, fmt.Errorf("sending the descriptor: %w", err)
	}
	unix.Close(fds[1])

	// The pump: this is the whole cost being measured. Each direction also
	// carries the end of the byte stream across the boundary — the sandbox
	// closing its socketpair end becomes a FIN on the QUIC stream, and the
	// peer finishing the stream becomes a half-close toward the sandbox —
	// because a copy loop that only moved bytes would leave each side
	// waiting on an end that never arrived.
	go func() {
		io.Copy(s, local)
		s.Close()
	}()
	go func() {
		io.Copy(local, s)
		if u, ok := local.(*net.UnixConn); ok {
			u.CloseWrite()
		}
	}()

	var results []phaseResult
	if err := json.NewDecoder(ctl).Decode(&results); err != nil {
		cmd.Wait()
		return nil, fmt.Errorf("reading the child's results: %w", err)
	}
	return results, cmd.Wait()
}

// pingPong measures a bare socketpair round trip to a child that only echoes:
// the cost of the two extra hops the proxy adds, with QUIC taken out of it.
func pingPong(ctlLn net.Listener, ctlPath string, n int) (phaseResult, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return phaseResult{}, err
	}
	local, err := connFromFD(fds[0], "pingpong")
	if err != nil {
		return phaseResult{}, err
	}
	cmd, ctl, err := startChild(ctlLn, ctlPath)
	if err != nil {
		return phaseResult{}, err
	}
	defer ctl.Close()
	if err := sendFD(ctl, fds[1], "echo"); err != nil {
		return phaseResult{}, err
	}
	unix.Close(fds[1])

	req, resp := make([]byte, 64), make([]byte, 64)
	samples := make([]float64, 0, n)
	for i := 0; i < n+200; i++ {
		for j := range req {
			req[j] = byte(j + i)
		}
		start := time.Now()
		if _, err := local.Write(req); err != nil {
			return phaseResult{}, err
		}
		if _, err := io.ReadFull(local, resp); err != nil {
			return phaseResult{}, err
		}
		if i >= 200 { // the first 200 are warmup
			samples = append(samples, float64(time.Since(start).Nanoseconds())/1000)
		}
		if !bytes.Equal(req, resp) {
			return phaseResult{}, errors.New("socketpair echo mismatch")
		}
	}
	local.Close()
	sort.Float64s(samples)
	return phaseResult{Name: "socketpair-pingpong-64B", N: n,
		MedianUS: quantile(samples, 0.5), P90US: quantile(samples, 0.9), MinUS: samples[0]}, cmd.Wait()
}

// udpRun passes the QUIC connection's own UDP socket to a child.
func udpRun(udp *net.UDPConn, ctlLn net.Listener, ctlPath string) (map[string]string, error) {
	var dup int
	rc, err := udp.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dupErr error
	if err := rc.Control(func(fd uintptr) { dup, dupErr = unix.Dup(int(fd)) }); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	defer unix.Close(dup)

	cmd, ctl, err := startChild(ctlLn, ctlPath)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	if err := sendFD(ctl, dup, "udp"); err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.NewDecoder(ctl).Decode(&out); err != nil {
		cmd.Wait()
		return nil, err
	}
	return out, cmd.Wait()
}

func startChild(ctlLn net.Listener, ctlPath string) (*exec.Cmd, *net.UnixConn, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(self, "-mode=child", "-ctl="+ctlPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	c, err := ctlLn.Accept()
	if err != nil {
		return nil, nil, err
	}
	return cmd, c.(*net.UnixConn), nil
}

// ---------------------------------------------------------------- output

func summarize(runs []runReport) []summaryRow {
	// Every cell is the median across runs of that run's own figure, so a
	// single scheduling hiccup in one run cannot carry the result.
	pick := func(i int, f func(phaseResult) float64) (float64, float64) {
		direct := make([]float64, 0, len(runs))
		proxied := make([]float64, 0, len(runs))
		for _, r := range runs {
			direct = append(direct, f(r.Direct[i]))
			proxied = append(proxied, f(r.Proxied[i]))
		}
		sort.Float64s(direct)
		sort.Float64s(proxied)
		return quantile(direct, 0.5), quantile(proxied, 0.5)
	}
	row := func(name, metric string, d, x float64) summaryRow {
		return summaryRow{Phase: name, Metric: metric, Direct: d, Proxied: x, Delta: x - d, Ratio: x / d}
	}
	var rows []summaryRow
	for i, p := range phases {
		if p.N == 1 {
			d, x := pick(i, func(r phaseResult) float64 { return r.MBps })
			rows = append(rows, row(p.Name, "throughput (MiB/s)", d, x))
			continue
		}
		d, x := pick(i, func(r phaseResult) float64 { return r.MedianUS })
		rows = append(rows, row(p.Name, "median RTT (us)", d, x))
		d, x = pick(i, func(r phaseResult) float64 { return r.MinUS })
		rows = append(rows, row(p.Name, "best RTT (us)", d, x))
		d, x = pick(i, func(r phaseResult) float64 { return r.P90US })
		rows = append(rows, row(p.Name, "p90 RTT (us)", d, x))
	}
	return rows
}

func printSummary(rep report) {
	mismatches := 0
	for _, r := range rep.Runs {
		for _, p := range append(append([]phaseResult{}, r.Direct...), r.Proxied...) {
			mismatches += p.Mismatches
		}
	}
	fmt.Printf("runs=%d  go=%s  %s  kernel=%s\n", len(rep.Runs), rep.Go, rep.QUIC, rep.Kernel)
	fmt.Printf("round-trip byte verification: %d mismatches across every phase of every run\n\n", mismatches)
	fmt.Printf("%-18s %-20s %12s %12s %12s %8s\n", "phase", "metric", "direct", "proxied", "delta", "ratio")
	for _, r := range rep.Summary {
		fmt.Printf("%-18s %-20s %12.2f %12.2f %+12.2f %8.3f\n", r.Phase, r.Metric, r.Direct, r.Proxied, r.Delta, r.Ratio)
	}
	fmt.Printf("\nbare socketpair round trip to the child, 64 B, no QUIC (the floor the proxy pays twice over):\n")
	fmt.Printf("  median %.2f us, best %.2f us, p90 %.2f us over %d round trips\n",
		rep.Pairwise.MedianUS, rep.Pairwise.MinUS, rep.Pairwise.P90US, rep.Pairwise.N)
	fmt.Printf("\nUDP socket descriptor passed to the child:\n")
	keys := make([]string, 0, len(rep.UDPProbe))
	for k := range rep.UDPProbe {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-18s %s\n", k, rep.UDPProbe[k])
	}
}

// ---------------------------------------------------------------- plumbing

func quicConfig() *quic.Config {
	// Flow control is left at quic-go's defaults: this host's
	// net.core.rmem_max is small, and forcing large windows only buys
	// socket buffer overruns that would show up as transport noise.
	return &quic.Config{MaxIdleTimeout: 60 * time.Second}
}

func selfSigned() (*tls.Config, *tls.Config, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ticket22-e1"},
		DNSNames:              []string{"ticket22-e1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	server := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}},
		NextProtos:   []string{"ticket22-e1"},
	}
	client := &tls.Config{RootCAs: pool, ServerName: "ticket22-e1", NextProtos: []string{"ticket22-e1"}}
	return server, client, nil
}

func uname() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return string(bytes.TrimRight(u.Release[:], "\x00"))
}

func main() {
	mode := flag.String("mode", "parent", "parent or child")
	ctl := flag.String("ctl", "", "control socket the child dials")
	runs := flag.Int("runs", 5, "how many times to run every phase")
	out := flag.String("out", "", "write the full report as JSON here")
	flag.Parse()

	var err error
	switch *mode {
	case "parent":
		err = parent(*runs, *out)
	case "child":
		err = child(*ctl)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *mode, err)
		os.Exit(1)
	}
}
