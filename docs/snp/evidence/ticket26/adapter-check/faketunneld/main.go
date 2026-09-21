// A throwaway stand-in for tunneld, for ticket 26's adapter check.
//
// It is ticket 25's adapter-check stand-in (docs/snp/evidence/ticket25/
// adapter-check/faketunneld) with two things added and one taken away:
//
//   - it PUSHES policies, on command, through attest/sandbox's Host.Apply, and
//     prints the acknowledgement or the refusal and how long the round trip
//     took. That is what E1 measures: the wall time from the call to its
//     return, which is everything the contract, the helper, the control socket
//     and the sentry did between them.
//   - its exit serves its own bytes rather than dialling anywhere. One name is
//     a slow HTTP body of a fixed size, so that a stream can be held open
//     across a narrowing and the byte count at the end says whether it
//     survived; every other permitted name is a short page.
//   - there is no tunnel, no QUIC and no attestation in it, and nothing here is
//     evidence about tunneld.
//
// Commands arrive on stdin, one per line, so that a shell script can time them
// against what the workload is doing:
//
//	apply <path>   push the bytes of that file, print the answer, and — on an
//	               acknowledgement — start a liveness watch on the digest the
//	               push produced, which is how the `alive` stream is seen from
//	               outside. A watch that ends prints why and when.
//	watch <digest> start a watch on a digest of the caller's choosing, which
//	               with a digest nothing is enforcing is how a mismatch is
//	               shown to be a mismatch and not a silence.
//	echo <text>    put a marker in this log
//	quit           stop
//
//	faketunneld -socket <path> -allow host:port[,...] -slow host:port
//	            -slow-bytes N -slow-chunk N -slow-pause-ms N [-peer b]
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

func main() {
	socket := flag.String("socket", "", "path of the sandbox socket to serve")
	allow := flag.String("allow", "", "comma-separated host:port the exit will answer")
	peer := flag.String("peer", "b", "the one peer name this stand-in answers Open for")
	slow := flag.String("slow", "", "the host:port whose body is served slowly")
	slowBytes := flag.Int("slow-bytes", 4<<20, "how many bytes the slow body carries")
	slowChunk := flag.Int("slow-chunk", 64<<10, "how many bytes per write of the slow body")
	slowPause := flag.Duration("slow-pause", 40*time.Millisecond, "how long between writes of the slow body")
	flag.Parse()
	if *socket == "" {
		log.Fatal("faketunneld: -socket is required")
	}
	// UTC, because the workload inside the sandbox stamps its lines in UTC and
	// the two logs are read against each other.
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	log.SetPrefix("faketunneld: ")

	n := &network{peer: *peer, allow: map[string]bool{}, slow: *slow, slowBytes: *slowBytes, slowChunk: *slowChunk, slowPause: *slowPause}
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			n.allow[a] = true
		}
	}
	exit, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("the exit listener: %v", err)
	}
	n.exit = exit.Addr().String()
	go serveExit(exit, n)
	log.Printf("exit listening on %s, allow=%v, slow=%q (%d bytes, %d per %v)", n.exit, n.allow, n.slow, n.slowBytes, n.slowChunk, n.slowPause)

	os.Remove(*socket)
	h, err := sandbox.Listen(*socket, n, func(f string, a ...any) { log.Printf(f, a...) })
	if err != nil {
		log.Fatalf("serving %s: %v", *socket, err)
	}
	defer h.Close()
	log.Printf("serving the sandbox socket at %s, peer=%q", h.Path(), *peer)

	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		verb, rest, _ := strings.Cut(line, " ")
		switch verb {
		case "apply":
			applyOne(h, strings.TrimSpace(rest))
		case "watch":
			startWatch(h, "chosen", strings.TrimSpace(rest))
		case "echo":
			log.Printf("MARK %s", rest)
		case "quit":
			log.Printf("exiting on command")
			return
		default:
			log.Printf("unknown command %q", line)
		}
	}
	log.Printf("stdin ended; exiting")
}

// applyOne pushes one policy and prints the whole of what came back.
func applyOne(h *sandbox.Host, path string) {
	policy, err := os.ReadFile(path)
	if err != nil {
		log.Printf("APPLY %s: cannot read it: %v", path, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	err = h.Apply(ctx, policy)
	elapsed := time.Since(start)
	if err != nil {
		log.Printf("APPLY %s REFUSED elapsed=%v err=%v", path, elapsed, err)
		return
	}
	sum := sha256.Sum256(policy)
	digest := hex.EncodeToString(sum[:])
	log.Printf("APPLY %s ACK elapsed=%v bytes=%d digest=%s", path, elapsed, len(policy), digest)
	startWatch(h, filepath.Base(path), digest)
}

// startWatch is the liveness half of the contract, watched from tunneld's side.
// [sandbox.Host.Watch] reports the loss of liveness for one digest: three
// missed pulses, a pulse carrying a different digest, or the socket closing.
// Nothing here decides anything — a real tunneld would refuse and close the
// tunnel — it only says what it saw and when, which is the evidence.
func startWatch(h *sandbox.Host, label, digest string) {
	if len(digest) != 64 {
		log.Printf("WATCH %s: %q is not a digest", label, digest)
		return
	}
	log.Printf("WATCH %s digest=%s started (pulse %v, %d misses)", label, digest, sandbox.DefaultPulse, sandbox.DefaultMisses)
	started := time.Now()
	lost := h.Watch(context.Background(), digest)
	go func() {
		err, ok := <-lost
		switch {
		case !ok:
			log.Printf("WATCH %s digest=%s ended with the host after %v", label, digest, time.Since(started))
		default:
			log.Printf("WATCH %s digest=%s LOST after %v: %v", label, digest, time.Since(started), err)
		}
	}()
}

// network is the tunneld side of the contract: Open dials this program's own
// exit, which is where the CONNECT line is read.
type network struct {
	peer      string
	exit      string
	allow     map[string]bool
	slow      string
	slowBytes int
	slowChunk int
	slowPause time.Duration
}

func (n *network) Open(ctx context.Context, peer string) (sandbox.Stream, error) {
	if peer != n.peer {
		return nil, fmt.Errorf("no peer named %q", peer)
	}
	c, err := net.Dial("tcp", n.exit)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func (n *network) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	<-ctx.Done()
	return nil, sandbox.Attested{}, ctx.Err()
}

// serveExit is ticket 23's exit, in miniature: one destination per stream, said
// on the first line, checked against a list this process was given. What is
// behind the destination is this program itself.
func serveExit(l net.Listener, n *network) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go serveConnect(c, n)
	}
}

func serveConnect(c net.Conn, n *network) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		log.Printf("EXIT could not read the destination: %v", err)
		return
	}
	c.SetReadDeadline(time.Time{})
	target, ok := strings.CutPrefix(strings.TrimSpace(line), "CONNECT ")
	if !ok {
		log.Printf("EXIT refused %q: it is not a destination", strings.TrimSpace(line))
		fmt.Fprintf(c, "REFUSED %s\n", strings.TrimSpace(line))
		return
	}
	if !n.allow[target] {
		log.Printf("EXIT refused %s: it is not in the allow list", target)
		fmt.Fprintf(c, "REFUSED %s\n", target)
		return
	}
	if _, err := fmt.Fprintf(c, "OK %s\n", target); err != nil {
		log.Printf("EXIT could not answer for %s: %v", target, err)
		return
	}
	// Read the request line and whatever headers follow it, and answer.
	req, err := br.ReadString('\n')
	if err != nil {
		log.Printf("EXIT %s: no request line: %v", target, err)
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(h) == "" {
			break
		}
	}
	req = strings.TrimSpace(req)
	if target == n.slow {
		log.Printf("EXIT %s serving %d bytes slowly for %q", target, n.slowBytes, req)
		served := serveSlow(c, n)
		log.Printf("EXIT %s finished after %d of %d bytes", target, served, n.slowBytes)
		return
	}
	body := fmt.Sprintf("this is %s\n", target)
	fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	log.Printf("EXIT %s served a short page for %q", target, req)
}

// serveSlow writes a body of a fixed size in chunks, with a pause between them,
// so that the stream is open for a known length of time and the number of bytes
// that arrived at the other end is a fact about the stream and not about a
// buffer.
func serveSlow(c net.Conn, n *network) int {
	if _, err := fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", n.slowBytes); err != nil {
		return 0
	}
	chunk := make([]byte, n.slowChunk)
	for i := range chunk {
		chunk[i] = byte('a' + i%26)
	}
	written := 0
	for written < n.slowBytes {
		size := n.slowChunk
		if rest := n.slowBytes - written; rest < size {
			size = rest
		}
		w, err := c.Write(chunk[:size])
		written += w
		if err != nil {
			log.Printf("EXIT slow body stopped at %d bytes: %v", written, err)
			return written
		}
		time.Sleep(n.slowPause)
	}
	return written
}
