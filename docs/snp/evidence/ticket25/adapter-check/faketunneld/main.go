// A throwaway stand-in for tunneld, for ticket 25's adapter check.
//
// It is tunneld only in the one respect the adapter touches: it serves
// attest/sandbox's local socket, so the runsc tunnel helper — which speaks that
// protocol and nothing else — connects to it, asks for streams, and gets them.
// What is on the far end of each stream is this program's own exit, which is
// ticket 23's CONNECT/OK/REFUSED line and a dial, with no tunnel, no QUIC and
// no attestation anywhere. Nothing here is evidence about tunneld; it exists so
// that the adapter can be exercised without one.
//
//	faketunneld -socket <path> -allow host:port[,host:port...] [-peer b]
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

func main() {
	socket := flag.String("socket", "", "path of the sandbox socket to serve")
	allow := flag.String("allow", "", "comma-separated host:port the exit will dial")
	peer := flag.String("peer", "b", "the one peer name this stand-in answers Open for")
	flag.Parse()
	if *socket == "" {
		log.Fatal("faketunneld: -socket is required")
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("faketunneld: ")

	n := &network{peer: *peer, allow: map[string]bool{}}
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
	go serveExit(exit, n.allow)
	log.Printf("exit listening on %s, allow=%v", n.exit, n.allow)

	os.Remove(*socket)
	h, err := sandbox.Listen(*socket, n, func(f string, a ...any) { log.Printf(f, a...) })
	if err != nil {
		log.Fatalf("serving %s: %v", *socket, err)
	}
	defer h.Close()
	log.Printf("serving the sandbox socket at %s, peer=%q", h.Path(), *peer)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("exiting")
}

// network is the tunneld side of the contract: Open dials this program's own
// exit, which is where the CONNECT line is read.
type network struct {
	peer  string
	exit  string
	allow map[string]bool
}

func (n *network) Open(ctx context.Context, peer string) (sandbox.Stream, error) {
	if peer != n.peer {
		return nil, fmt.Errorf("no peer named %q", peer)
	}
	c, err := net.Dial("tcp", n.exit)
	if err != nil {
		return nil, err
	}
	log.Printf("opened a stream for peer %q", peer)
	return c.(*net.TCPConn), nil
}

func (n *network) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	<-ctx.Done()
	return nil, sandbox.Attested{}, ctx.Err()
}

// serveExit is ticket 23's exit, in miniature: one destination per stream, said
// on the first line, checked against a list this process was given.
func serveExit(l net.Listener, allow map[string]bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go serveConnect(c, allow)
	}
}

func serveConnect(c net.Conn, allow map[string]bool) {
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
	if !allow[target] {
		log.Printf("EXIT refused %s: it is not in the allow list", target)
		fmt.Fprintf(c, "REFUSED %s\n", target)
		return
	}
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("EXIT refused %s: %v", target, err)
		fmt.Fprintf(c, "REFUSED %s\n", target)
		return
	}
	defer remote.Close()
	if _, err := fmt.Fprintf(c, "OK %s\n", target); err != nil {
		log.Printf("EXIT could not answer for %s: %v", target, err)
		return
	}
	log.Printf("EXIT dialed %s -> %s", target, remote.RemoteAddr())
	pump(c, br, remote)
	log.Printf("EXIT %s ended", target)
}

// pump carries bytes both ways and carries each half-close with them.
func pump(c net.Conn, br *bufio.Reader, remote net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, br)
		if h, ok := remote.(halfCloser); ok {
			h.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(c, remote)
		if h, ok := c.(halfCloser); ok {
			h.CloseWrite()
		}
	}()
	wg.Wait()
}
