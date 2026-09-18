// E1a Go client: an UNMODIFIED-style Go program exercising the two code paths
// the sentry's FD-backed endpoint has to satisfy.
//
//	phase 1 (plain TCP): net.Dial("tcp", addr), write a line, read the reply,
//	                     print LocalAddr/RemoteAddr, then Close.
//	phase 2 (TLS/HTTP):  net/http default transport GET of an https URL.
//
// argv: goclient <echo addr host:port> <https url>
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: goclient <host:port> <https url>")
		os.Exit(2)
	}
	addr, url := os.Args[1], os.Args[2]

	fmt.Println("=== PHASE 1: plain TCP ===")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("PHASE1 dial error:", err)
	} else {
		fmt.Printf("PHASE1 LocalAddr=%v RemoteAddr=%v\n", c.LocalAddr(), c.RemoteAddr())
		if _, err := io.WriteString(c, "hello-from-go\n"); err != nil {
			fmt.Println("PHASE1 write error:", err)
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		fmt.Printf("PHASE1 read=%q err=%v\n", line, err)
		if err := c.Close(); err != nil {
			fmt.Println("PHASE1 close error:", err)
		}
		fmt.Println("PHASE1 OK")
	}

	fmt.Println("=== PHASE 2: net/http + crypto/tls ===")
	// E1_DIAL_IP pins the phase-2 destination to an already-resolved address so
	// that fault-injection runs are not confounded by the resolver's own
	// sockets (DNS is out of scope for E1: the adapter supplies sentry DNS).
	// The socket path is unchanged: http.Transport still calls net.Dial("tcp",
	// ip:port) through the same net/http default transport machinery, and the
	// TLS ServerName still comes from the URL.
	client := http.DefaultClient
	if ip := os.Getenv("E1_DIAL_IP"); ip != "" {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			d := &net.Dialer{Timeout: 15 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		}
		client = &http.Client{Transport: tr}
		fmt.Println("PHASE2 dial pinned to", ip)
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("PHASE2 get error:", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	resp.Body.Close()
	fmt.Printf("PHASE2 status=%s bodyprefix=%q\n", resp.Status, string(body))
	fmt.Println("PHASE2 OK")
}
