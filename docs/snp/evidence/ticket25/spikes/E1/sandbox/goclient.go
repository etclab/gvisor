// Ticket 25, spike E1b. An UNMODIFIED-shaped Go client: nothing in here knows
// about the adapter. It resolves two names out of /etc/hosts, which point at the
// synthetic 100.64.0.0/10 addresses the sentry intercepts, and then does what
// any Go program does.
//
//	CGO_ENABLED=0 go build -o goclient goclient.go
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Printf("goclient: pid %d\n", os.Getpid())

	// ---- 1. a plain TCP round trip against the helper's echo server.
	fmt.Printf("\n== net.Dial tcp echo.spike.test:7777\n")
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", "echo.spike.test:7777", 10*time.Second)
	fmt.Printf("   Dial:        err=%v (%v)\n", err, time.Since(t0))
	if err != nil {
		fmt.Printf("   FAILED at Dial\n")
	} else {
		fmt.Printf("   LocalAddr:   %v\n", c.LocalAddr())
		fmt.Printf("   RemoteAddr:  %v\n", c.RemoteAddr())
		msg := "hello from go\n"
		n, err := c.Write([]byte(msg))
		fmt.Printf("   Write:       n=%d err=%v\n", n, err)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		m, err := c.Read(buf)
		fmt.Printf("   Read:        n=%d err=%v data=%q (round trip %v)\n", m, err, string(buf[:max(m, 0)]), time.Since(t0))
		// A bigger transfer, to exercise short reads and EAGAIN.
		big := make([]byte, 256*1024)
		for i := range big {
			big[i] = byte(i)
		}
		done := make(chan int, 1)
		go func() {
			got := 0
			rb := make([]byte, 32*1024)
			for got < len(big) {
				k, err := c.Read(rb)
				if k > 0 {
					got += k
				}
				if err != nil {
					fmt.Printf("   bulk read err after %d: %v\n", got, err)
					break
				}
			}
			done <- got
		}()
		t1 := time.Now()
		c.SetWriteDeadline(time.Now().Add(20 * time.Second))
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		wn, werr := c.Write(big)
		got := <-done
		fmt.Printf("   bulk:        wrote %d err=%v, echoed %d back in %v\n", wn, werr, got, time.Since(t1))
		// Half close, then expect EOF.
		if tc, ok := c.(*net.TCPConn); ok {
			cwerr := tc.CloseWrite()
			fmt.Printf("   CloseWrite:  err=%v\n", cwerr)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			k, rerr := c.Read(buf)
			fmt.Printf("   Read at EOF: n=%d err=%v\n", k, rerr)
		}
		c.Close()
	}

	// ---- 2. a real HTTPS GET, through the same machinery.
	fmt.Printf("\n== net/http GET https://www.rfc-editor.org/\n")
	t0 = time.Now()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{},
			DisableKeepAlives:   true,
			MaxIdleConns:        1,
			TLSHandshakeTimeout: 20 * time.Second,
		},
	}
	resp, err := client.Get("https://www.rfc-editor.org/")
	if err != nil {
		fmt.Printf("   GET:         err=%v (%v)\n", err, time.Since(t0))
		fmt.Printf("   FAILED at GET\n")
		return
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	fmt.Printf("   GET:         %s in %v\n", resp.Status, time.Since(t0))
	fmt.Printf("   proto:       %s  TLS=%v\n", resp.Proto, resp.TLS != nil)
	if resp.TLS != nil {
		fmt.Printf("   TLS:         version=%#x cipher=%#x server=%q\n", resp.TLS.Version, resp.TLS.CipherSuite, resp.TLS.ServerName)
		if len(resp.TLS.PeerCertificates) > 0 {
			fmt.Printf("   cert CN:     %q\n", resp.TLS.PeerCertificates[0].Subject.CommonName)
		}
	}
	fmt.Printf("   body:        %d bytes read (err=%v), first 120: %q\n", len(body), rerr, string(body[:min(len(body), 120)]))
	fmt.Printf("\ngoclient: done\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
