// The Go workload of ticket 25's adapter check: an ordinary Go program that
// knows nothing about the adapter. It resolves names through whatever
// /etc/resolv.conf says, dials with net.Dial and net/http, and prints one
// tagged line per thing it tried.
//
// Nothing here names an address the sentry allocated, and nothing is pinned:
// every destination is a name or a public address, which is the point — the
// table is the only thing that decides which of them works.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

func main() {
	// 1. A name the table carries, over TLS, end to end.
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get("https://www.rfc-editor.org/")
	if err != nil {
		fmt.Printf("ALLOWED-NAME error=%v\n", err)
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 48))
		resp.Body.Close()
		fmt.Printf("ALLOWED-NAME status=%q tls=%v bodyprefix=%q\n", resp.Status, resp.TLS != nil, string(body))
	}

	// 2. The same name on a port the table does not permit.
	c, err := net.DialTimeout("tcp", "www.rfc-editor.org:80", 20*time.Second)
	if err != nil {
		fmt.Printf("WRONG-PORT error=%v errno=%s\n", err, errnoOf(err))
	} else {
		c.Close()
		fmt.Printf("WRONG-PORT connected, which it should not have\n")
	}

	// 3. A name the table carries that the far exit will not dial. The table
	// is this sentry's list and the exit has its own; a destination the far
	// side refuses is not this sentry's refusal, so it is ECONNREFUSED and no
	// event.
	c, err = net.DialTimeout("tcp", "refused.example:443", 20*time.Second)
	if err != nil {
		fmt.Printf("REFUSED-BY-EXIT error=%v errno=%s\n", err, errnoOf(err))
	} else {
		c.Close()
		fmt.Printf("REFUSED-BY-EXIT connected, which it should not have\n")
	}

	// 4. A name the table does not carry.
	addrs, err := net.LookupHost("example.com")
	fmt.Printf("UNKNOWN-NAME addrs=%v error=%v\n", addrs, err)

	// 5. A public address, named directly, with no name in it at all.
	c, err = net.DialTimeout("tcp", "8.8.8.8:443", 20*time.Second)
	if err != nil {
		fmt.Printf("RAW-ADDRESS error=%v errno=%s\n", err, errnoOf(err))
	} else {
		c.Close()
		fmt.Printf("RAW-ADDRESS connected, which it should not have\n")
	}

	// 6. A datagram to a public resolver, both ways a client sends one.
	uc, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Printf("UDP-CONNECT error=%v errno=%s\n", err, errnoOf(err))
	} else {
		n, werr := uc.Write([]byte("\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
		uc.Close()
		fmt.Printf("UDP-CONNECT connected, wrote n=%d err=%v\n", n, werr)
	}
	fmt.Printf("UDP-SENDTO %s\n", rawSendto())

	// 7. The sandbox's own loopback is not egress and must be untouched.
	l, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		fmt.Printf("LOOPBACK listen error=%v\n", lerr)
	} else {
		go func() {
			conn, err := l.Accept()
			if err == nil {
				io.Copy(conn, conn)
				conn.Close()
			}
		}()
		lc, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
		if err != nil {
			fmt.Printf("LOOPBACK dial error=%v\n", err)
		} else {
			io.WriteString(lc, "ping\n")
			buf := make([]byte, 5)
			lc.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, rerr := io.ReadFull(lc, buf)
			lc.Close()
			fmt.Printf("LOOPBACK echoed=%q n=%d err=%v\n", buf[:n], n, rerr)
		}
		l.Close()
	}
	os.Exit(0)
}

// rawSendto is the sendto(2) style of datagram: no connect, the address on
// every message. It is the one that reaches the sentry's sendmsg path.
func rawSendto() string {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Sprintf("socket error=%v", err)
	}
	defer syscall.Close(fd)
	err = syscall.Sendto(fd, []byte("\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"), 0,
		&syscall.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}, Port: 53})
	if err != nil {
		return fmt.Sprintf("error=%v errno=%s", err, errnoName(err))
	}
	return "sent, which it should not have"
}

func errnoOf(err error) string {
	var e error = err
	for e != nil {
		if se, ok := e.(syscall.Errno); ok {
			return errnoName(se)
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return "none"
		}
		e = u.Unwrap()
	}
	return "none"
}

func errnoName(err error) string {
	if e, ok := err.(syscall.Errno); ok {
		switch e {
		case syscall.ENETUNREACH:
			return "ENETUNREACH"
		case syscall.ECONNREFUSED:
			return "ECONNREFUSED"
		case syscall.EHOSTUNREACH:
			return "EHOSTUNREACH"
		default:
			return fmt.Sprintf("errno %d", int(e))
		}
	}
	return "none"
}
