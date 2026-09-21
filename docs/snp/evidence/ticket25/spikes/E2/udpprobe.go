// Ticket 25, spike E2. Runs INSIDE a runsc sandbox booted with --network=none.
// It asks one question four ways: where does a UDP datagram go, and what errno
// does the caller see? The payload is a real DNS A query for example.com so the
// bytes the sentry sees are the bytes the adapter will have to look at.
//
// Static build, no cgo:  CGO_ENABLED=0 go build -o udpprobe udpprobe.go
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// dnsQuery is a real DNS A query for example.com: id 0x1234, RD set, one question.
func dnsQuery() []byte {
	q := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // flags: RD
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // qtype A, qclass IN
	return q
}

func errStr(err error) string {
	if err == nil {
		return "OK"
	}
	if e, ok := err.(syscall.Errno); ok {
		return fmt.Sprintf("errno=%d %s (%q)", int(e), errnoName(int(e)), e.Error())
	}
	return fmt.Sprintf("err=%v (%T)", err, err)
}

func errnoName(n int) string {
	names := map[int]string{
		1: "EPERM", 9: "EBADF", 11: "EAGAIN", 13: "EACCES", 14: "EFAULT",
		22: "EINVAL", 32: "EPIPE", 88: "ENOTSOCK", 91: "EPROTOTYPE",
		92: "ENOPROTOOPT", 93: "EPROTONOSUPPORT", 95: "EOPNOTSUPP",
		97: "EAFNOSUPPORT", 98: "EADDRINUSE", 99: "EADDRNOTAVAIL",
		100: "ENETDOWN", 101: "ENETUNREACH", 102: "ENETRESET",
		103: "ECONNABORTED", 104: "ECONNRESET", 105: "ENOBUFS",
		106: "EISCONN", 107: "ENOTCONN", 110: "ETIMEDOUT",
		111: "ECONNREFUSED", 112: "EHOSTDOWN", 113: "EHOSTUNREACH",
		114: "EALREADY", 115: "EINPROGRESS",
	}
	if s, ok := names[n]; ok {
		return s
	}
	return "?"
}

func sa(ip string, port int) *syscall.SockaddrInet4 {
	s := &syscall.SockaddrInet4{Port: port}
	copy(s.Addr[:], net.ParseIP(ip).To4())
	return s
}

// rawUDP: one socket, one datagram, one recv attempt with a 2 s SO_RCVTIMEO.
// connected == true does connect(2)+write(2)+read(2) (what Go's net.UDPConn does);
// connected == false does sendto(2)+recvfrom(2).
func rawUDP(ip string, port int, connected bool) {
	mode := "sendto/recvfrom (unconnected)"
	if connected {
		mode = "connect+write/read (connected)"
	}
	fmt.Printf("\n== UDP %s:%d  %s\n", ip, port, mode)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Printf("   socket:   %s\n", errStr(err))
		return
	}
	defer syscall.Close(fd)
	tv := syscall.Timeval{Sec: 2}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		fmt.Printf("   SO_RCVTIMEO: %s\n", errStr(err))
	}
	q := dnsQuery()
	dst := sa(ip, port)

	if connected {
		t0 := time.Now()
		err = syscall.Connect(fd, dst)
		fmt.Printf("   connect:  %s  (%.1f ms)\n", errStr(err), float64(time.Since(t0).Microseconds())/1000)
		if err != nil {
			return
		}
		t0 = time.Now()
		n, err := syscall.Write(fd, q)
		fmt.Printf("   write:    n=%d %s  (%.1f ms)\n", n, errStr(err), float64(time.Since(t0).Microseconds())/1000)
		if err != nil {
			return
		}
	} else {
		t0 := time.Now()
		err = syscall.Sendto(fd, q, 0, dst)
		fmt.Printf("   sendto:   %s  (%.1f ms)\n", errStr(err), float64(time.Since(t0).Microseconds())/1000)
		if err != nil {
			return
		}
	}

	buf := make([]byte, 1500)
	t0 := time.Now()
	var n int
	var from syscall.Sockaddr
	if connected {
		n, err = syscall.Read(fd, buf)
	} else {
		n, from, err = syscall.Recvfrom(fd, buf, 0)
	}
	fmt.Printf("   recv:     n=%d %s  (%.0f ms) from=%v\n", n, errStr(err), float64(time.Since(t0).Microseconds())/1000, from)
	if n > 0 {
		fmt.Printf("   bytes:    % x\n", buf[:min(n, 64)])
	}
	// A second recv: an ICMP port unreachable is reported on the NEXT operation.
	if connected && err == nil {
		// nothing
	} else if connected {
		t0 = time.Now()
		n2, err2 := syscall.Read(fd, buf)
		fmt.Printf("   recv#2:   n=%d %s  (%.0f ms)\n", n2, errStr(err2), float64(time.Since(t0).Microseconds())/1000)
	}
}

// goUDP is the same thing through Go's net package, the way a real client does it.
func goUDP(ip string, port int) {
	fmt.Printf("\n== UDP %s:%d  net.DialUDP\n", ip, port)
	raddr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	t0 := time.Now()
	c, err := net.DialUDP("udp4", nil, raddr)
	fmt.Printf("   DialUDP:  %s  (%.1f ms)\n", errStr(err), float64(time.Since(t0).Microseconds())/1000)
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Printf("   local:    %v  remote: %v\n", c.LocalAddr(), c.RemoteAddr())
	n, err := c.Write(dnsQuery())
	fmt.Printf("   Write:    n=%d %s\n", n, errStr(err))
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	t0 = time.Now()
	n, err = c.Read(buf)
	fmt.Printf("   Read:     n=%d %s  (%.0f ms)\n", n, errStr(err), float64(time.Since(t0).Microseconds())/1000)
	if n > 0 {
		fmt.Printf("   bytes:    % x\n", buf[:min(n, 64)])
	}
}

func rawTCP(ip string, port int) {
	fmt.Printf("\n== TCP %s:%d  socket+connect (blocking)\n", ip, port)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("   socket:   %s\n", errStr(err))
		return
	}
	defer syscall.Close(fd)
	t0 := time.Now()
	err = syscall.Connect(fd, sa(ip, port))
	fmt.Printf("   connect:  %s  (%.0f ms)\n", errStr(err), float64(time.Since(t0).Microseconds())/1000)
	if err == nil {
		lsa, lerr := syscall.Getsockname(fd)
		fmt.Printf("   getsockname: %v %s\n", lsa, errStr(lerr))
	}
}

func goTCP(ip string, port int) {
	fmt.Printf("\n== TCP %s:%d  net.DialTimeout 3s\n", ip, port)
	t0 := time.Now()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
	fmt.Printf("   Dial:     %s  (%.0f ms)\n", errStr(err), float64(time.Since(t0).Microseconds())/1000)
	if err == nil {
		fmt.Printf("   local=%v remote=%v\n", c.LocalAddr(), c.RemoteAddr())
		c.Close()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Printf("udpprobe: ticket 25 E2, pid %d\n", os.Getpid())
	fmt.Printf("DNS A query for example.com, %d bytes: % x\n", len(dnsQuery()), dnsQuery())
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		fmt.Printf("iface %d %-8s flags=%v addrs=%v mtu=%d\n", i.Index, i.Name, i.Flags, addrs, i.MTU)
	}

	targets := []struct {
		ip   string
		port int
	}{
		{"127.0.0.53", 53},
		{"127.0.0.1", 53},
		{"8.8.8.8", 53},
		{"10.0.0.1", 53},
	}
	fmt.Printf("\n######## part 1: unconnected sendto\n")
	for _, t := range targets {
		rawUDP(t.ip, t.port, false)
	}
	fmt.Printf("\n######## part 2: connected UDP (connect + write)\n")
	for _, t := range targets {
		rawUDP(t.ip, t.port, true)
	}
	fmt.Printf("\n######## part 3: Go's net.DialUDP\n")
	for _, t := range targets {
		goUDP(t.ip, t.port)
	}
	fmt.Printf("\n######## part 4: the TCP baseline — every other connect fails\n")
	rawTCP("127.0.0.1", 9)
	rawTCP("8.8.8.8", 53)
	goTCP("127.0.0.1", 9)
	goTCP("8.8.8.8", 53)
	fmt.Printf("\nudpprobe: done\n")
}
