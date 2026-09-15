// Command control is the positive control: it sends one UDP datagram to each
// target it is given and prints the exact error, or its absence, with the
// errno spelled out.
//
// The egress probe in attest/cmd/tunneld/egress.go cannot serve as a positive
// control on its own. It writes, then reads, and a write the ceiling PERMITTED
// into a dummy interface that answers nothing ends as "TIMEOUT" — true, but it
// reads like a black hole rather than like a permission. This program stops at
// the write, where the netfilter output hook has already had its say: a write
// that returns nil is a write the ceiling let out, and a write that returns
// EPERM is the ceiling refusing.
//
// The control worth running is a pair with one bit of difference between them:
// the same address on the tunnel port and on a neighbouring port. One must
// succeed and one must fail, and no other explanation fits.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: control udp:HOST:PORT [...]")
		os.Exit(2)
	}
	bad := 0
	for _, target := range os.Args[1:] {
		network, address, ok := cut(target)
		if !ok {
			fmt.Fprintf(os.Stderr, "control: %q is not udp:HOST:PORT or tcp:HOST:PORT\n", target)
			os.Exit(2)
		}
		verdict, detail := attempt(network, address)
		if verdict != "ALLOWED" && verdict != "REFUSED" {
			bad++
		}
		fmt.Printf("CONTROL %-8s %s/%s: %s\n", verdict, network, address, detail)
	}
	os.Exit(bad)
}

func cut(s string) (network, address string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			network, address = s[:i], s[i+1:]
			return network, address, network == "udp" || network == "tcp"
		}
	}
	return "", "", false
}

// attempt stops at the write for UDP: the output hook runs there, so the write
// is where the ceiling speaks. Nothing is read back, because a reply would
// require somebody on the other end and this spike deliberately has nobody.
func attempt(network, address string) (verdict, detail string) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial(network, address)
	if err != nil {
		return classify(err), "dial: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Write([]byte("ceiling control"))
	if err != nil {
		return classify(err), "write: " + err.Error()
	}
	return "ALLOWED", fmt.Sprintf("write of %d bytes returned no error; the output hook did not refuse it", n)
}

func classify(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EACCES, syscall.EPERM, syscall.ECONNREFUSED:
			return "REFUSED"
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return "UNROUTED"
		}
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "TIMEOUT"
	}
	return "OTHER"
}
