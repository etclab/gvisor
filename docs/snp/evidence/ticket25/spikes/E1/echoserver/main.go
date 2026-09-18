// Tiny loopback TCP echo server used by the plain-TCP phase of E1a, so that
// phase needs no internet. Prints "LISTEN <addr>" on stdout then serves
// forever (one line in, same line back, prefixed with "echo: ").
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	addr := "127.0.0.1:0"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Printf("LISTEN %s\n", ln.Addr().String())
	os.Stdout.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString('\n')
				if len(line) > 0 {
					fmt.Fprintf(c, "echo: %s", line)
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}
