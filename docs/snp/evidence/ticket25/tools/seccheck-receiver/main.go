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

// The evidence's seccheck receiver: it listens where a trace session's remote
// sink is pointed and prints one line per point.
//
// It is what examples/seccheck/server.cc is, in Go and with one point's fields
// spelled out: argv[1] is the socket to listen on, and every message becomes a
// line on stdout. It is standalone on purpose — no bazel, no module, no
// dependency but the standard library — so that a harness can build it with
// one `go build` and keep the binary beside the evidence it produced. The two
// things it has to know are small enough to write down: the remote sink's
// eight-byte header (pkg/sentry/seccheck/sinks/remote/wire), and enough of
// protobuf's wire format to walk a message made of varints and
// length-delimited fields.
//
// Usage:
//
//	seccheck-receiver <socket-path>
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// The remote sink's header. See pkg/sentry/seccheck/sinks/remote/wire.
const (
	headerStructSize = 8
	currentVersion   = 1
)

// The message types this receiver names. Everything else is printed by number.
// See gvisor.common.MessageType in pkg/sentry/seccheck/points/common.proto.
const (
	msgContainerStart      = 1
	msgSentryEgressRefused = 39
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <socket-path>\n", os.Args[0])
		os.Exit(2)
	}
	path := os.Args[1]
	// A stale socket from an earlier run would make Listen fail; the caller
	// hands a fresh path, and removing one that is not connectable is the
	// polite thing to do anyway.
	os.Remove(path)

	l, err := listenSeqPacket(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listening on %s: %v\n", path, err)
		os.Exit(1)
	}
	defer unixClose(l)
	defer os.Remove(path)

	// A killed receiver should still take its socket with it.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		unixClose(l)
		os.Remove(path)
		os.Exit(0)
	}()

	fmt.Printf("listening on %s\n", path)
	os.Stdout.Sync()
	for {
		conn, _, err := syscall.Accept(l)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			return
		}
		serve(conn)
		syscall.Close(conn)
	}
}

// listenSeqPacket binds and listens on an AF_UNIX SOCK_SEQPACKET socket, which
// is what the remote sink connects to.
func listenSeqPacket(path string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.Listen(fd, 5); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func unixClose(fd int) { syscall.Close(fd) }

// serve does the version handshake and then prints every point until the
// sentry goes away.
func serve(conn int) {
	buf := make([]byte, 1<<16)
	n, err := syscall.Read(conn, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "handshake: %v\n", err)
		return
	}
	var hs message
	hs.parse(buf[:n])
	fmt.Printf("connected: the sentry speaks wire version %d\n", hs.varint(1))
	// gvisor.common.Handshake{version: 1}: field 1, varint, value 1.
	if _, err := syscall.Write(conn, []byte{0x08, currentVersion}); err != nil {
		fmt.Fprintf(os.Stderr, "handshake reply: %v\n", err)
		return
	}
	for {
		n, err := syscall.Read(conn, buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			return
		}
		if n == 0 {
			fmt.Printf("disconnected\n")
			return
		}
		print(buf[:n])
	}
}

// print turns one message into one line.
func print(b []byte) {
	if len(b) < headerStructSize {
		fmt.Printf("short message: %d bytes\n", len(b))
		return
	}
	headerSize := binary.LittleEndian.Uint16(b[0:2])
	msgType := binary.LittleEndian.Uint16(b[2:4])
	dropped := binary.LittleEndian.Uint32(b[4:8])
	if int(headerSize) > len(b) {
		fmt.Printf("message claims a %d byte header in %d bytes\n", headerSize, len(b))
		return
	}
	payload := b[headerSize:]
	switch msgType {
	case msgSentryEgressRefused:
		fmt.Println(egressRefused(payload, dropped))
	case msgContainerStart:
		fmt.Printf("container_start dropped=%d\n", dropped)
	default:
		fmt.Printf("message type=%d bytes=%d dropped=%d\n", msgType, len(payload), dropped)
	}
	os.Stdout.Sync()
}

// egressRefused formats a sentry/egress_refused point. The field numbers are
// EgressRefused's in pkg/sentry/seccheck/points/sentry.proto.
func egressRefused(b []byte, dropped uint32) string {
	var m message
	m.parse(b)
	var ctx message
	ctx.parse(m.bytes(1))
	var sb strings.Builder
	sb.WriteString("egress_refused")
	fmt.Fprintf(&sb, " protocol=%s", quoteEmpty(m.str(2)))
	if a := m.str(3); a != "" {
		fmt.Fprintf(&sb, " address=%s", a)
	}
	if p := m.varint(4); p != 0 {
		fmt.Fprintf(&sb, " port=%d", p)
	}
	if n := m.str(5); n != "" {
		fmt.Fprintf(&sb, " name=%s", n)
	}
	fmt.Fprintf(&sb, " reason=%s", quoteEmpty(m.str(6)))
	if t := ctx.varint(1); t != 0 {
		fmt.Fprintf(&sb, " time=%s", time.Unix(0, int64(t)).UTC().Format(time.RFC3339Nano))
	}
	if id := ctx.str(6); id != "" {
		fmt.Fprintf(&sb, " container_id=%s", id)
	}
	if tid := ctx.varint(2); tid != 0 {
		fmt.Fprintf(&sb, " thread_id=%d", tid)
	}
	if dropped != 0 {
		fmt.Fprintf(&sb, " dropped=%d", dropped)
	}
	return sb.String()
}

func quoteEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

// ===== just enough protobuf =====

// A message is one decoded protobuf message: field number to the last value
// seen for it. Nothing here repeats, so last-wins is the whole merge rule.
type message struct {
	varints map[int]uint64
	lens    map[int][]byte
}

// parse walks b, skipping anything it does not understand.
func (m *message) parse(b []byte) {
	m.varints = map[int]uint64{}
	m.lens = map[int][]byte{}
	for i := 0; i < len(b); {
		tag, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return
		}
		i += n
		field, kind := int(tag>>3), int(tag&7)
		switch kind {
		case 0: // varint
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return
			}
			m.varints[field] = v
			i += n
		case 1: // 64-bit
			if i+8 > len(b) {
				return
			}
			m.varints[field] = binary.LittleEndian.Uint64(b[i : i+8])
			i += 8
		case 2: // length-delimited
			l, n := binary.Uvarint(b[i:])
			if n <= 0 || i+n+int(l) > len(b) {
				return
			}
			i += n
			m.lens[field] = b[i : i+int(l)]
			i += int(l)
		case 5: // 32-bit
			if i+4 > len(b) {
				return
			}
			m.varints[field] = uint64(binary.LittleEndian.Uint32(b[i : i+4]))
			i += 4
		default:
			return
		}
	}
}

func (m *message) varint(field int) uint64 { return m.varints[field] }
func (m *message) bytes(field int) []byte  { return m.lens[field] }
func (m *message) str(field int) string    { return string(m.lens[field]) }
