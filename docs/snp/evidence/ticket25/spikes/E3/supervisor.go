// Ticket 25, spikes E3 and E1b. The throwaway host-side supervisor ("the
// helper" of the adapter design, piece 2).
//
// It does three things:
//
//   1. connects to a running sandbox's control socket (<root>/runsc-<id>.sock)
//      and calls Spike.Attach, handing one end of a fresh socketpair to the
//      sentry through a urpc FilePayload;
//   2. serves a urpc SERVER on its own end of that socketpair, so the sentry is
//      the client and the direction of calls is sentry -> helper. The one method
//      is Helper.Open{Addr} -> FilePayload: it makes another socketpair, dials
//      the real destination on the host, pumps bytes both ways, and returns the
//      other end of the socketpair to the sentry;
//   3. runs a local TCP echo server so E3 has a destination that needs no
//      network, and maps the synthetic 100.64.0.0/10 addresses of E1b onto real
//      destinations.
//
// It deliberately imports NOTHING from gvisor: the gvisor tree only builds
// under bazel (go build fails on generated files), so the urpc wire format is
// reimplemented here. That format is small: one JSON object per message over a
// SOCK_STREAM unix socket, with any file descriptors attached as SCM_RIGHTS on
// the sendmsg that carries the message's first byte (pkg/urpc/urpc.go marshal /
// unmarshal).
//
//	go build -o supervisor supervisor.go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------- urpc wire

// clientCall / callResult mirror pkg/urpc/urpc.go.
type clientCall struct {
	Method string `json:"method"`
	Arg    any    `json:"arg"`
}

type serverCall struct {
	Method string          `json:"method"`
	Arg    json.RawMessage `json:"arg"`
}

type callResult struct {
	Success bool   `json:"success"`
	Err     string `json:"err"`
	Result  any    `json:"result"`
}

type callResultIn struct {
	Success bool            `json:"success"`
	Err     string          `json:"err"`
	Result  json.RawMessage `json:"result"`
}

// sockConn is a blocking SOCK_STREAM unix socket used directly through the
// syscalls, so the Go netpoller never touches the fd and SCM_RIGHTS is easy.
type sockConn struct {
	fd int
	mu sync.Mutex
}

func (c *sockConn) Read(p []byte) (int, error) {
	for {
		n, err := syscall.Read(c.fd, p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (c *sockConn) Close() error { return syscall.Close(c.fd) }

// sendMsg writes one JSON object, with fds attached via SCM_RIGHTS.
func (c *sockConn) sendMsg(v any, fds []int) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	n, err := syscall.SendmsgN(c.fd, data, oob, nil, 0)
	if err != nil {
		return err
	}
	for n < len(data) {
		m, err := syscall.Write(c.fd, data[n:])
		if err != nil {
			return err
		}
		n += m
	}
	return nil
}

// recvMsg reads one JSON object, extracting any SCM_RIGHTS on the first byte.
// This mirrors urpc's unmarshal(), including its habit of building a fresh
// json.Decoder per message.
func (c *sockConn) recvMsg(v any) ([]int, error) {
	first := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*128)) // urpc maxFiles == 128
	n, oobn, _, _, err := syscall.Recvmsg(c.fd, first, oob, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}
	var fds []int
	if oobn > 0 {
		scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, err
		}
		for _, scm := range scms {
			got, err := syscall.ParseUnixRights(&scm)
			if err != nil {
				continue
			}
			fds = append(fds, got...)
		}
	}
	d := json.NewDecoder(io.MultiReader(bytes.NewReader(first), c))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, err
	}
	return fds, nil
}

// call is the client half: send a call, wait for the reply.
func (c *sockConn) call(method string, arg any, result any, sendFDs []int) ([]int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.sendMsg(&clientCall{Method: method, Arg: arg}, sendFDs); err != nil {
		return nil, fmt.Errorf("send %s: %w", method, err)
	}
	var r callResultIn
	fds, err := c.recvMsg(&r)
	if err != nil {
		return nil, fmt.Errorf("recv %s: %w", method, err)
	}
	if !r.Success {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, fmt.Errorf("remote error: %s", r.Err)
	}
	if result != nil && len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, result); err != nil {
			return fds, fmt.Errorf("decode result: %w", err)
		}
	}
	return fds, nil
}

type handler func(arg json.RawMessage, fds []int) (result any, outFDs []int, err error)

// serve is the server half: one request at a time, forever.
func (c *sockConn) serve(handlers map[string]handler) {
	for {
		var sc serverCall
		fds, err := c.recvMsg(&sc)
		if err != nil {
			log.Printf("supervisor: urpc server read: %v (stream over)", err)
			return
		}
		h, ok := handlers[sc.Method]
		var res callResult
		var outFDs []int
		if !ok {
			res.Err = "unknown method " + sc.Method
		} else {
			r, ofds, herr := h(sc.Arg, fds)
			if herr != nil {
				res.Err = herr.Error()
			} else {
				res.Success = true
				res.Result = r
				outFDs = ofds
			}
		}
		if res.Result == nil {
			res.Result = struct{}{}
		}
		if err := c.sendMsg(&res, outFDs); err != nil {
			log.Printf("supervisor: urpc server write: %v", err)
			return
		}
		for _, fd := range outFDs {
			syscall.Close(fd)
		}
		log.Printf("supervisor: served %s -> success=%v err=%q fds_out=%d", sc.Method, res.Success, res.Err, len(outFDs))
	}
}

// ------------------------------------------------------------ the helper

type openArgs struct {
	Addr string `json:"Addr"`
}

type openResult struct {
	// Files is urpc.FilePayload's field; it is json:"-" on the sentry side.
	ID     int64  `json:"ID"`
	Mapped string `json:"Mapped"`
}

type closeArgs struct {
	ID   int64 `json:"ID"`
	Half int   `json:"Half"` // 0 = close both, 1 = shutdown write only
}

type stream struct {
	id      int64
	sup     int // the supervisor's end of the socketpair
	conn    net.Conn
	closed  atomic.Bool
	dst     string
	rxBytes atomic.Int64
	txBytes atomic.Int64
}

var (
	streamsMu sync.Mutex
	streams   = map[int64]*stream{}
	nextID    atomic.Int64
	addrMap   = map[string]string{}
	exitCh    = make(chan struct{})
)

func mapAddr(a string) string {
	if m, ok := addrMap[a]; ok {
		return m
	}
	return a
}

// handleOpen: make a socketpair, dial the (mapped) destination, pump, return the
// far end of the socketpair to the caller.
func handleOpen(arg json.RawMessage, _ []int) (any, []int, error) {
	var a openArgs
	if err := json.Unmarshal(arg, &a); err != nil {
		return nil, nil, err
	}
	dst := mapAddr(a.Addr)
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		log.Printf("supervisor: Helper.Open %s -> %s DIAL FAILED after %v: %v", a.Addr, dst, time.Since(t0), err)
		return nil, nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	// Give the pair generous buffers so the 1 MiB write test measures the pump,
	// not a 208 KiB default.
	for _, fd := range fds {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1<<20)
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	}
	id := nextID.Add(1)
	st := &stream{id: id, sup: fds[0], conn: conn, dst: dst}
	streamsMu.Lock()
	streams[id] = st
	streamsMu.Unlock()
	log.Printf("supervisor: Helper.Open %s -> %s connected in %v, stream %d, sentry fd will be %d",
		a.Addr, dst, time.Since(t0), id, fds[1])
	go st.pumpOut()
	go st.pumpIn()
	return &openResult{ID: id, Mapped: dst}, []int{fds[1]}, nil
}

// pumpOut: sentry -> host.
func (s *stream) pumpOut() {
	buf := make([]byte, 64*1024)
	for {
		n, err := syscall.Read(s.sup, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || n == 0 {
			log.Printf("supervisor: stream %d sentry->host ended after %d bytes (n=%d err=%v)", s.id, s.txBytes.Load(), n, err)
			if tc, ok := s.conn.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			return
		}
		s.txBytes.Add(int64(n))
		if _, werr := s.conn.Write(buf[:n]); werr != nil {
			log.Printf("supervisor: stream %d host write: %v", s.id, werr)
			return
		}
	}
}

// pumpIn: host -> sentry.
func (s *stream) pumpIn() {
	buf := make([]byte, 64*1024)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.rxBytes.Add(int64(n))
			off := 0
			for off < n {
				m, werr := syscall.Write(s.sup, buf[off:n])
				if werr == syscall.EINTR {
					continue
				}
				if werr != nil {
					log.Printf("supervisor: stream %d sentry write: %v", s.id, werr)
					return
				}
				off += m
			}
		}
		if err != nil {
			log.Printf("supervisor: stream %d host->sentry ended after %d bytes: %v", s.id, s.rxBytes.Load(), err)
			if !s.closed.Load() {
				syscall.Shutdown(s.sup, syscall.SHUT_WR)
			}
			return
		}
	}
}

// handleClose: what the sentry sees when the helper drops its end.
func handleClose(arg json.RawMessage, _ []int) (any, []int, error) {
	var a closeArgs
	if err := json.Unmarshal(arg, &a); err != nil {
		return nil, nil, err
	}
	streamsMu.Lock()
	st := streams[a.ID]
	streamsMu.Unlock()
	if st == nil {
		return nil, nil, fmt.Errorf("no stream %d", a.ID)
	}
	st.closed.Store(true)
	if a.Half == 1 {
		log.Printf("supervisor: Helper.Close stream %d: shutdown(SHUT_WR) on our end", a.ID)
		syscall.Shutdown(st.sup, syscall.SHUT_WR)
	} else {
		// shutdown() first: pumpOut is blocked in read(2) on this fd and that
		// blocked read holds a reference to the socket, so a bare close(2)
		// would NOT deliver EOF to the sentry until this process exits. (The
		// first run of E3 recorded exactly that: output-01's 35 s gap.)
		log.Printf("supervisor: Helper.Close stream %d: shutdown(SHUT_RDWR) then close() of our end, and of the host conn", a.ID)
		syscall.Shutdown(st.sup, syscall.SHUT_RDWR)
		syscall.Close(st.sup)
		st.conn.Close()
	}
	return struct{}{}, nil, nil
}

// handleExit: the helper dies, so the sentry's urpc client can be observed
// losing its peer.
func handleExit(_ json.RawMessage, _ []int) (any, []int, error) {
	log.Printf("supervisor: Helper.Exit requested; exiting in 200 ms")
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(exitCh)
	}()
	return struct{}{}, nil, nil
}

func handlePing(arg json.RawMessage, _ []int) (any, []int, error) {
	log.Printf("supervisor: Helper.Ping %s", string(arg))
	return struct{ Pong string }{"pong"}, nil, nil
}

// ------------------------------------------------------------ echo server

func startEcho() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}
				n, _ := io.Copy(c, c)
				log.Printf("supervisor: echo connection closed after %d bytes", n)
			}(c)
		}
	}()
	log.Printf("supervisor: echo server on %s", ln.Addr())
	return ln.Addr().String()
}

// ------------------------------------------------------------ main

// oPath is O_PATH; Go's syscall package does not export it.
const oPath = 0x200000

func dialUnix(path string) (*sockConn, error) {
	// UNIX_PATH_MAX is 108. runsc's own sandboxConnect() works around a longer
	// path by opening it O_PATH and connecting to /proc/self/fd/N instead
	// (runsc/sandbox/sandbox.go:851); the scratch directories here are long
	// enough to need it.
	if len(path) >= 108 {
		pfd, err := syscall.Open(path, oPath, 0)
		if err != nil {
			return nil, fmt.Errorf("O_PATH open %q: %w", path, err)
		}
		defer syscall.Close(pfd)
		path = fmt.Sprintf("/proc/self/fd/%d", pfd)
		log.Printf("supervisor: control socket path too long, connecting via %s", path)
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &sockConn{fd: fd}, nil
}

type attachArgs struct {
	EchoAddr string `json:"EchoAddr"`
	Mode     string `json:"Mode"`
}

func main() {
	ctrl := flag.String("ctrl", "", "path to the sandbox control socket")
	mode := flag.String("mode", "e3", "which in-sentry probe to run: e3 or e1b")
	extraMap := flag.String("map", "", "comma-separated synthetic=real address pairs")
	hold := flag.Duration("hold", 120*time.Second, "how long to stay alive")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetPrefix("[sup] ")

	echo := startEcho()
	addrMap["__echo__"] = echo
	if *extraMap != "" {
		for _, kv := range splitComma(*extraMap) {
			i := lastIndexByte(kv, '=')
			if i < 0 {
				log.Fatalf("bad -map entry %q", kv)
			}
			addrMap[kv[:i]] = kv[i+1:]
		}
	}
	// 100.64.0.2:7777 is E1b's loopback echo; it always points at our own.
	addrMap["100.64.0.2:7777"] = echo
	for k, v := range addrMap {
		log.Printf("supervisor: address map %s -> %s", k, v)
	}

	conn, err := dialUnix(*ctrl)
	if err != nil {
		log.Fatalf("connect to control socket %q: %v", *ctrl, err)
	}
	log.Printf("supervisor: connected to control socket %s", *ctrl)

	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Fatalf("socketpair: %v", err)
	}
	ours := &sockConn{fd: pair[0]}

	// Hand pair[1] to the sentry.
	t0 := time.Now()
	if _, err := conn.call("Spike.Attach", &attachArgs{EchoAddr: echo, Mode: *mode}, nil, []int{pair[1]}); err != nil {
		log.Fatalf("Spike.Attach: %v", err)
	}
	syscall.Close(pair[1])
	log.Printf("supervisor: Spike.Attach returned in %v", time.Since(t0))

	go ours.serve(map[string]handler{
		"Helper.Open":  handleOpen,
		"Helper.Close": handleClose,
		"Helper.Exit":  handleExit,
		"Helper.Ping":  handlePing,
	})

	select {
	case <-exitCh:
		log.Printf("supervisor: exiting on Helper.Exit")
	case <-time.After(*hold):
		log.Printf("supervisor: exiting on -hold timeout")
	}
	os.Exit(0)
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
