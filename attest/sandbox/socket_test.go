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

package sandbox_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/attest/sandbox"
)

// The contract, driven from another process.
//
// This is the case the contract exists for: spike E1 established that a QUIC
// stream cannot cross a process boundary as a descriptor, so tunneld hands over
// one end of a socketpair and pumps. What this test proves is that the three
// verbs survive the crossing — a stream opened, a stream accepted with the
// peer's identity on it, a policy pushed and answered — and that bytes and both
// ends of the byte stream come through a received descriptor intact.
//
// The tunnel under it is fake, on purpose. What an attested peer is, and what
// it takes to be admitted as one, is package tunneld's question and is tested
// there (tunneld/sandbox_test.go, over the loopback harness with the fake
// platform). What is asked here is only whether the boundary carries what it
// says it carries.

// childEnv names the socket for the re-executed test binary. Its presence is
// what turns one of these tests into the sandbox process.
const childEnv = "GVISOR_SANDBOX_CHILD_SOCKET"

// whoTheParentClaims is the identity the fake network attaches to the stream it
// hands to Accept. The child checks it field for field, so a field lost in the
// crossing fails the test rather than being quietly empty.
var whoTheParentClaims = sandbox.Attested{
	Peer:         "b",
	Vendor:       "amd-sev-snp",
	Measurement:  strings.Repeat("11", 48),
	PolicyDigest: strings.Repeat("ab", 32),
}

const (
	policyV1 = `{"format":"policy","version":1,"n":["one"],"f":["two"],"x":["three"]}`
	policyV2 = `{"format":"policy","version":2,"n":[],"f":[],"x":[]}`
)

func TestASandboxInAnotherProcessOpensAcceptsAndIsPushedAPolicy(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	fake := newFakeNetwork()
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, fake, func(format string, a ...any) { t.Logf(format, a...) })
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()
	if host.Path() != socket {
		t.Errorf("host listens on %q; want %q", host.Path(), socket)
	}

	child := exec.Command(os.Args[0], "-test.run=^TestSandboxChildProcess$", "-test.v")
	child.Env = append(os.Environ(), childEnv+"="+socket)
	var out strings.Builder
	child.Stdout, child.Stderr = &out, &out
	if err := child.Start(); err != nil {
		t.Fatalf("starting the sandbox process: %v", err)
	}
	defer func() {
		if child.Process != nil {
			child.Process.Kill()
		}
	}()

	waitFor(t, "the sandbox to attach", func() bool { return host.Attached() > 0 })

	// OPEN. The child asked for a peer; the far end of the socketpair the fake
	// network handed tunneld is this test, playing the peer.
	far := fake.nextOpened(t)
	if got, err := io.ReadAll(far); err != nil || string(got) != "ping" {
		t.Errorf("the peer received %q (%v) over the opened stream; want %q", got, err, "ping")
	}
	writeAndEnd(t, far, "pong")
	far.Close()

	// APPLY, while the child is in ACCEPT. A push must not wait behind a
	// request that is waiting for a peer.
	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Errorf("pushing a version 1 policy: %v", err)
	}
	err = host.Apply(context.Background(), []byte(policyV2))
	if !errors.Is(err, sandbox.ErrPolicyRefused) {
		t.Errorf("pushing a version 2 policy returned %v; want a refusal", err)
	}

	// ACCEPT. The stream the fake network gives out is one end of another
	// socketpair, and this test holds the other.
	near, incoming := socketpair(t)
	fake.incoming <- incoming
	writeAndEnd(t, near, "hello")
	if got, err := io.ReadAll(near); err != nil || string(got) != "world" {
		t.Errorf("the peer received %q (%v) over the accepted stream; want %q", got, err, "world")
	}
	near.Close()

	if err := child.Wait(); err != nil {
		t.Fatalf("the sandbox process failed: %v\n%s", err, out.String())
	}
	if testing.Verbose() {
		t.Logf("the sandbox process said:\n%s", out.String())
	}
}

// TestSandboxChildProcess is the sandbox, in the process the test above
// re-executed. It is skipped in every ordinary run.
func TestSandboxChildProcess(t *testing.T) {
	socket := os.Getenv(childEnv)
	if socket == "" {
		t.Skip("not the sandbox process; " + childEnv + " is unset")
	}
	// The composition a real out-of-process sandbox uses: the null sandbox over
	// the client, and the client answering pushes with the null sandbox's Apply.
	var (
		null    *sandbox.Null
		applied = make(chan error, 4)
	)
	client, err := sandbox.Dial(socket, func(ctx context.Context, policy []byte) error {
		err := null.Apply(ctx, policy)
		applied <- err
		return err
	})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()
	null = sandbox.NewNull(client, t.Logf)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	checkChildOpensAStream(t, ctx, null)
	checkChildAcceptsAStream(t, ctx, null)

	// APPLY: the version 1 policy acknowledged, the version 2 one refused.
	answered := answers(t, applied, 2)
	if answered[0] != nil {
		t.Errorf("the first push was refused: %v", answered[0])
	}
	if !errors.Is(answered[1], sandbox.ErrPolicyRefused) {
		t.Errorf("the second push returned %v; want a refusal", answered[1])
	}
	records := null.Applied()
	if len(records) != 1 {
		t.Fatalf("the null sandbox recorded %d policies; want 1", len(records))
	}
	if records[0].Format != sandbox.PolicyFormat || records[0].Version != sandbox.PolicyVersion || records[0].Bytes != len(policyV1) {
		t.Errorf("recorded %+v; want the version 1 policy of %d bytes", records[0], len(policyV1))
	}
}

// checkChildOpensAStream is the OPEN half of the child process's side of the
// contract: a stream to a known peer round-trips through the descriptor
// tunneld returned, and a peer tunneld does not know is refused with
// tunneld's own sentence rather than handed out as a stream.
func checkChildOpensAStream(t *testing.T, ctx context.Context, null *sandbox.Null) {
	t.Helper()
	stream, err := null.Open(ctx, "b")
	if err != nil {
		t.Fatalf("opening a stream to b: %v", err)
	}
	writeAndEnd(t, stream, "ping")
	if got, err := io.ReadAll(stream); err != nil || string(got) != "pong" {
		t.Errorf("the sandbox read %q (%v) from the opened stream; want %q", got, err, "pong")
	}
	stream.Close()

	// A peer tunneld will not give a stream to is an error and no stream, with
	// tunneld's own sentence in it.
	if _, err := null.Open(ctx, "nobody"); err == nil || !strings.Contains(err.Error(), "unknown peer") {
		t.Errorf("opening a stream to an unknown peer returned %v; want tunneld's refusal", err)
	}
}

// checkChildAcceptsAStream is the ACCEPT half: the accepted stream carries
// the peer's identity, and the bytes written each way round-trip across it.
func checkChildAcceptsAStream(t *testing.T, ctx context.Context, null *sandbox.Null) {
	t.Helper()
	accepted, who, err := null.Accept(ctx)
	if err != nil {
		t.Fatalf("accepting a stream: %v", err)
	}
	if who != whoTheParentClaims {
		t.Errorf("the accepted stream carried %+v; want %+v", who, whoTheParentClaims)
	}
	if got, err := io.ReadAll(accepted); err != nil || string(got) != "hello" {
		t.Errorf("the sandbox read %q (%v) from the accepted stream; want %q", got, err, "hello")
	}
	writeAndEnd(t, accepted, "world")
	accepted.Close()
}

// TestTheHostRefusesAPushWithNoSandboxAttached is the other end of the same
// claim: an acknowledgement means a sandbox has the policy, so a tunneld with
// no sandbox beside it says so rather than acknowledging on one's behalf.
func TestTheHostRefusesAPushWithNoSandboxAttached(t *testing.T) {
	host, err := sandbox.Listen(filepath.Join(t.TempDir(), "sandbox.sock"), newFakeNetwork(), nil)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer host.Close()
	if err := host.Apply(context.Background(), []byte(policyV1)); !errors.Is(err, sandbox.ErrPolicyRefused) {
		t.Errorf("pushing at nobody returned %v; want a refusal", err)
	}
	host.Close()
	if err := host.Apply(context.Background(), []byte(policyV1)); !errors.Is(err, sandbox.ErrHostClosed) {
		t.Errorf("pushing at a closed host returned %v; want ErrHostClosed", err)
	}
}

// TestListenRefusesAPathThatIsNotASocket keeps the replacement of a stale
// socket from becoming the deletion of whatever is at the path.
func TestListenRefusesAPathThatIsNotASocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}
	if host, err := sandbox.Listen(path, newFakeNetwork(), nil); err == nil {
		host.Close()
		t.Error("listening replaced a regular file")
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Errorf("the file at the path is gone: %v", err)
	}
}

// a fakeNetwork is tunneld with the tunnel taken out: every stream it hands
// over is one end of a socketpair whose other end the test drives.
type fakeNetwork struct {
	opened   chan *net.UnixConn
	incoming chan sandbox.Stream
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{opened: make(chan *net.UnixConn, 4), incoming: make(chan sandbox.Stream, 4)}
}

func (f *fakeNetwork) Open(_ context.Context, peer string) (sandbox.Stream, error) {
	if peer != "b" {
		return nil, fmt.Errorf("tunneld: unknown peer: %q is not in the peer table", peer)
	}
	near, far := socketpairConns()
	if near == nil {
		return nil, errors.New("socketpair")
	}
	f.opened <- far
	return near, nil
}

func (f *fakeNetwork) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	select {
	case s := <-f.incoming:
		return s, whoTheParentClaims, nil
	case <-ctx.Done():
		return nil, sandbox.Attested{}, ctx.Err()
	}
}

func (f *fakeNetwork) nextOpened(t *testing.T) *net.UnixConn {
	t.Helper()
	var opened *net.UnixConn
	waitFor(t, "a stream to be opened", func() bool {
		select {
		case opened = <-f.opened:
			return true
		default:
			return false
		}
	})
	return opened
}

func socketpair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, b := socketpairConns()
	if a == nil {
		t.Fatal("socketpair")
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func socketpairConns() (*net.UnixConn, *net.UnixConn) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil
	}
	var conns [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			return nil, nil
		}
		conns[i] = c.(*net.UnixConn)
	}
	return conns[0], conns[1]
}

func writeAndEnd(t *testing.T, s sandbox.Stream, what string) {
	t.Helper()
	if _, err := s.Write([]byte(what)); err != nil {
		t.Fatalf("writing %q: %v", what, err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("ending the write side after %q: %v", what, err)
	}
}

// answers waits for the sandbox to answer n pushes and returns what it said to
// each, in order.
func answers(t *testing.T, applied chan error, n int) []error {
	t.Helper()
	out := make([]error, 0, n)
	for len(out) < n {
		select {
		case err := <-applied:
			out = append(out, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("the sandbox answered %d of %d pushes", len(out), n)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestThePumpCarriesTheEndOfTheStreamEachWay is the property the two io.Copy
// goroutines exist for, checked without a process boundary in the way: a
// sandbox that half-closes is a peer that reads end-of-file, and the reverse.
func TestThePumpCarriesTheEndOfTheStreamEachWay(t *testing.T) {
	fake := newFakeNetwork()
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, fake, nil)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer host.Close()
	client, err := sandbox.Dial(socket, nil)
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	defer client.Close()

	stream, err := client.Open(context.Background(), "b")
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer stream.Close()
	far := fake.nextOpened(t)
	defer far.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The peer reads to end-of-file, which only arrives if the sandbox's
		// half-close crossed the boundary, and then answers and half-closes.
		if got, err := io.ReadAll(far); err != nil || string(got) != "request" {
			t.Errorf("the peer read %q (%v); want %q", got, err, "request")
		}
		writeAndEnd(t, far, "response")
	}()
	writeAndEnd(t, stream, "request")
	if got, err := io.ReadAll(stream); err != nil || string(got) != "response" {
		t.Errorf("the sandbox read %q (%v); want %q", got, err, "response")
	}
	wg.Wait()
}
