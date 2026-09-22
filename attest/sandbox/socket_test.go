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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	client, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(ctx context.Context, policy []byte) error {
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
	began := time.Now()
	err = host.Apply(context.Background(), []byte(policyV1))
	if !errors.Is(err, sandbox.ErrPolicyRefused) {
		t.Errorf("pushing at nobody returned %v; want a refusal", err)
	}
	if !errors.Is(err, sandbox.ErrNoEnforcingSandbox) {
		t.Errorf("the refusal is %v; want it to carry the sentinel tunneld tells a peer there is nobody here by", err)
	}
	// A caller that gave neither a deadline nor a cancellation is answered at
	// once, because nothing it supplied could ever end a wait.
	if took := time.Since(began); took > time.Second {
		t.Errorf("pushing at nobody took %v; want the refusal at once", took)
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
	client, err := sandbox.Dial(socket, sandbox.RoleNetwork, nil)
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

// Liveness, contract version 3, across the same process boundary.
//
// What the three verbs could not say is that the sandbox is still enforcing
// what it acknowledged: ticket 23 measured an acknowledgement arriving 1.856 ms
// after the workload started and the workload dead at 43 ms, with the tunnel
// still up. The heartbeat is the answer, and the four cases below are the whole
// of it — it says the right thing, it stops saying it, it says the wrong thing,
// and it goes away.
//
// The sandbox is a second process for the same reason the tests above use one:
// the case the contract exists for is the one with a boundary in it, and
// "stopped pulsing without closing" and "the socket closed" are different only
// when there is a process that can be stopped without being killed.

const (
	// livenessSocketEnv names the socket for the re-executed test binary, and
	// livenessModeEnv says which sandbox it should be. Their presence is what
	// turns one of these tests into the sandbox process.
	livenessSocketEnv = "GVISOR_SANDBOX_LIVENESS_SOCKET"
	livenessModeEnv   = "GVISOR_SANDBOX_LIVENESS_MODE"
)

// anotherPolicysDigest is a well-formed digest that is not policyV1's. It
// stands for the policy some other peer pushed, or the one a sandbox went on
// enforcing after it was pushed a second.
var anotherPolicysDigest = strings.Repeat("00", 32)

func TestASandboxPulsesTheDigestOfThePolicyItAcknowledged(t *testing.T) {
	host, _ := livenessWorld(t, "hold")

	// Two watches at once, both ended by the host's own close: one for the
	// policy that was pushed, which must not fire, and one for a different
	// policy, which must — and whose sentence
	// carries the digest the sandbox actually pulsed. That sentence is how the
	// pulse is observed at all, without the host growing an accessor nothing in
	// production would use.
	right := host.Watch(context.Background(), livenessDigest(policyV1))
	wrong := host.Watch(context.Background(), anotherPolicysDigest)

	err := livenessLost(t, wrong, 2*time.Second)
	if !strings.Contains(err.Error(), livenessDigest(policyV1)) || !strings.Contains(err.Error(), "expected") {
		t.Errorf("the watch reported %q; want the digest it pulsed and the one expected", err)
	}
	livenessStillLive(t, right, 2*time.Second)
}

func TestAKilledSandboxIsAPolicyNoLongerInForce(t *testing.T) {
	host, child := livenessWorld(t, "hold")
	lost := host.Watch(context.Background(), livenessDigest(policyV1))

	began := time.Now()
	if err := child.Process.Kill(); err != nil {
		t.Fatalf("killing the sandbox: %v", err)
	}
	err := livenessLost(t, lost, 2*time.Second)
	if !strings.Contains(err.Error(), "closed its socket") {
		t.Errorf("a killed sandbox was reported as %q; want its socket closing", err)
	}
	t.Logf("a killed sandbox was a lost policy after %v", time.Since(began))
}

func TestASandboxThatStopsPulsingIsAPolicyNoLongerInForce(t *testing.T) {
	host, child := livenessWorld(t, "hold")
	lost := host.Watch(context.Background(), livenessDigest(policyV1))

	// SIGSTOP is "stopped pulsing without closing" exactly: the process is
	// there, its socket is open, and nothing comes out of it.
	began := time.Now()
	if err := unix.Kill(child.Process.Pid, unix.SIGSTOP); err != nil {
		t.Fatalf("stopping the sandbox: %v", err)
	}
	err := livenessLost(t, lost, 10*time.Second)
	took := time.Since(began)
	if !strings.Contains(err.Error(), "missed 3 pulses") {
		t.Errorf("a silent sandbox was reported as %q; want the missed pulses", err)
	}
	// Three misses of a one-second pulse, less however old the last pulse
	// already was: spike E3 measured the whole interval, 2.10 s to 3.25 s.
	if took < 1500*time.Millisecond || took > 6*time.Second {
		t.Errorf("a silent sandbox was a lost policy after %v; want about three pulses", took)
	}
	t.Logf("a silent sandbox was a lost policy after %v", took)
}

func TestASandboxPulsingAnotherPolicysDigestIsAPolicyNoLongerInForce(t *testing.T) {
	host, _ := livenessWorld(t, "wrong")
	lost := host.Watch(context.Background(), livenessDigest(policyV1))

	err := livenessLost(t, lost, 2*time.Second)
	if !strings.Contains(err.Error(), anotherPolicysDigest) || !strings.Contains(err.Error(), "expected") {
		t.Errorf("a sandbox enforcing something else was reported as %q; want what it pulsed and what was expected", err)
	}
}

// TestASandboxThatRefusedAPolicyIsNotWatched: a watch is over the sandboxes
// that acknowledged, and one that refused claimed nothing it could stop
// claiming. The host says so by reporting the loss at once rather than counting
// pulses nobody promised.
func TestASandboxThatRefusedAPolicyIsNotWatched(t *testing.T) {
	fake := newFakeNetwork()
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, fake, func(format string, a ...any) { t.Logf(format, a...) })
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()
	client, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error {
		return errors.New("this sandbox will not have it")
	})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()
	waitFor(t, "the sandbox to attach", func() bool { return host.Attached() > 0 })
	if err := host.Apply(context.Background(), []byte(policyV1)); err == nil {
		t.Fatal("the sandbox acknowledged a policy it was written to refuse")
	}
	err = livenessLost(t, host.Watch(context.Background(), livenessDigest(policyV1)), 2*time.Second)
	if err == nil {
		t.Fatal("a watch over a sandbox that acknowledged nothing reported it live")
	}
	// And it says which of the two it is. The sandbox is still sitting on the
	// socket; what it has not done is take a policy.
	if !strings.Contains(err.Error(), "no attachment has acknowledged this policy") {
		t.Errorf("the watch reported %q; want it to say nothing has acknowledged the policy", err)
	}
}

// livenessWorld is a host with a sandbox process attached to it and a policy
// acknowledged, which is the state a watch is started from.
func livenessWorld(t *testing.T, mode string) (*sandbox.Host, *exec.Cmd) {
	t.Helper()
	if os.Getenv(livenessSocketEnv) != "" {
		t.Skip("this process is the sandbox")
	}
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), func(format string, a ...any) { t.Logf(format, a...) })
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	t.Cleanup(func() { host.Close() })

	child := exec.Command(os.Args[0], "-test.run=^TestSandboxLivenessChildProcess$", "-test.v")
	child.Env = append(os.Environ(), livenessSocketEnv+"="+socket, livenessModeEnv+"="+mode)
	var out strings.Builder
	child.Stdout, child.Stderr = &out, &out
	if err := child.Start(); err != nil {
		t.Fatalf("starting the sandbox process: %v", err)
	}
	t.Cleanup(func() {
		// SIGCONT first, so that a stopped sandbox is reaped rather than left.
		child.Process.Signal(unix.SIGCONT)
		child.Process.Kill()
		child.Wait()
	})
	waitFor(t, "the sandbox to attach", func() bool { return host.Attached() > 0 })
	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("pushing the policy: %v", err)
	}
	return host, child
}

// livenessLost waits for a watch to report a loss, and fails if it does not.
func livenessLost(t *testing.T, lost <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err, ok := <-lost:
		if !ok {
			t.Fatal("the watch ended without reporting a loss")
		}
		return err
	case <-time.After(within):
		t.Fatalf("no loss of liveness was reported within %v", within)
		return nil
	}
}

// livenessStillLive is the other half: a watch over a sandbox that is pulsing
// what it acknowledged must report nothing at all.
func livenessStillLive(t *testing.T, lost <-chan error, over time.Duration) {
	t.Helper()
	select {
	case err, ok := <-lost:
		t.Errorf("a pulsing sandbox was reported lost: %v (open=%v)", err, ok)
	case <-time.After(over):
	}
}

func livenessDigest(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}

// TestSandboxLivenessChildProcess is the sandbox for the tests above, in the
// process they re-executed. It is skipped in every ordinary run.
func TestSandboxLivenessChildProcess(t *testing.T) {
	socket := os.Getenv(livenessSocketEnv)
	if socket == "" {
		t.Skip("not the sandbox process; " + livenessSocketEnv + " is unset")
	}
	acknowledged := make(chan struct{}, 1)
	client, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error {
		acknowledged <- struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()

	switch mode := os.Getenv(livenessModeEnv); mode {
	case "hold":
		// Acknowledge and pulse, and let the parent decide how it ends.
		time.Sleep(time.Minute)
	case "wrong":
		// A sandbox enforcing something other than the bytes it was handed says
		// so with Alive, which is what the supervisor in front of a sentry will
		// do with the digest the sentry answers with.
		<-acknowledged
		for {
			if err := client.Alive(anotherPolicysDigest); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

// TestTheHostSaysWhatItPushedWithItsDigest: the console line a transcript reads
// a push off is the host's too, and is the null sandbox's line field for field.
//
// It matters where the sandbox is in another process and its console is not the
// one being read — the adapter's, where tunneld's own log is the transcript. A
// harness that had to know which sandbox was beside which tunneld before it
// could find the digest would not be reading the contract.
func TestTheHostSaysWhatItPushedWithItsDigest(t *testing.T) {
	var (
		mu   sync.Mutex
		said []string
	)
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), func(format string, a ...any) {
		mu.Lock()
		said = append(said, fmt.Sprintf(format, a...))
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()
	// A sandbox that takes a version 1 policy and refuses anything else, which
	// is the whole of what the null one does with an envelope — and which says
	// so without composing a Null around the client this test does not need,
	// and so without that composition's knot (socketSandbox, cmd/agent-probe).
	client, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, policy []byte) error {
		_, err := sandbox.ReadEnvelope(policy)
		return err
	})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	defer client.Close()
	waitFor(t, "the sandbox to attach", func() bool { return host.Attached() > 0 })

	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("pushing the policy: %v", err)
	}
	if err := host.Apply(context.Background(), []byte(policyV2)); err == nil {
		t.Fatal("a version 2 policy was acknowledged")
	}

	want := fmt.Sprintf("SANDBOX applied format=%s version=%d bytes=%d sha256=%s",
		sandbox.PolicyFormat, sandbox.PolicyVersion, len(policyV1), livenessDigest(policyV1))
	mu.Lock()
	lines := append([]string(nil), said...)
	mu.Unlock()
	seen := 0
	for _, line := range lines {
		if line == want {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("the host's console has %d of %q; want exactly one, and none for the refused push:\n%s",
			seen, want, strings.Join(lines, "\n"))
	}
}

// aPushWaitingForAnEnforcingSandbox is the state the next two tests start from:
// a host with only a network client attached — the exit client, in the measured
// image — and a push held open on it under the caller's context. It returns the
// host, its socket, and where the push's answer will arrive.
func aPushWaitingForAnEnforcingSandbox(t *testing.T, ctx context.Context) (*sandbox.Host, string, chan error) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), nil)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	t.Cleanup(func() { host.Close() })
	netClient, err := sandbox.Dial(socket, sandbox.RoleNetwork, nil)
	if err != nil {
		t.Fatalf("dialing the network client: %v", err)
	}
	t.Cleanup(func() { netClient.Close() })
	waitFor(t, "the network client to attach", func() bool { return host.Attached() > 0 })

	pushed := make(chan error, 1)
	go func() { pushed <- host.Apply(ctx, []byte(policyV1)) }()
	select {
	case err := <-pushed:
		t.Fatalf("Apply returned %v with only a network client attached; want it still waiting", err)
	case <-time.After(100 * time.Millisecond):
	}
	return host, socket, pushed
}

// TestAPushThatArrivesBeforeTheEnforcingSandboxHasAttachedIsNotAcknowledgedUntilTheEnforcingSandboxHasIt
// is what an acknowledgement means on this socket. The push lands while only the
// network client is there, waits, and is answered when — and only when — the
// enforcing sandbox has the bytes.
func TestAPushThatArrivesBeforeTheEnforcingSandboxHasAttachedIsNotAcknowledgedUntilTheEnforcingSandboxHasIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, socket, pushed := aPushWaitingForAnEnforcingSandbox(t, ctx)

	applied := make(chan []byte, 1)
	enf, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, p []byte) error {
		applied <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing the enforcing client: %v", err)
	}
	defer enf.Close()

	select {
	case got := <-applied:
		if string(got) != policyV1 {
			t.Fatalf("the enforcing sandbox received %q; want %q", got, policyV1)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the enforcing sandbox did not receive the policy")
	}
	select {
	case err := <-pushed:
		if err != nil {
			t.Fatalf("the push was refused after the enforcing sandbox took it: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the push was not acknowledged after the enforcing sandbox acknowledged it")
	}
}

// TestAPushWaitingForAnEnforcingSandboxEndsWhenItsCallerGivesUp is the other
// half of the wait. A push held open for an enforcing sandbox that has not
// arrived is the caller's wait and not the host's: cancelling the caller ends it,
// and what comes back is the refusal that says what was missing.
func TestAPushWaitingForAnEnforcingSandboxEndsWhenItsCallerGivesUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, _, pushed := aPushWaitingForAnEnforcingSandbox(t, ctx)
	cancel()
	select {
	case err := <-pushed:
		if !errors.Is(err, sandbox.ErrNoEnforcingSandbox) && !errors.Is(err, context.Canceled) {
			t.Errorf("the cancelled push returned %v; want the refusal or the cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the caller did not end the wait")
	}
}

func TestAnEnforcingSandboxThatAttachesAfterAPushReceivesThePolicyInForce(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), nil)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	// Connect an enforcing client, push a policy to it, then close it.
	enf1, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, p []byte) error {
		return nil
	})
	if err != nil {
		t.Fatalf("dialing enforcing client 1: %v", err)
	}
	waitFor(t, "enforcing client 1 attached", func() bool { return host.Attached() > 0 })

	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	enf1.Close()
	waitFor(t, "enforcing client 1 gone", func() bool { return host.Attached() == 0 })

	// Connect a late enforcing sandbox. It must receive the policy in force via replay.
	replayed := make(chan []byte, 1)
	enf2, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, p []byte) error {
		replayed <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing late enforcing client: %v", err)
	}
	defer enf2.Close()

	select {
	case got := <-replayed:
		if string(got) != policyV1 {
			t.Fatalf("late enforcing sandbox received %q; want %q", string(got), policyV1)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late enforcing sandbox did not receive the policy in force")
	}
}

// TestANetworkClientIsNeverPushedAPolicy is the half of contract v4 the role
// declaration exists for. A network attachment is a channel and nothing else, so
// a policy goes to the enforcing sandbox and the network client is not woken for
// it — not even to refuse it, which would put an answer on the socket for a
// document that was never addressed to it.
func TestANetworkClientIsNeverPushedAPolicy(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), nil)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	atTheNetwork := make(chan []byte, 1)
	netClient, err := sandbox.Dial(socket, sandbox.RoleNetwork, func(_ context.Context, p []byte) error {
		atTheNetwork <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing the network client: %v", err)
	}
	defer netClient.Close()
	atTheEnforcer := make(chan []byte, 1)
	enf, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, p []byte) error {
		atTheEnforcer <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing the enforcing client: %v", err)
	}
	defer enf.Close()
	waitFor(t, "both clients to attach", func() bool { return host.Attached() == 2 })

	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("pushing the policy: %v", err)
	}
	select {
	case got := <-atTheEnforcer:
		if string(got) != policyV1 {
			t.Fatalf("the enforcing sandbox was pushed %q; want %q", got, policyV1)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the enforcing sandbox was not pushed the policy")
	}
	select {
	case got := <-atTheNetwork:
		t.Errorf("the network client was pushed %q", got)
	case <-time.After(500 * time.Millisecond):
	}

	// Nor is a network client that arrives afterwards offered the policy in
	// force: the replay is the enforcing attachment's and not any attachment's.
	netClient.Close()
	waitFor(t, "the network client to go", func() bool { return host.Attached() == 1 })
	late, err := sandbox.Dial(socket, sandbox.RoleNetwork, func(_ context.Context, p []byte) error {
		atTheNetwork <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing the late network client: %v", err)
	}
	defer late.Close()
	waitFor(t, "the late network client to attach", func() bool { return host.Attached() == 2 })
	select {
	case got := <-atTheNetwork:
		t.Errorf("a network client that attached after the push was replayed %q", got)
	case <-time.After(500 * time.Millisecond):
	}
}

// a rawClient is this socket with no [sandbox.Client] on it: the four-byte length
// and the JSON, written by hand.
//
// It is how the rules no compiler can hold a client to are driven — attach once,
// attach before anything else, name a role this host knows — because the one
// hand-written client of this contract is in runsc (runsc/cmd/tunnel_client.go),
// mirrors this wire by hand, and cannot be imported here.
type rawClient struct{ c *net.UnixConn }

func dialRaw(t *testing.T, socket string) *rawClient {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatalf("dialing %s: %v", socket, err)
	}
	t.Cleanup(func() { c.Close() })
	return &rawClient{c: c}
}

// send writes one message, exactly the bytes given.
func (r *rawClient) send(t *testing.T, message string) {
	t.Helper()
	frame := make([]byte, 4+len(message))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(message)))
	copy(frame[4:], message)
	if _, err := r.c.Write(frame); err != nil {
		t.Fatalf("sending %s: %v", message, err)
	}
}

// next is the next message the host sends back.
func (r *rawClient) next(t *testing.T) string {
	t.Helper()
	r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(r.c, header[:]); err != nil {
		t.Fatalf("reading the answer's length: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(r.c, body); err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	return string(body)
}

// TestTheHostHoldsAClientToTheAttachRules drives the three rules on the attach
// message, each of which only a client written by hand can break: attach once,
// attach before asking for anything, and name a role this host knows. Every one
// of them is refused with a sentence, and none of them leaves something the host
// would count as attached.
func TestTheHostHoldsAClientToTheAttachRules(t *testing.T) {
	const attachEnforcing = `{"id":0,"type":"attach","role":"enforcing"}`
	for _, c := range []struct {
		name string
		sent []string
		says string
	}{
		{
			name: "a second attach on one connection",
			sent: []string{attachEnforcing, attachEnforcing},
			says: "this client has already attached",
		},
		{
			name: "a stream asked for before attaching",
			sent: []string{`{"id":1,"type":"open","peer":"b"}`},
			says: "this client has not attached",
		},
		{
			name: "a role this host does not know",
			sent: []string{`{"id":0,"type":"attach","role":"bystander"}`},
			// The sentence travels as JSON, so the quotes around the role it
			// did not know arrive escaped.
			says: `unknown role \"bystander\"`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "sandbox.sock")
			host, err := sandbox.Listen(socket, newFakeNetwork(), nil)
			if err != nil {
				t.Fatalf("listening on %s: %v", socket, err)
			}
			defer host.Close()

			raw := dialRaw(t, socket)
			for _, m := range c.sent {
				raw.send(t, m)
			}
			if got := raw.next(t); !strings.Contains(got, c.says) {
				t.Errorf("the host answered %s; want it to say %q", got, c.says)
			}
			// A connection that never attached is a connection this host counts
			// as nothing, and the one that attached twice was closed for it.
			waitFor(t, "the host to count nothing attached", func() bool { return host.Attached() == 0 })
		})
	}
}

// TestALateEnforcingSandboxThatRefusesThePolicyInForceIsDropped is the replay's
// failure, which the host has to answer for itself: the sandbox that had the
// policy is gone and the one that arrived will not have it, so there is nothing
// enforcing it and the host stops saying there is. What it does not say is
// anything about a tunnel, which is the watcher's to close or not.
func TestALateEnforcingSandboxThatRefusesThePolicyInForceIsDropped(t *testing.T) {
	var (
		mu   sync.Mutex
		says strings.Builder
	)
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), func(format string, a ...any) {
		mu.Lock()
		fmt.Fprintf(&says, format+"\n", a...)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	enf1, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatalf("dialing the first enforcing client: %v", err)
	}
	waitFor(t, "the first enforcing client to attach", func() bool { return host.Attached() == 1 })
	if err := host.Apply(context.Background(), []byte(policyV1)); err != nil {
		t.Fatalf("pushing the policy: %v", err)
	}
	enf1.Close()
	waitFor(t, "the first enforcing client to go", func() bool { return host.Attached() == 0 })

	// The late one will not have it.
	enf2, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error {
		return errors.New("this sandbox will not have it")
	})
	if err != nil {
		t.Fatalf("dialing the late enforcing client: %v", err)
	}
	defer enf2.Close()
	select {
	case <-enf2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the late enforcing client that refused the policy in force was not dropped")
	}
	waitFor(t, "the late enforcing client to go", func() bool { return host.Attached() == 0 })

	mu.Lock()
	console := says.String()
	mu.Unlock()
	if !strings.Contains(console, "refused the policy in force") {
		t.Errorf("the host's console does not say the policy in force was refused:\n%s", console)
	}
	if strings.Contains(console, "no tunnel was closed") {
		t.Errorf("the host said something about a tunnel, which it knows nothing about:\n%s", console)
	}

	// Nothing is in force now, so the next enforcing sandbox is offered nothing.
	pushed := make(chan []byte, 1)
	enf3, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(_ context.Context, p []byte) error {
		pushed <- p
		return nil
	})
	if err != nil {
		t.Fatalf("dialing the third enforcing client: %v", err)
	}
	defer enf3.Close()
	waitFor(t, "the third enforcing client to attach", func() bool { return host.Attached() == 1 })
	select {
	case p := <-pushed:
		t.Errorf("a sandbox attaching after the refusal was pushed %q; want nothing in force", p)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestASecondEnforcingClientOnOneSocketIsRefusedAndANonEnforcingClientIsNot(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandbox.sock")
	host, err := sandbox.Listen(socket, newFakeNetwork(), nil)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	defer host.Close()

	// First enforcing client connects.
	enf1, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatalf("dialing first enforcing client: %v", err)
	}
	defer enf1.Close()
	waitFor(t, "first enforcing client attached", func() bool { return host.Attached() == 1 })

	// Second enforcing client tries to connect. It must be refused and its socket closed.
	enf2, err := sandbox.Dial(socket, sandbox.RoleEnforcing, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatalf("dialing second enforcing client: %v", err)
	}
	defer enf2.Close()
	select {
	case <-enf2.Done():
		if enf2.Err() == nil || !strings.Contains(enf2.Err().Error(), "a second enforcing client is not permitted on this socket") {
			t.Fatalf("second enforcing client closed with error %v; want reason saying second enforcing client is not permitted", enf2.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second enforcing client was not closed")
	}

	// A non-enforcing (network) client connects on the same socket. It must succeed.
	netClient, err := sandbox.Dial(socket, sandbox.RoleNetwork, nil)
	if err != nil {
		t.Fatalf("dialing network client: %v", err)
	}
	defer netClient.Close()
	waitFor(t, "network client attached", func() bool { return host.Attached() == 2 })

	select {
	case <-netClient.Done():
		t.Fatalf("network client was unexpectedly closed: %v", netClient.Err())
	case <-time.After(200 * time.Millisecond):
	}
}
