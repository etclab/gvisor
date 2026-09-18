# E3 — PASS. The two pieces meet over urpc + FilePayload, with no new transport

Ticket 25, experiment 3. Workstation only, 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t25`, branch `ticket-25-the-adapter-intercept-and-handoff`.
No sudo, no hardware, host-side only. The sandbox is booted with S1's flag set,
unchanged (`--platform=systrap --network=none --ignore-cgroups --rootless
--gofer-network-namespace=new`), plus `--debug --debug-log=<dir>/`.

    runsc sha256      ec1d47fa1bd3b521c53dccf5b31d9a286a8babbafd64357849b408e651bf085b
    supervisor sha256 a0c231bf87d32009611240365172f92a397185f004988793f8690b60e9553ab9

## What was asked

Do piece (1), a Tunnel object on the sandbox's control server, and piece (2), a
host-side helper, meet over urpc + FilePayload without any new transport, in the
**sentry → helper** direction, under the sentry's seccomp filter? With sizes,
timings, and what the sentry sees when the helper goes away.

## What was done

- `patch-01-spike-urpc-object.diff` — the throwaway sentry side: a new
  `runsc/boot/spike_e3.go` registering `Spike` on the control server
  (`controller.go:250`, one line, beside `&debug{}`), plus the file's `srcs`
  entry in `runsc/boot/BUILD`. `Spike.Attach(*spikeAttachArgs)` embeds
  `urpc.FilePayload`, `unix.Dup`s the one FD it receives (urpc closes the
  received files when the call returns) and hands it to a goroutine that builds
  `urpc.NewClient(unet.NewSocket(fd))` — so the sentry is the **client** and the
  helper the **server** on that socketpair. The patch is reverted; only the
  `.diff` remains.
- `supervisor.go` — the host-side helper. It imports **nothing** from gvisor:
  the tree only builds under bazel, so urpc's wire format is reimplemented in
  ~150 lines (one JSON object per message over a `SOCK_STREAM` unix socket, FDs
  attached as `SCM_RIGHTS` on the sendmsg that carries the first byte — exactly
  `pkg/urpc/urpc.go` `marshal`/`unmarshal`). It connects to
  `<root>/runsc-<id>.sock`, calls `Spike.Attach` with one end of a socketpair,
  serves `Helper.{Ping,Open,Close,Exit}` on the other end, and runs a local TCP
  echo server as the destination.
  It needed runsc's own long-path workaround (`sandbox.go:851`): the scratch
  paths here exceed `UNIX_PATH_MAX` (108), so it opens the socket `O_PATH` and
  connects to `/proc/self/fd/N` (output-03:9).
- `run-e3.sh <runsc> <workdir> <supervisor>` reproduces the run.

**Two runs are kept.** The first (output-01, output-02) is wrong and is kept
because its failure is instructive: `Helper.Close` did a bare `close(2)` on the
helper's end while the pump goroutine was still blocked in `read(2)` on that fd.
The blocked read holds a reference to the socket, so **no EOF reached the sentry
until the helper process exited** — a 35 s gap in the sentry's log
(output-02: the close test's timestamps are 07:57:42, the close was at
07:57:07). The fix is `shutdown(SHUT_RDWR)` before `close(2)`. A helper that
wants the sandbox to see a stream end **must shut the socket down, not merely
close its descriptor**, if any of its own threads may be parked on that fd.
Run 2 (output-03, output-04) is the measurement.

## The recorded answers

**1. The round trip works, both directions, under the sentry's filter.**
The FD crossed in (`Spike.Attach`, o3:12, o4:559), the sentry built a urpc client
on it (o4:562), and the first call came straight back (o4:565):

    Attach: received one FD, duped to 30, echo="127.0.0.1:46643" mode="e3"
    begin: urpc client built on the donated socketpair, under the sentry's seccomp filter
    step0 Ping: err=<nil> rtt=923.767µs pong="pong"

Nothing in the seccomp filter had to change. This is the precedent
`runsc/boot/controller.go:755` already sets (stateipc's client), confirmed for a
client the sentry builds itself at run time on a donated FD: `sendmsg` with
`MSG_DONTWAIT|MSG_NOSIGNAL`, `recvmsg` with `MSG_DONTWAIT|MSG_TRUNC`, `read`,
`write`, `dup`, `close`, `fcntl(F_GETFL/F_SETFL)` and `epoll_*` are all in the
default (non-hostinet) allow list; `unet.NewSocket` only needs `F_SETFL` and an
eventfd, both allowed.

**2. An FD came back out, and it carries real bytes.** `Helper.Open` dialled the
echo on the host, made a fresh socketpair, and returned one end as a
`FilePayload` result (o3:15-16, o4:568):

    Open(127.0.0.1:46643) stream1: OK rtt=1.342841ms id=1 mapped=127.0.0.1:46643 fd=32

`Helper.Open`'s whole cost, dial included, was **1.34 ms** measured in the sentry
(the host-side dial itself 586 µs, o3:15).

**3. Sizes and timings** (o4:569-571):

| what | sentry write | echo round trip |
|---|---|---|
| `"hello\n"`, 6 bytes | — | **827 µs** |
| 64 KiB | 111 µs, 562.6 MiB/s | 1.84 ms, 33.9 MiB/s |
| 1 MiB | 5.26 ms, 190.1 MiB/s | 8.62 ms, 116.0 MiB/s |

**Writes block; they do not return EAGAIN.** For both bulk sizes the counters are
`EAGAIN=0 shortWrites=0` — the FD arrives **blocking** (`F_GETFL=0x2`, i.e.
`O_RDWR` with no `O_NONBLOCK`, o4:580), and a blocking `write(2)` on it simply
waits for the helper's pump to drain. When the sentry sets `O_NONBLOCK` itself
(allowed: `fcntl` `F_SETFL` is in the filter), the pipeline's capacity shows:
**EAGAIN after 444,864 bytes in 2 calls** (o4:582) with nothing draining, and a
non-blocking read of an empty socket returns `EAGAIN` (o4:583). So an FD-backed
endpoint can be driven either way; the choice is the sentry's.

**4. What the sentry sees when the helper drops the stream** (o4:574-576):

    close: asked the helper to close its end of stream 1: err=<nil>
    close: read #0 after the helper closed: n=0 err=<nil>          <- EOF, clean
    close: write #0 after the helper closed: n=-1 err=broken pipe  <- EPIPE

EOF on read, `EPIPE` on write — not `ECONNRESET`, because this is an `AF_UNIX`
socketpair and not a TCP socket. An adapter that must present `ECONNRESET` to the
sandbox has to synthesise it; the transport will not supply it.

**5. What happens to the urpc client when the helper exits** (o4:586-593):
`Helper.Exit` itself returns cleanly (`err=<nil>`, 558 µs) because the helper
replies before exiting; every later call fails **immediately** with `EPIPE`
(`syscall.Errno`), 347 µs and 65 µs — it does not hang, and it does not block the
sentry. Note the shape of the failure: it is a raw `syscall.Errno` from the write
of the request, not a `urpc.RemoteError`, so a caller that only inspects
`RemoteError` will misread a dead helper as a transport bug. Note also that the
data FD of stream 2, opened before the exit, kept working right up to the moment
the helper died (o3:26-28) — the data path and the control path fail
independently.

## Verdict

**Yes.** Piece (1) and piece (2) meet over urpc + `FilePayload` in the
sentry → helper direction, under the sentry's existing seccomp filter, with **no
new transport, no new syscall in the allow list, and no change to runsc's
plumbing** beyond registering one object on the control server. An FD donated in
through `Spike.Attach` becomes a working urpc client inside the sentry; an FD
returned out of `Helper.Open` is an ordinary socketpair end that the sentry reads
and writes with `read(2)`/`write(2)` at **116 MiB/s round trip through a host TCP
hop**, blocking or non-blocking as it chooses, with a sub-millisecond call
latency for the handoff itself.

Two things the design must carry from here. The helper must `shutdown(2)` before
`close(2)`, or the sandbox will not see the stream end (run 1). And the stream is
an `AF_UNIX` socketpair, so its native end-of-life signals are EOF and `EPIPE`:
anything TCP-shaped the sandbox expects — `ECONNRESET`, `SO_ERROR`, a peer
address — must be supplied by the endpoint in the sentry, which is exactly what
E1b goes on to test.
