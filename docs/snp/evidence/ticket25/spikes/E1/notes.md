# E1a — what an unmodified Go and an unmodified Node program actually do to a connected TCP socket

Host half of ticket 25's experiment E1, run on the host, outside any sandbox,
on 2026-09-18.  Everything here is reproduced by `./run.sh`.

E1 asks whether the sentry's planned **FD-backed endpoint** — an AF_UNIX
socketpair end handed in by the supervisor and dressed up so the program still
sees an AF_INET SOCK_STREAM socket — is enough for an unmodified runtime, or
whether the endpoint has to be a real netstack socket.  The sentry can answer
any socket-level call however it likes, so the question reduces to: *which
calls does each runtime make on a connected TCP socket, in what order, what
does it do with each answer, and which answers can it not tolerate being wrong
or refused?*  E1a measures the calls and the tolerances on the host with
`strace`; the sentry half (E1b) is separate.

## Setup

| thing | value |
|---|---|
| Go | go1.26.3 linux/amd64 (`/usr/local/go/bin/go` is a 1.22.3 shim that dispatches to the `go1.26.3` toolchain in the module cache; `run.sh` pins `GOTOOLCHAIN=go1.26.3`) |
| Go source quoted below | `/home/pniroula/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.linux-amd64/src/net/` — **not** `/usr/local/go/src`, which is the 1.22.3 shim's source |
| Node | v18.19.1, libuv **1.48.0**, OpenSSL 3.0.13 (`/usr/bin/node`) |
| libuv/Node source quoted below | `/nix/store/0dybxj9f9navs638ndxfsbjsp1y0dbq2-node-sources/` — that tree is Node **20.14.0 / libuv 1.46.0**.  The two functions quoted (`uv__tcp_connect`, `uv__stream_connect`) and `AddressToJS` are unchanged between 1.46 and 1.48 / Node 18 and 20 in every respect that matters here, and every claim drawn from them is corroborated by the traces. |
| strace | 6.8 |
| clients | `goclient/main.go`, `nodeclient.js`; loopback echo server `echoserver/main.go` |
| phase 1 | plain TCP to the loopback echo server (no internet) |
| phase 2 | `https://www.rfc-editor.org/` — TLS 1.3 + HTTP/1.1, 200 OK |

Two harness details, both deliberate:

* **`E1_DIAL_IP`.** `strace -e inject=` is process-wide, so an unpinned
  injection run would also break the *resolver's* sockets and confound the
  result.  DNS is out of scope for E1 (the adapter supplies sentry DNS), so
  runs 05–19 pre-resolve the phase-2 host and hand the already-resolved address
  to `http.Transport.DialContext` (Go) / the `lookup` option (Node).  Only the
  lookup step changes; the socket sequence is byte-for-byte the one in the
  unpinned baselines (compare run 01 lines 114–126 with run 05).
* **`EOPNOTSUPP` instead of `ENOTSUP`.** strace 6.8 rejects the name `ENOTSUP`
  (`strace: invalid inject argument 'getsockname:error=ENOTSUP'`, see the first
  aborted attempt).  On Linux `ENOTSUP == EOPNOTSUPP == 95`, so run 07/13 are
  spelled `EOPNOTSUPP` and mean exactly ENOTSUP.

## 1. Per-runtime call table (connected TCP socket)

Line numbers are lines of the named `output-NN-*.txt`, which contain the client's
stdout followed by the untrimmed strace.

### Go 1.26.3 — `net.Dial` / `net/http` / `crypto/tls`

| step | call, exactly as traced | where | notes |
|---|---|---|---|
| create | `socket(AF_INET, SOCK_STREAM\|SOCK_CLOEXEC\|SOCK_NONBLOCK, IPPROTO_IP)` | 01:32, 01:114 | both flags always set; no `fcntl(F_SETFL)` follow-up, **no `ioctl` on the socket, ever** (grep for `ioctl(N<TCP` across all 19 outputs returns nothing) |
| pre-connect setsockopt | none for AF_INET/SOCK_STREAM | — | `setDefaultSockopts` only touches `IPV6_V6ONLY` (AF_INET6) and `SO_BROADCAST` (DGRAM/RAW), `net/sockopt_linux.go:12-24` |
| connect | `connect(...) = -1 EINPROGRESS` | 01:33, 01:115 | **EINPROGRESS even on loopback**; the 0-return path is handled too, see §3 |
| register | `epoll_ctl(EPOLL_CTL_ADD, fd, EPOLLIN\|EPOLLOUT\|EPOLLRDHUP\|**EPOLLET**)` | 01:36, 01:117 | one registration covers read, write and connect-completion; **edge-triggered** |
| wait | `epoll_pwait(...) = [{events=EPOLLOUT}]` | 01:39 | |
| completion | `getsockopt(SOL_SOCKET, SO_ERROR) = [0]` | 01:41/43, 01:119 | exactly 2 in the whole run, one per dial |
| peer | `getpeername(...) = 0` | 01:44, 01:120 | `net/fd_unix.go:139` — the connect loop **requires** this to succeed, see §2 |
| local | `getsockname(...) = 0` | 01:45, 01:121 | `net/sock_posix.go:139`; error discarded there, but the *value* is load-bearing, see §2 |
| post-connect setsockopt | `TCP_NODELAY=1`, `SO_KEEPALIVE=1`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT=9` | 01:46-50 (idle 15s), 01:122-126 (idle 30s, the Transport's) | 5 per socket; `net/tcpsock.go:289-306` |
| data | plain `read(2)` / `write(2)` only | 03:60, 03:62 (phase 1); 03:163-1270 (TLS) | **no `writev`/`sendmsg`/`recvmsg`/`sendto`/`recvfrom` at all**; short reads and `EAGAIN` are normal (03:164) |
| close | `epoll_ctl(EPOLL_CTL_DEL)` then `close(2)` | 01:53, 01:54 | **Go never calls `shutdown(2)`** — `grep -c 'shutdown('` is 0 in runs 01, 03 and 12 |
| TLS phase difference | none at the socket level | | same socket calls, only the payload differs; the idle keep-alive connection is simply left open at exit (no `close` of the phase-2 fd in run 01) |

### Node 18.19.1 / libuv 1.48 — `net.connect` / `https.get`

| step | call, exactly as traced | where | notes |
|---|---|---|---|
| create | `socket(AF_INET, SOCK_STREAM\|SOCK_CLOEXEC\|SOCK_NONBLOCK, IPPROTO_IP)` | 02:79, 02:138 | identical to Go |
| connect | `connect(...) = -1 EINPROGRESS` | 02:80, 02:139 | libuv also accepts a 0 return, see §3 |
| register | **submitted through io_uring, not `epoll_ctl(2)`** | 19:91 `io_uring_enter(19<io_uring>, 3, 3, IORING_ENTER_GETEVENTS)` right after the connect at 19:90 | libuv ≥1.46 batches `EPOLL_CTL_ADD/MOD` into its ring; that is why runs 02/06 show **no** `EPOLL_CTL_ADD` for fd 24 while they do show the `EPOLL_CTL_DEL` (02:152).  gVisor has no io_uring, so under runsc libuv will fall back to plain `epoll_ctl` — a host-only artifact, but E1b must expect the fallback path |
| wait | `epoll_pwait(...) = [{events=EPOLLOUT}]` | 02:81, 02:141 | **level-triggered**, and `EPOLLHUP` is used as a real signal (02:87) |
| completion | `getsockopt(SOL_SOCKET, SO_ERROR)` | 02:82, 02:142 | **the return value is ignored**, see §2 |
| peer/local | `getsockname` then `getpeername` | 02:83, 02:84 | **on demand only**: they appear in phase 1 because the client reads `s.localAddress`/`s.remoteAddress`; the https phase never touches them and never calls either (02:138-153) |
| setsockopt | **none, ever** | — | `grep -c 'setsockopt(N<TCP'` is 0 in runs 02, 04 and 06.  No `TCP_NODELAY`, no keepalive.  Run 15 (`setsockopt→ENOPROTOOPT`) injects nothing at all because nothing is called |
| data | plain `read(2)` / `write(2)` (8 reads, 4 writes in run 04) | 04:131, 04:133, 04:137, 04:262-282 | libuv uses `writev` only for a multi-buffer write: `uv__writev()` in `deps/uv/src/unix/stream.c` is `if (n == 1) return write(fd, vec->iov_base, vec->iov_len); else` `writev(...)`.  This workload never queues 2 buffers, so a `writev`-capable endpoint is still required in general |
| close | `shutdown(fd, SHUT_WR)`, then `epoll_ctl(DEL)`, then `close(2)` | 02:86/88 and 02:151-153 | **`shutdown(SHUT_WR)` on every `.end()`**, i.e. on every socket, including the TLS one |
| TLS phase difference | none at the socket level | | |

## 2. Fault-injection matrix

`strace -e inject=SYSCALL:error=ERRNO[:when=N]` (works on the static Go binary,
no `LD_PRELOAD`).  "completed" = the client printed both `PHASE1 OK`/read and a
200 for phase 2.

| injection | Go | Node |
|---|---|---|
| `getsockname → EOPNOTSUPP` | **completes, but dials 3× and throws the first 2 connections away.**  run 07: fail at :43 → `EPOLL_CTL_DEL`+`close` at :44-45 → new socket :46 → fail at :57 → close :59 → new socket :60 → fail at :73 → this one is kept (:74-78).  `LocalAddr()` is `nil`.  Cause in §4 | **completes, no retry.**  run 13: `local=undefined:undefined`, remote fine, 200 OK |
| `getpeername → ENOTCONN` | **FATAL — and it hangs, it does not fail.**  run 08 exits 124 (killed by the 25 s per-run timeout) with phase 1 never finishing.  The trace ends at :36 `getpeername(...) = -1 ENOTCONN (INJECTED)` and then emits **no further socket syscall** until the SIGTERM at :38.  `net/fd_unix.go:110-145`: on the EINPROGRESS path, `SO_ERROR == 0` but `Getpeername` failing does not break the `for` loop — it falls through to `runtime.KeepAlive(fd)` and loops back to `fd.pfd.WaitWrite()`, which blocks for ever because the edge-triggered EPOLLOUT was already consumed.  A silent permanent hang inside `net.Dial`, invisible to strace | **tolerated.**  run 14: `remote=undefined:undefined family=undefined`, exchange completes, 200 OK |
| `setsockopt → ENOPROTOOPT` (all) | **tolerated.**  run 09: `TCP_NODELAY` and `SO_KEEPALIVE` both refused (:45-46, :61-62); `newTCPConn` discards the `setNoDelay` error (`net/tcpsock.go:290` calls it without checking) and `SetKeepAliveConfig` aborts the keepalive triple after `SO_KEEPALIVE` fails, so `TCP_KEEPIDLE/INTVL/CNT` are never attempted.  Both phases complete | **vacuously tolerated** — run 15 injects nothing because libuv issues no setsockopt on a client TCP socket |
| `getsockopt → ENOPROTOOPT` (all) | **FATAL, clean error.**  run 10: `dial tcp 127.0.0.1:…: getsockopt: protocol not available` for phase 1 (:38/40) and the same for phase 2 (:51).  `net/fd_unix.go:127-129` turns it straight into `os.NewSyscallError("getsockopt", err)` | **FATAL, and garbage.**  run 16: `connect Unknown system error -28968` on both phases (:80, :89), then an immediate `close` (:81, :90).  libuv **ignores the `getsockopt` return value** and reads the uninitialised stack variable: `deps/uv/src/unix/stream.c` `uv__stream_connect()` does `getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorsize); error = UV__ERR(error);` with `int error;` never initialised on the failure path |
| `getsockopt → ENOPROTOOPT` (`when=1`) | **FATAL for the first dial, same message** (run 11, :43); the second dial's getsockopt succeeds (:55) yet phase 2 still fails, because the Transport's dial *is* the first-and-only dial of that phase | **first dial fails with a *different* garbage errno** — run 17 prints `-31243` where run 16 printed `-28968`, which is the uninitialised-stack read caught red-handed; the second dial (:91) succeeds and phase 2 returns 200 |
| `shutdown → ENOTCONN` | **no-op.**  run 12 completes exactly like the baseline; Go issues no `shutdown` at all | **tolerated but stalls.**  run 18: the exchange completes, then `shutdown(SHUT_WR) = -1 ENOTCONN (INJECTED)` at :88, the peer never sees EOF, nothing else happens for ~5 s (:89-92), the client's own 5 s socket timeout fires (`PHASE1 timeout`) and only then is the fd closed (:93-94).  Wall time 6.05 s vs ~1 s baseline.  `uv__drain()` (`stream.c:651`) reports the errno to the shutdown callback and does **not** set `UV_HANDLE_SHUT`, so the half-close silently never happens |

## 3. Can `connect()` return 0 instead of EINPROGRESS?

Yes for both, from source; the host never produced a 0 return (loopback
included — 01:33 is EINPROGRESS), so this is a source claim, not a measurement.

*Go*, `net/fd_unix.go:48-60`:

```go
switch err := connectFunc(fd.pfd.Sysfd, ra); err {
case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
case nil, syscall.EISCONN:
        select { case <-ctx.Done(): return nil, mapErr(ctx.Err()); default: }
        if err := fd.pfd.Init(fd.net, true); err != nil { return nil, err }
        runtime.KeepAlive(fd)
        return nil, nil
```

An immediate success returns `(nil, nil)` — i.e. `crsa == nil` — and skips the
poll/`SO_ERROR`/`getpeername` loop entirely.  `net/sock_posix.go:133-146` then
falls back: `Getsockname` for the local address, `Getpeername` for the remote,
and only if *that* returns nothing does it use the address the caller dialled.
So a 0 return is strictly *easier* on the endpoint: no `SO_ERROR` is asked for,
and a failing `getpeername` here is survivable (unlike §2, because this path has
no retry loop to spin in).  The `getsockname`/`getpeername` *values* still feed
`selfConnect` (§4).

*libuv*, `deps/uv/src/unix/tcp.c` `uv__tcp_connect()`: after
`r = connect(...)`, only `if (r == -1 && errno != 0)` is treated as anything but
success, and in every case it then does `uv__io_start(loop, &handle->io_watcher,
POLLOUT)` and returns.  A 0 return therefore still goes through POLLOUT and
still calls `getsockopt(SO_ERROR)` in `uv__stream_connect()`.  libuv cannot skip
`SO_ERROR`; Go can.

## 4. What if `getsockname`/`getpeername` answer AF_UNIX instead of AF_INET?

Reasoned from source — strace cannot rewrite a syscall's *result buffer*, only
its return value, so this was not injected.

*Go*: `net/tcpsock_posix.go:16-24`, `sockaddrToTCP` switches on
`*syscall.SockaddrInet4` / `*syscall.SockaddrInet6` and `return nil` for
anything else, AF_UNIX included.  So an AF_UNIX answer is **indistinguishable
from the call failing**: `fd.laddr` / `fd.raddr` end up nil, `LocalAddr()` /
`RemoteAddr()` return a nil `Addr` (and any caller doing
`conn.RemoteAddr().String()` panics).  Worse, it lands in the same trap run 07
exposed — `net/tcpsock_posix.go:111-116`:

```go
for i := 0; i < 2 && (laddr == nil || laddr.Port == 0) && (selfConnect(fd, err) || spuriousENOTAVAIL(err)); i++ {
        if err == nil { fd.Close() }
        fd, err = internetSocket(ctx, sd.network, laddr, raddr, syscall.SOCK_STREAM, proto, "dial", ctrlCtxFn)
}
```

with `selfConnect` (`:124-144`) returning **true** when `fd.laddr == nil ||
fd.raddr == nil`, and also when `l.Port == r.Port && l.IP.Equal(r.IP)`.  So a
nil, AF_UNIX or wrong-family local/remote address makes `net.Dial` close the
connection and dial twice more before relenting — which for an FD-backed
endpoint means the supervisor's socketpair FD is dropped and two more handoffs
are demanded.  The same fires if the adapter's *synthetic* local and remote
addresses are ever equal.

*Node*: `src/tcp_wrap.cc` `AddressToJS()` switches on `addr->sa_family` with
cases for `AF_INET6` and `AF_INET` and a `default:` that sets only
`address` to `String::Empty()` — no `family`, no `port`.  libuv's
`uv__getsockpeername()` copies whatever the kernel wrote into a
`sockaddr_storage` and does not filter by family.  So AF_UNIX gives
`remoteAddress === ''`, `remotePort === undefined`, `remoteFamily ===
undefined`, and nothing else breaks — the same benign outcome as the run-13/14
injections (which gave `undefined` rather than `''`).

## 5. Verdict

**The FD-backed endpoint must answer `getpeername` and `getsockopt(SOL_SOCKET,
SO_ERROR)` correctly, must be pollable, and must answer `getsockname` with a
plausible AF_INET address that differs from the peer address.**  `SO_ERROR` is
non-negotiable for both runtimes: refusing it fails Go's dial with a clean
`getsockopt: protocol not available` (runs 10/11) and fails Node's with an
uninitialised-stack garbage errno (`connect Unknown system error -28968`, runs
16/17), because libuv never checks the call's return value — so the endpoint
must return 0 with a zeroed `int`, not an error, and an AF_UNIX socket that
rejects `SOL_SOCKET/SO_ERROR` is disqualified outright.  `getpeername` is
non-negotiable *for Go specifically*, and its failure mode is the worst one in
the whole matrix: run 08 shows `net.Dial` wedged for ever inside
`fd.pfd.WaitWrite()` with no further syscall (the edge-triggered EPOLLOUT is
already spent), so a sentry that answers ENOTCONN there produces a hung workload
rather than an error; Node merely reports `remoteAddress undefined`.
`getsockname` may not be refused *cheaply* either: it does not fail the dial,
but a refusal — or an AF_UNIX answer, or a local address equal to the remote
one — trips Go's `selfConnect` heuristic and makes it close the connection and
re-dial twice (run 07), which for a supervisor-supplied FD means two wasted
handoffs per dial.  The endpoint **may refuse or ignore** every `setsockopt`
(`TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_KEEPIDLE/INTVL/CNT` — run 09 completes with
all of them refused, and libuv issues none at all), and may ignore `ioctl` and
`fcntl` on the socket, which neither runtime ever issues.  `shutdown(SHUT_WR)`
is Node-only and must be *honoured*, not merely accepted: refusing it does not
raise an error (run 18 still returns 200) but the half-close never reaches the
peer, so a request/response protocol that ends on EOF stalls until some timeout
— on a socketpair this is the one call that maps cleanly anyway.  `connect` may
return either 0 or EINPROGRESS: Go's 0 path skips `SO_ERROR` and `getpeername`
entirely (`fd_unix.go:50-60`) while libuv polls for POLLOUT and asks for
`SO_ERROR` either way.  The FD must be pollable for EPOLLOUT and EPOLLIN by
**both** disciplines — Go registers it once as
`EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET` (edge-triggered, one shot per transition,
01:36) and Node level-triggered while also acting on `EPOLLHUP` (02:87) — and
must support plain `read`/`write` with `EAGAIN` and short reads, plus `writev`
for libuv's multi-buffer path.  Nothing in either runtime's connected-socket
path requires a netstack TCP endpoint: an AF_UNIX socketpair end already
satisfies read/write/writev/shutdown/poll/close natively, and the four calls it
cannot answer natively — `getsockname`, `getpeername`, `SO_ERROR`,
`setsockopt` — are precisely the ones the sentry intercepts, so the design is
viable provided the sentry synthesises AF_INET answers for the first three
(distinct local and remote addresses) and swallows the fourth.

## 6. Files

| file | what |
|---|---|
| `run.sh` | reproduces every run; `E1_ONLY="07 08"` redoes a subset, `E1_TIMEOUT` sets the per-run limit (default 25 s) |
| `goclient/main.go`, `goclient/go.mod` | Go client, two phases |
| `nodeclient.js` | Node client, two phases |
| `echoserver/main.go`, `echoserver/go.mod` | loopback TCP echo server for phase 1 |
| `output-01-go-baseline.txt` … `output-06-node-baseline-pinned.txt` | baselines: plain, with read/write traced, and address-pinned controls |
| `output-07…12-go-inject-*.txt` | Go fault injection |
| `output-13…18-node-inject-*.txt` | Node fault injection |
| `output-19-node-baseline-io-uring.txt` | proves libuv registers the fd with epoll via io_uring |

Each output file starts with a `###` header giving the exact command, the echo
server address, the exit status and the outcome, then the client's stdout, then
the untrimmed strace.
