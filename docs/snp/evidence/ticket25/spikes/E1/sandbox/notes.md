# E1b — PASS for both runtimes. An FD-backed endpoint can stand in for a TCP socket

Ticket 25, experiment 1, sandbox half. (E1's host half — the strace study with
injected failures, "E1a" — is `../notes.md`; this subdirectory holds the
in-sandbox half and nothing else.) Workstation only, 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t25`, branch
`ticket-25-the-adapter-intercept-and-handoff`. No sudo, no hardware.

    runsc sha256      11005df8c5191970592b1e28e3b59837c918d3d42a447e1865202b9a8f80ac30
    supervisor sha256 a0c231bf87d32009611240365172f92a397185f004988793f8690b60e9553ab9
    goclient sha256   de8956a72e2b4706db5e6216dda45055f7b73bede9200af62b5f508806e41ca7
    node              v18.19.1 (Ubuntu /usr/bin/node, libuv)

Sandbox flags are S1's, unchanged — in particular **`--network=none`**, so the
handoff is the only way a byte can leave the sandbox — plus `--debug
--debug-log=<dir>/ --strace`.

## What was asked

Can an FD-backed `tcpip.Endpoint` stand in for a TCP socket, for unmodified Go
and Node programs **inside** the sandbox? Or must the endpoint be a netstack
socket (the ticket's alternative: a netstack loopback proxy inside the sentry)?
And should `Connect` report success synchronously or `ErrConnectStarted`?

## What was done

- `patch-01-fd-backed-endpoint-and-connect-hook.diff` — a new
  `pkg/sentry/socket/netstack/spike_fdendpoint.go` implementing `tcpip.Endpoint`
  over a host FD, plus one line in `sock.Connect` (`netstack.go:820`) and two
  `BUILD` entries. Readiness follows hostinet
  (`pkg/sentry/socket/hostinet/socket.go:154`): `fdnotifier.AddFD` for
  edge-triggered epoll notifications, `fdnotifier.NonBlockingPoll` for the
  current state. Local and remote addresses, `SO_ERROR` and the keepalive
  options are answered from sentry-side state, because the sentry's seccomp
  filter allows neither `getsockname` nor `setsockopt`
  (`runsc/boot/filter/config/config_main.go:91-117`).
- `patch-02-boot-side-helper-client.diff` — E3's `Spike` object again, but this
  time the urpc client is handed to netstack through a one-method interface
  (`netstack.SpikeHelper`), so the netstack package gains **no** new build
  dependency on urpc.
- `run-e1b.sh <runsc> <workdir> <supervisor> <goclient> <nodeclient.js> go|node
  sync|started` builds the bundle and runs one client. The bundle's
  `/etc/hosts` maps `www.rfc-editor.org → 100.64.0.1` and
  `echo.spike.test → 100.64.0.2`, with `/etc/nsswitch.conf` saying
  `hosts: files dns`. **That is the only thing that makes the clients
  unmodified**: neither `goclient.go` nor `nodeclient.js` contains an address,
  a proxy setting or anything else that knows an adapter exists.
- The helper maps `100.64.0.2:7777 → its own loopback echo` and
  `100.64.0.1:443 → www.rfc-editor.org:443`.

Four runs: {Go, Node} × {`sync`, `started`}.

## The recorded answers

**1. Both runtimes work, completely, over a real TLS connection.**

| run | echo dial | 256 KiB bulk | half close | HTTPS GET |
|---|---|---|---|---|
| Go, sync (o1) | 29.0 ms (o1:28) | 262144 echoed, 26.6 ms (o1:33) | EOF (o1:34-35) | **200 OK**, TLS 1.3, 238 ms (o1:38-41) |
| Go, started (o2) | 23.8 ms (o2:28) | 262144, 9.1 ms (o2:33) | EOF (o2:34-35) | **200 OK**, TLS 1.3, 216 ms (o2:38-41) |
| Node, sync (o3) | 87 ms (o3:28) | 262144, 15 ms (o3:32) | FIN seen (o3:33-34) | **200 OK**, TLSv1.3, 275 ms, 179558 B body (o3:38-42) |
| Node, started (o4) | 82 ms (o4:28) | 262144, 23 ms (o4:32) | FIN seen (o4:33-34) | **200 OK**, TLSv1.3, 320 ms, 179558 B body (o4:38-42) |

Both runtimes negotiated TLS 1.3 to the real `www.rfc-editor.org` and validated
its certificate (`cert CN "rfc-editor.org"`, `server="www.rfc-editor.org"` in
Go's SNI) — from a sandbox with `--network=none`, over a descriptor the helper
passed in. Nothing in either client was rewritten to avoid a call.

**2. The calls each runtime made on the socket, and how they were answered.**

Go, synchronous connect (o5:1305-1337) — E1a's prediction holds exactly, the
`connect() == 0` path skips `SO_ERROR` and asks the two names instead:

    connect(… 100.64.0.2:7777) = 0
    getsockname(… 100.127.255.254:40001) = 0
    getpeername(… 100.64.0.2:7777)      = 0
    setsockopt(SOL_TCP, TCP_NODELAY)     = 0
    setsockopt(SOL_SOCKET, SO_KEEPALIVE) = 0
    setsockopt(SOL_TCP, TCP_KEEPINTVL)   = 0
    setsockopt(SOL_TCP, TCP_KEEPIDLE)    = 0
    shutdown(fd, SHUT_WR)                = 0            (o5:1439)

Go, `ErrConnectStarted` (o6:1295-1351) — the EINPROGRESS path, with `SO_ERROR`
answered zero:

    connect(…) = -1 errno=115 (operation now in progress)
    getsockopt(SOL_SOCKET, SO_ERROR, {value=0}) = 0
    getpeername / getsockname / four setsockopt            all = 0

Node, both modes (o7:3061-3084, o8:3034-3057) — libuv asks `SO_ERROR` whichever
way `connect` went, then both names, and **issues no `setsockopt` at all**:

    connect(…) = 0                       (o7)  /  = -1 errno=115 (o8)
    getsockopt(SOL_SOCKET, SO_ERROR, {value=0}) = 0
    getsockname(… 100.127.255.254:40001) = 0
    getpeername(… 100.64.0.2:7777)       = 0
    shutdown(fd, SHUT_WR)                = 0     (o7:3146, o8:3119)

**Not one call was refused.** The endpoint logs a line whenever it answers
`ErrUnknownProtocolOption`; the count in every run's sentry log is **zero**.
Every option both runtimes touched was either a `tcpip.SocketOptions` field the
generic netstack layer handles (`TCP_NODELAY`, `SO_KEEPALIVE`) or one the
prototype remembers (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`).

**3. Both epoll disciplines work on the FD-backed endpoint.** Go registers once,
edge-triggered (o5):

    epoll_ctl(ADD, socket:[1], events=EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET) = 0

and Node level-triggered, re-arming with `EPOLL_CTL_MOD` (o7):

    epoll_ctl(ADD, socket:[3], events=EPOLLOUT) = 0
    epoll_ctl(ADD, socket:[3], events=EPOLLIN)  = -1 errno=17 (file exists)   <- libuv's usual probe
    epoll_ctl(MOD, socket:[3], events=EPOLLIN)  = 0

Note that this epoll is the **sentry's own**, driven by `Readiness()` and the
sock's waiter queue; the host FD is separately in fdnotifier's edge-triggered
epoll. Both layers agreed: 21 socket I/O syscalls in the Go run with 2 `EAGAIN`,
18 in the Node run with 1 `EAGAIN`, no stalls and no spurious wakeups. Short
reads appear as expected (Go reads 32768 at a time out of the 262144 in flight,
Node 65536).

**4. `connect`: synchronous success and `ErrConnectStarted` both work, and the
choice does not matter for correctness.** All four runs pass. Two things decide
it in practice, and neither is about the runtimes:

- **The handoff cost is paid inside `connect(2)` either way**, because the
  prototype asks the helper *before* it swaps the endpoint in. `connect` took
  47 ms in the Go/sync run and 15 ms in Go/started for the real host
  (o5:1542, o6:1576) — that is the helper's own dial (o1:18 records 46 ms;
  o2:18 records 13.5 ms). Returning `ErrConnectStarted` does **not** make the
  dial asynchronous as the code stands; it only changes the errno.
- **`ErrConnectStarted` costs three extra syscalls per connection** (`SO_ERROR`
  plus, for Go, the re-ordered name lookups) and is the path that *depends* on
  `SO_ERROR` being answered zero — the one E1a shows failing catastrophically
  if it is refused (libuv reads an uninitialised int).

So the honest recommendation is: **return success synchronously** while the
helper call is synchronous, because it is the smaller contract; switch to
`ErrConnectStarted` only when the design makes `Helper.Open` asynchronous, and
then the writable notification must fire after the dial completes, not before it
as the spike does.

**5. Two host-side facts worth carrying.** `/etc/hosts` is enough for both
resolvers with no DNS at all: glibc tried `/var/run/nscd/socket` first and got
`ENOENT` (o7:2966, 2974) and then read the files. And Ubuntu's `node`
externalises builtins to `/usr/share/nodejs` and `abort()`s at startup without
them — the run script bind-mounts that directory read-only; a real workload
image has to carry it.

## Verdict

**Yes for both runtimes; the endpoint does not have to be a netstack socket.**
Unmodified Go (`net.Dial`, `net/http`) and unmodified Node 18/libuv
(`net.connect`, `https.get`) both ran to completion on a hand-built
`tcpip.Endpoint` backed by an `AF_UNIX` socketpair end handed in by the helper,
inside a sandbox with `--network=none`, including a full TLS 1.3 HTTPS GET
against a real internet host with certificate validation. The ticket's
alternative — a netstack loopback proxy inside the sentry — **is not needed**.

What made it work is exactly the four answers E1a predicted, and no more:

1. `getsockopt(SOL_SOCKET, SO_ERROR)` returns **0**, from sentry state. The
   prototype gets this for free by owning a `tcpip.SocketOptions` whose handler
   returns a nil `LastError`, which is what `netstack.go:999-1011` reads.
2. `getpeername` returns the **AF_INET synthetic destination**, from
   `GetRemoteAddress`.
3. `getsockname` returns an AF_INET local address that **differs** from the
   remote one — the prototype hands out `100.127.255.254:<40000+n>`, one port per
   connection, so Go's `selfConnect` heuristic never fires and every dial is one
   handoff (confirmed: the helper opened exactly two streams per run).
4. `shutdown(SHUT_WR)` is **passed through to `shutdown(2)`** on the host FD, and
   the helper's pump turns it into a `CloseWrite` on the real TCP connection;
   both clients then saw the peer's FIN (o1:35 `Read at EOF: n=0 err=EOF`,
   o3:34 `end event`).

Everything else the endpoint may refuse, and the refusal is never reached
because the two runtimes between them ask for nothing else. The remaining
correctness work is not about the runtimes but about the endpoint's own
bookkeeping, and the spike had to get two pieces of it right to pass at all:
a **read-side leftover buffer** (`Endpoint.Read` is handed an `io.Writer` with no
declared capacity, so a short user buffer would otherwise drop the rest of a
64 KiB host read), and a **write-side backlog flushed from the notification
path** (`Endpoint.Write` takes ownership of what it reads from the `Payloader`,
so bytes the host FD would not take cannot be given back, and the sandbox may
never write again). Both are in the `.diff`; both are load-bearing.
