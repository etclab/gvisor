# E2 — the intercept fires, but only for *unconnected* sendto; and 127.0.0.53:53 is reachable

Ticket 25, experiment 2. Workstation only, 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t25`, branch `ticket-25-the-adapter-intercept-and-handoff`,
based on ticket 24's tip `ab26b518c`. No sudo, no hardware, host-side only.
The sandbox is booted with S1's flag set, unchanged:

    runsc --root=<statedir> --platform=systrap --network=none --ignore-cgroups \
          --rootless --gofer-network-namespace=new run --bundle <dir> <id>

with `--debug --debug-log=<dir>/ --strace` added so the sentry's own log can be
read. The bundle is a directory (ticket 24 E3's layout, minus its workload-device
step — a directory bundle is enough on the host).

## What was asked

Does a datagram reach `sock.SendMsg` under `--network=none`, and at which address
must a responder sit? Plus the TCP baseline: what does every other `connect()`
return from inside?

## What was done

Two runs, two binaries.

| run | runsc sha256 | patch | evidence |
|---|---|---|---|
| 1 | `99bb52d5db5a2c29a2fd5a4fb4873323a2ba681e79f2e78fe3d3eae2a47d2bb0` | patch-01 only | output-01, output-02 |
| 2 | `1d8955ee54f92c364fa6ca8baacdc2d09e52c4ca8a489e7c7e7f1c41e690236e` | patch-01 + patch-02 | output-03, output-04 |

- `patch-01-sendmsg-connect-write-logging.diff` — `sock.Connect`, `sock.SendMsg`
  and `sock.Write` in `pkg/sentry/socket/netstack/netstack.go` each renamed to a
  `…Spike` inner function and given a logging wrapper that prints the parsed
  address, the socket's family/type/protocol, the endpoint's local and remote
  address, and the result. `sock.Write` is in there because that, not `SendMsg`,
  is where a *connected* socket's data arrives — see the verdict.
- `patch-02-loopback-dns-responder.diff` — a UDP endpoint bound inside the sentry
  on the sandbox's own netstack at `127.0.0.53:53`, answering every query with a
  fixed A record for `100.64.0.1` (E1b's first synthetic address). It is started
  once, lazily, from the two wrappers, so it is bound before the probe's first
  datagram is delivered. Both patches are reverted; only the `.diff`s remain.
- `udpprobe.go` — a static Go program (go1.22.3 toolchain, `CGO_ENABLED=0`,
  sha256 `5b48eb81182636dd68528c4a13eb7235e1ab9f7f34151b509f3e85d52c90a174`)
  that sends one **real DNS A query for example.com** (29 bytes, output-01:2)
  to each of four addresses three ways — unconnected `sendto`, `connect`+`write`,
  and Go's `net.DialUDP` — and then does the TCP baseline.
- `run-e2.sh` builds the bundle and runs it. Reproduce with
  `run-e2.sh <runsc> <workdir> <udpprobe>`.

A note on reading output-01 and output-03: the driver's own `RUNSC_EXIT=0` echo
races with the sandbox's stdout and lands mid-line (output-01:19,
output-03:17). Nothing was trimmed; that is what the file recorded.

## The recorded answers

**1. An unconnected `sendto` reaches `SendMsg` with the address parsed, for all
four destinations — including the two that are unreachable.** Four lines, one per
target (output-02:1067, 1267, 1353, 1375):

    SendMsg: sockFamily=2 skType=2 proto=17 nbytes=29 flags=0x0 to{family=2 addr=127.0.0.53 port=53} … -> n=29 err=<nil>
    SendMsg: …                                                  to{family=2 addr=127.0.0.1  port=53} … -> n=29 err=<nil>
    SendMsg: …                                                  to{family=2 addr=8.8.8.8    port=53} … -> n=0  err=network is unreachable
    SendMsg: …                                                  to{family=2 addr=10.0.0.1   port=53} … -> n=0  err=network is unreachable

So the intercept point the ticket names is real: the address is in hand before
`s.Endpoint.Write`, and it is in hand *even for the unroutable destinations*,
because netstack's `ENETUNREACH` is produced inside `Endpoint.Write`, after the
wrapper has already seen the address.

**2. A *connected* UDP socket never reaches `SendMsg` at all.** Go's
`net.UDPConn.Write` — and any `connect()`+`write()` client — issues `write(2)`,
which lands in `sock.Write` with `to == nil`. The address was given earlier, at
`Connect` (output-02:1398/1407, 1505/1514):

    Connect: sockFamily=2 skType=2 proto=17 blocking=true to{family=2 addr=127.0.0.53 port=53} -> err=<nil>
    Write:   sockFamily=2 skType=2 proto=17 nbytes=29 local=127.0.0.53:31382 remote=127.0.0.53:53 -> n=29 err=<nil>

This is the single most important thing E2 found for the adapter: **a DNS
intercept cannot live in `SendMsg` alone.** glibc's resolver and Go's pure
resolver both `connect()` the UDP socket before writing. `sock.Connect` is the
address-bearing call for them; `SendMsg` is the address-bearing call only for
`sendto`-style clients. The adapter must hook *both*, exactly as it must for TCP.

**3. The exact errnos the caller saw.**

| destination | unconnected `sendto` | `connect` | connected `write` | first `recv` |
|---|---|---|---|---|
| 127.0.0.53:53 | OK (o1:8) | OK (o1:25) | n=29 (o1:26) | ECONNREFUSED 111 (o1:27) |
| 127.0.0.1:53 | OK (o1:12) | OK (o1:31) | n=29 (o1:32) | ECONNREFUSED 111 (o1:33) |
| 8.8.8.8:53 | ENETUNREACH 101 (o1:16) | ENETUNREACH 101 (o1:37) | — | — |
| 10.0.0.1:53 | ENETUNREACH 101 (o1:19) | ENETUNREACH 101 (o1:40) | — | — |

Both halves of the ticket's guess are confirmed, and they are *different errors
on different sockets*:

- **Non-loopback → `ENETUNREACH` at `sendto`/`connect`.** The loopback-only stack
  has no route; nothing is ever emitted. Same for TCP (o1:68).
- **Loopback with nothing bound → ICMP port unreachable, surfaced as
  `ECONNREFUSED` on the *next* receive, and only on a connected socket.** On the
  unconnected socket the same ICMP is dropped and `recvfrom` simply blocks to its
  2 s `SO_RCVTIMEO` and returns `EAGAIN` (o1:9, o1:13). On the connected socket
  the first `read` returns `ECONNREFUSED` immediately (0 ms) and the *second*
  read then blocks to `EAGAIN` (o1:28, o1:34) — the error is consumed once. Go's
  `net.DialUDP` shows the same thing in its own wrapper (o1:48, o1:54).
  This is Linux's behaviour reproduced faithfully, and it means a client that
  times out rather than fails fast is the signature of an *unconnected* sender.

**4. The TCP baseline — every other `connect()` fails, and how.**

    TCP 127.0.0.1:9  blocking connect  -> ECONNREFUSED 111        (o1:65)
    TCP 8.8.8.8:53   blocking connect  -> ENETUNREACH  101        (o1:68)
    Connect: skType=1 proto=6 blocking=true  to{127.0.0.1:9}  -> err=connection refused          (o2:1883)
    Connect: skType=1 proto=6 blocking=false to{127.0.0.1:9}  -> err=connection attempt started  (o2:1918)
    Connect: skType=1 proto=6 blocking=false to{8.8.8.8:53}   -> err=network is unreachable      (o2:1956)

Note the asymmetry the adapter will have to imitate: a **non-blocking** connect to
a loopback address returns `ErrConnectStarted` and the failure arrives later on
the writable notification, whereas an unroutable address fails *synchronously*
even when non-blocking. Both paths go through the same `sock.Connect`.

**5. A tiny in-sentry UDP responder on the loopback stack at 127.0.0.53:53 is
reachable — verified, not reasoned.** patch-02 bound one and it answered
(output-04:1195, 1206, 1213):

    responder: bound on 127.0.0.53:53
    responder: got 29 bytes (total 29) from 127.0.0.53:62052: 12 34 01 00 …
    responder: answered 45 bytes to 127.0.0.53:62052 -> n=45 err=<nil>

and the probe received it, on all three client styles (output-03:9-10, 28-29,
48-49) — 45 bytes, `12 34 81 80 … 64 40 00 01`, i.e. the query's id echoed back,
QR/RA set, one answer, rdata `100.64.0.1`. The control is in the same run: with
the responder bound on `127.0.0.53` only, the identical query to **`127.0.0.1:53`
still gets `ECONNREFUSED`** (output-03:14, 34). So the loopback NIC accepts the
whole `127.0.0.0/8` — netstack even assigned the *source* address `127.0.0.53`
(output-01:46) — and a responder is reached at exactly the address it binds,
with no route, no NIC and no new device.

## Verdict

Under `--network=none` the sandbox has one NIC, `lo`, with `127.0.0.1/8` and
`::1/128` (output-01:3), and that is enough for everything the adapter needs on
the UDP side. A datagram *does* reach `sock.SendMsg` with its destination parsed
— but only when the client used `sendto` on an unconnected socket. The resolvers
that matter connect first, and their bytes arrive in `sock.Write` with no address
at all; for them the address-bearing call is `sock.Connect`. **The DNS intercept
must therefore be anchored on `sock.Connect` as well as `sock.SendMsg`, or it
must not be an intercept at all** — and E2 shows the cheaper alternative works:
a UDP responder bound inside the sentry at `127.0.0.53:53` is reachable by every
client style tested, needs no intercept, and returns whatever answer the adapter
chooses. Putting `nameserver 127.0.0.53` in the sandbox's `/etc/resolv.conf` and
binding a responder there is a strictly smaller change than hooking two syscalls.

Everything else fails exactly as the ticket assumed: non-loopback destinations
are `ENETUNREACH` before a byte leaves the sentry, and loopback destinations with
nothing bound are `ECONNREFUSED`. That is the "every other connect fails"
baseline against which E1b's 100.64.0.0/10 interception has to be judged: any
address in that range reaching `sock.Connect` today gets `ENETUNREACH`
synchronously, so an adapter that answers instead cannot be masking a
pre-existing success.
