# The adapter check — the sentry's egress adapter, end to end, on a workstation

Ticket 25's own check of the piece this ticket builds. It is **not** the loopback
proof (that is `../loopback/`, two sandboxes and the real tunneld): it is the
sentry-side agent's own evidence that the adapter does what the interface note
says, with a throwaway stand-in where tunneld would be. Workstation only,
2026-09-18, worktree `/home/pniroula/Projects/gvisor-t25`, branch
`ticket-25-the-adapter-intercept-and-handoff`. No sudo, no hardware.

    runsc sha256           ab593dc254fe9617d8370ce77f81ae5abeb4483e4c980c4605247d441a1f4f70
    faketunneld sha256     b353c39d71423c9299e18871db3128d5b52cf325fec220c530888fc15efaff77
    seccheck-receiver      1935dc5c7f12a8bd4f1da9f47ae438b7ee94fde3a7e749a8be14bfcc57c41e7c
    adapterclient sha256   f21fc8fee4199fc0da588e2be3cbd4a9bd48b57025512310750d039b06ccd87c
    node                   v18.19.1 (Ubuntu /usr/bin/node, libuv)

`runsc` is `make runsc`'s `-c opt` binary. Everything here is reproduced by
`./run-adapter-check.sh <runsc> <workdir> <faketunneld> <seccheck-receiver>
<adapterclient> <adapternode.js>`; the untrimmed transcript of the run these
numbers come from is `output-01-adapter-check.txt`.

## What was asked

Does the adapter, as built, do the six things the interface note fixes? A name
in the table becomes an address and then a working TLS connection through the
helper; the same name on another port, a name the table does not carry, a
public address named directly and a datagram to one are each refused with
`ENETUNREACH` and a recorded event; a destination the **far exit** refuses is
`ECONNREFUSED` and is **not** recorded, because that refusal is the other end's;
the sandbox's own loopback is untouched; and the two flags are refused before a
sandbox exists unless they come together with `--network=none`.

## What was done

Six runs, from one script.

| run | what it is |
| --- | --- |
| `go` | the Go workload, whose resolver is Go's own pure-Go one |
| `node` | the Node workload, whose resolver is glibc's `getaddrinfo` |
| `wrong-peer` | the same table with `default_exit` naming a peer the stand-in does not answer for |
| `no-helper` | `--tunnel-socket` pointed at a path nothing is listening on |
| `validate-network` | `--network=sandbox` with both tunnel flags |
| `validate-lonely` | `--tunnel-table` without `--tunnel-socket` |

The sandbox flags are S1's, unchanged, plus the two the adapter adds and the
trace session:

    runsc --root=<state> --platform=systrap --network=none --ignore-cgroups \
          --rootless --gofer-network-namespace=new \
          --tunnel-socket=<tunneld.sock> --tunnel-table=<table.json> \
          --pod-init-config=<pod-init.json> \
          --debug --debug-log=<dir>/ run --bundle <bundle> <id>

The table, for the four sandbox runs:

```json
{"default_exit":"b",
 "names":{"www.rfc-editor.org":{"port":443},
          "refused.example":{"port":443}}}
```

**The rootfs has no `/etc/hosts` entry for either name.** `/etc/resolv.conf` says
`nameserver 127.0.0.53` and `/etc/nsswitch.conf` says `hosts: files dns`, so the
only thing that can turn a name into an address is the responder inside the
sentry. That is the difference from spike E1b, which used a hosts file and never
exercised DNS at all.

`faketunneld/` is tunneld only in the one respect the adapter touches: it serves
`attest/sandbox`'s local socket, so the helper — which speaks that protocol and
nothing else — attaches to it and asks for streams. Behind each stream is its
own exit, which is ticket 23's `CONNECT`/`OK`/`REFUSED` line and a dial, with an
allow list of `www.rfc-editor.org:443` and nothing else. There is no tunnel, no
QUIC and no attestation anywhere in it; **nothing here is evidence about
tunneld.**

## The recorded answers

**1. A name in the table works, for both runtimes, over a real TLS connection
to a real host, from a sandbox with no network.**

| run | result |
| --- | --- |
| Go | `ALLOWED-NAME status="200 OK" tls=true bodyprefix="<!DOCTYPE html>…"` |
| Node | `ALLOWED-NAME status=200 tls=TLSv1.3 bytes=179488 ms=418` |

and the sentry's own account of the same two connections:

    tunnel dns: q=www.rfc-editor.org type=AAAA answer=noerror-empty
    tunnel dns: q=www.rfc-editor.org type=A answer=100.64.1.1
    tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 61.908961ms, host fd 48, local 100.64.0.1:40001

Note the order: **AAAA first**, which is what spike E4 said an agent runtime
does for every name, every time, and which the responder answers with NOERROR
and no records rather than a hang or an NXDOMAIN.

**2. Every other destination is `ENETUNREACH`, and the event says which rule
refused it.** The Go workload's six lines, and the receiver's:

    WRONG-PORT   error=dial tcp 100.64.1.1:80: connect: network is unreachable   errno=ENETUNREACH
    UNKNOWN-NAME addrs=[] error=lookup example.com on 127.0.0.53:53: no such host
    RAW-ADDRESS  error=dial tcp 8.8.8.8:443: connect: network is unreachable     errno=ENETUNREACH
    UDP-CONNECT  error=dial udp 8.8.8.8:53: connect: network is unreachable      errno=ENETUNREACH
    UDP-SENDTO   error=network is unreachable                                    errno=ENETUNREACH

    egress_refused protocol=tcp address=100.64.1.1 port=80 name=www.rfc-editor.org reason=wrong-port  container_id=t25-go-615387 thread_id=3
    egress_refused protocol=dns name=example.com reason=unknown-name
    egress_refused protocol=dns name=example.com reason=unknown-name
    egress_refused protocol=tcp address=8.8.8.8 port=443 reason=not-in-table     container_id=t25-go-615387 thread_id=4
    egress_refused protocol=udp address=8.8.8.8 port=53  reason=not-in-table     container_id=t25-go-615387 thread_id=4
    egress_refused protocol=udp address=8.8.8.8 port=53  reason=not-in-table     container_id=t25-go-615387 thread_id=4

Two DNS events for one name, because Go asks AAAA and A. Two UDP events for one
address, because the workload sent a datagram both ways a client can: the
`connect(2)` one, whose address arrives at `sock.Connect`, and the `sendto(2)`
one, whose address arrives at `sock.SendMsg` — spike E2's finding 2, which is
why the adapter hooks both. The DNS events carry no `container_id` or
`thread_id`: the responder answers on its own goroutine and has no task to take
them from, so it records the time and the name and nothing it would have to
invent.

**3. A destination the far exit refuses is `ECONNREFUSED` and is not recorded.**

    REFUSED-BY-EXIT error=dial tcp 100.64.1.0:443: connect: connection refused errno=ECONNREFUSED
    tunnel attach: refused.example:443 -> peer "b": refused by the far exit in 5.535131ms

`refused.example` is in the table — it resolves, and the sentry asks for the
stream — and the exit's own allow list says no. No `egress_refused` event
appears for it anywhere in the run. That is the interface note's rule kept: the
far side's list is ticket 23's and is recorded where the decision is made.

**4. The helper being unreachable is `ENETUNREACH` with reason `unavailable`,
and it does not hang.** Both of the two ways it can happen:

    wrong-peer: tunnel attach: www.rfc-editor.org:443 -> peer "zz": unavailable in 2.710931ms
                (asking tunneld for a stream to peer "zz": no peer named "zz")
    no-helper:  tunnel attach: www.rfc-editor.org:443 -> peer "b": unavailable in 419.576µs
                (TunnelHelper.Open(www.rfc-editor.org:443): broken pipe)

    egress_refused protocol=tcp address=100.64.1.1 port=443 name=www.rfc-editor.org reason=unavailable

Note the second one's shape: a helper that could not connect to tunneld exits,
and the sentry's next call fails with a raw `EPIPE` from the write of the
request rather than a `RemoteError` — spike E3's finding 5, and the reason the
boot side tells the two apart by type and not only by message.

**5. The sandbox's own loopback is exactly as `--network=none` leaves it.**
`LOOPBACK echoed="ping\n" n=5 err=<nil>` in every sandbox run: the workload
listened on `127.0.0.1:0`, dialled it and got its bytes back. The adapter does
not touch loopback, which is why the responder can sit on `127.0.0.53:53` in
the first place.

**6. The flags are refused before a sandbox exists.**

    $ runsc … --network=sandbox --tunnel-socket=… --tunnel-table=… run …
    tunnel-socket and tunnel-table require --network=none, got --network=sandbox
    RUNSC_EXIT=128

    $ runsc … --network=none --tunnel-table=… run …
    tunnel-socket and tunnel-table must be given together, got tunnel-socket="" and tunnel-table="…"
    RUNSC_EXIT=128

Both come out of `config.Validate`, which `NewFromFlags` calls, so they are
`runsc run`'s answer and not the sentry's. The sentry has its own copy of the
same ceiling — it refuses to install over a stack with a non-loopback NIC — and
that one is not reachable from the command line, because the first check already
stopped it.

## Run 2: the same six runs after the adversarial review

An adversarial review of the adapter found no path past the table and seven
defects beside it. They are fixed, and the same script was run again against
the rebuilt binary:

    runsc sha256 (run 2)   ea305e126ab20e4abc525317f8ab7c04179b0cf0e08a517de6c3799a4b3c4ba0

`output-02-adapter-check-after-review.txt` is that run, untrimmed.
**Every recorded answer above is unchanged** — the same nine workload lines, the
same refusal reasons in the same order, the same two validation refusals, the
same `ECONNREFUSED` with no event for the destination the far exit refuses. The
fixes are for things this check cannot reach: races, a backlogged half-close, a
descriptor held too long, an unbounded wait and a log line a name could forge.

What changed, and how each was argued:

| defect | fix | how it is shown |
| --- | --- | --- |
| the endpoint swapped under readers (torn interface read; two concurrent connects → two streams) | every read of `sock.Endpoint` goes through `sock.ep()` under a leaf `RWMutex`; the adapter claims the socket *before* asking the helper, so a second `connect(2)` is `EALREADY`/`EISCONN` and never attaches | by construction; the check's single-threaded dials are unaffected |
| `SHUT_WR` issued with bytes still in the backlog → silent truncation | the shutdown is remembered and issued from the flush path once the backlog drains | `TestTunnelEndpointHoldsTheHalfCloseBehindABacklog` fills the socketpair, half-closes, drains, and asserts every byte arrives before the end of file |
| a failed write dropped what it had already taken from the Payloader → a hole in the stream | the remainder goes to the backlog and the error becomes sticky, reported on the next call — which is also how a real socket behaves | by construction; a write is now also refused while a backlog stands, which bounds the backlog to one write |
| `Readiness` polled a descriptor after `Close` (fd reuse) | a closed endpoint answers from its own state | `TestTunnelEndpointReadinessAfterClose` |
| names reached the log and the trace raw; a label with a newline forges a line | quoted and scrubbed to printable ASCII, capped at 255 bytes | `TestTunnelPrintable`; and the query lines in run 2 read `q="www.rfc-editor.org"` |
| the helper kept a reference to every stream (urpc closes no result files), so the far exit's connection outlived the sandbox's until a finalizer ran | an `afterRPCCallback` closes each descriptor once its reply is on the wire | by construction. **The check cannot isolate this one**: the helper exits with its sandbox, so every descriptor is closed then anyway. It would show in a long-lived sandbox that opens many streams |
| the helper's wait for tunneld was unbounded → a wedged tunneld holds a workload thread inside `connect(2)` for ever, and every other connect behind it | the whole open is bounded by the same 30 s deadline the CONNECT line has | by construction; the `no-helper` run still answers in 274–704 µs |

## What this check does not say

It says nothing about tunneld, about attestation, about two peers, or about an
agent runtime: the stand-in has none of those. It also does not exercise the
adapter under a restore, and it uses one container per sandbox. The loopback
proof is where the real tunneld, the real exit and a real agent meet.

## Leftovers

Known and deliberately not fixed here; each is a thing this ticket does not
need and the next one may.

1. **A restored sandbox gets no adapter.** It is installed from `Loader.run`'s
   `created` path only.
2. **`tunnelEndpoint` is not stateify-savable**, so a checkpoint of a sandbox
   with an attached stream fails. A descriptor to a host socket is not state
   that can be written down.
3. **An `AF_INET6` socket, or a v4-mapped destination, is refused** with
   `not-in-table` rather than a reason that says the adapter is v4-only. The
   responder's AAAA answer means a runtime should never reach that path.
4. **The notifier callback takes the endpoint's mutex** while `Read` holds it
   across the copy into the caller's buffer, so a wakeup can wait on a slow
   copy.
5. **Bytes left in `rbuf` raise no new readable edge.** Under `EPOLLET` a
   reader that stops short could sleep on data the sentry already holds; both
   runtimes read until `EAGAIN`, so neither does.
6. **`SIOCINQ`/`SIOCOUTQ` report only the sentry's own buffers**, not what the
   descriptor holds.
7. **Table names are not charset-validated**, and the exit's answer is matched
   by prefix without checking that the destination it echoes is the one that
   was asked for.
8. **DNS refusals carry no task context** — no `container_id`, no `thread_id`.
   The responder has no task.
9. **The ceiling is checked once, at install.** A NIC added afterwards would
   not be noticed; nothing in the sandbox can add one.
10. **Refusal events are not rate-limited**: one per refused connect, datagram
    or query.
11. **The descriptor from the helper is duplicated with a plain `dup(2)`**,
    which carries no `FD_CLOEXEC`. Nothing is dropped — urpc's transport never
    sets it — and the sentry's own seccomp filter permits `fcntl` only for
    `F_GETFL`, `F_SETFL` and `F_GETFD`, so a CLOEXEC-preserving duplicate is
    not available to it. The sentry execs nothing after boot.
12. **The sentry's call into the helper is a blocking Go call** serialised by
    one mutex. It is bounded at 30 s but not interruptible by a signal.
13. **No seccomp filter on the helper**, matching `runsc/checkpointgofer`.

## Files here

| file | what |
| --- | --- |
| `run-adapter-check.sh` | the six runs, exactly as run |
| `output-01-adapter-check.txt` | the untrimmed transcript, run 1 |
| `output-02-adapter-check-after-review.txt` | the untrimmed transcript, run 2 (after the review's fixes) |
| `faketunneld/` | the stand-in: `attest/sandbox`'s socket plus a CONNECT exit |
| `adapterclient/` | the Go workload |
| `adapternode.js` | the Node workload |
| `../tools/seccheck-receiver/` | the receiver the event lines come from |
