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

    egress_refused protocol=tcp address=100.64.1.0 port=443 name=www.rfc-editor.org reason=unavailable

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

## What this check does not say

It says nothing about tunneld, about attestation, about two peers, or about an
agent runtime: the stand-in has none of those. It also does not exercise the
adapter under a restore, and it uses one container per sandbox. The loopback
proof is where the real tunneld, the real exit and a real agent meet.

## Files here

| file | what |
| --- | --- |
| `run-adapter-check.sh` | the six runs, exactly as run |
| `output-01-adapter-check.txt` | the untrimmed transcript |
| `faketunneld/` | the stand-in: `attest/sandbox`'s socket plus a CONNECT exit |
| `adapterclient/` | the Go workload |
| `adapternode.js` | the Node workload |
| `../tools/seccheck-receiver/` | the receiver the event lines come from |
