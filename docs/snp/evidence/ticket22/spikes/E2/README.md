# Ticket 22, experiment E2 — push a policy blob over the framing that already exists

Run 2026-09-15 on branch `ticket-22-sandbox-contract` at `e787af26e`, in worktree
`/home/pniroula/Projects/gvisor-t22`.

## The question

After admission, the delegator A pushes a policy blob to peer B and B acknowledges
before A proceeds. Does one unchanged `tunnel.Conn.Exchange` suffice to carry that
push and bring back the ack, or does the push need a stream type of its own? And
what does the extra round trip cost?

## The result

> One framed `Exchange` suffices. A policy blob goes out as the request of an
> ordinary exchange, B's `Serve` handler recognises it by its `format` and
> `version` fields and answers with an ack on the same stream, and A has the ack
> in hand before it proceeds — no new stream type, no change to `attest/tunnel`,
> no change to `attest/tunneld`. On the loopback harness the added round trip is
> **0.83 ms median and 1.17 ms at p90 for a 2 KiB blob** (against a 0.49 ms
> median for the bare 5-byte round trip on the same tunnel, so the blob itself
> costs about 0.34 ms of that). **A 64 KiB blob passes too, at 4.27 ms median and
> 6.04 ms p90**, and so does a 1 MiB one. The framing bound is 16 MiB
> (`attest/tunnel/tunnel.go:348`), which is 2560× a 64 KiB policy, so nothing
> about the size of a policy is near a limit; a blob over the bound is refused by
> the sender before a byte reaches the wire and the tunnel survives it. A push is
> never more expensive than the ordinary application exchange of the same size —
> at 64 KiB it is cheaper (4.27 ms against 7.00 ms), because the ack coming back
> is 45 bytes where the echo's response is another 64 KiB.

## The harness

`attest/tunneld/tunneld_test.go` — ticket 13's "two tunnelds on one VM", reused
unchanged:

| what | where |
| --- | --- |
| `start`, two tunnelds on `127.0.0.1:0` with the fake SNP platform | `attest/tunneld/tunneld_test.go:163` |
| `node` (a tunneld plus a served-exchange counter) | `attest/tunneld/tunneld_test.go:149` |
| `echo` handler, the comparison exchange | `attest/tunneld/tunneld_test.go:154` |
| `admitting`, `writeSet`, `writePolicy`, `everyImage`, `ctx` | `attest/tunneld/tunneld_test.go:69,133,105,100,186` |
| `Exchange` (one stream per call) | `attest/tunnel/tunnel.go:479` |
| `Serve` (one goroutine per stream) | `attest/tunnel/tunnel.go:515` |
| `maxFramePayload` | `attest/tunnel/tunnel.go:348` |

The spike is a test in the same external package (`tunneld_test`), so it drives
only the public API: `Tunneld.Peer` → `Channel.Exchange`. Nothing unexported was
needed.

## What was done

`startPushingCounted` starts B with a handler that parses the request as
`{"format":…,"version":…}` and branches:

- `format: "policy"`, `version: 1` → `{"format":"policy-ack","version":1,"ok":true}`
- `format: "policy"`, any other version → `{"format":"policy-ack","version":1,"ok":false,"reason":"unsupported policy version"}`
- `format: "slow"` → sleeps, for the ordering test
- anything else, including bytes that are not JSON → the harness's echo, `"sandbox-b:" + request`

A is started as before and gets a channel to B, which exists only because both
sides admitted the other at the handshake. Blobs are
`{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}` padded inside the list
entries to an exact byte count: 10/20/10 entries at 2 KiB, 320/640/320 at 64 KiB,
5120/10240/5120 at 1 MiB — the entry counts scale with size so each entry stays
about 50 bytes.

Timing: 200 iterations after 20 warmup, sequential, on one tunnel, with the
context taken out before the clock starts so only `Channel.Exchange` is inside the
measured window.

## The numbers

Run 1, milliseconds, 200 iterations after 20 warmup:

| series | request B | response B | p50 | p90 | p99 | min | max | mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| round-trip floor (5 B echo) | 5 | 15 | 0.492 | 0.681 | 0.889 | 0.262 | 1.260 | 0.510 |
| **push 2 KiB** | 2048 | 45 | **0.832** | **1.167** | 1.954 | 0.427 | 2.078 | 0.875 |
| echo 2 KiB | 2048 | 2058 | 0.780 | 0.998 | 1.425 | 0.481 | 1.567 | 0.807 |
| **push 64 KiB** | 65536 | 45 | **4.273** | **6.041** | 11.986 | 2.297 | 13.619 | 4.369 |
| echo 64 KiB | 65536 | 65546 | 7.002 | 10.251 | 16.246 | 3.912 | 18.664 | 7.426 |

Three repetitions, p50 / p90 in milliseconds, to show the spread:

| series | run 1 | run 2 | run 3 |
| --- | --- | --- | --- |
| round-trip floor (5 B) | 0.492 / 0.681 | 0.472 / 0.757 | 0.458 / 0.655 |
| push 2 KiB | 0.832 / 1.167 | 0.868 / 1.118 | 0.927 / 1.349 |
| echo 2 KiB | 0.780 / 0.998 | 0.947 / 1.300 | 0.909 / 1.316 |
| push 64 KiB | 4.273 / 6.041 | 4.956 / 7.205 | 4.721 / 6.538 |
| echo 64 KiB | 7.002 / 10.251 | 6.659 / 9.583 | 6.570 / 9.152 |

Per-iteration timings are in `e2-raw-timings-run{1,2,3}.csv`
(`series,iteration,request_bytes,response_bytes,nanoseconds`); the `go test -v`
output is in `e2-go-test-run{1,2,3}.txt`.

Read these as an upper bound on the loopback cost rather than a tight number. The
host (AMD EPYC 9354P, 64 cores, kernel 6.11.0-rc3-snp-host) was running other
work during the measurement, and quic-go logged `failed to sufficiently increase
receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB)` —
`net.core.rmem_max` is at the 212992 default, which matters for the 64 KiB series
and not for the 2 KiB one. The order of magnitude is what the ticket needs: the
push costs about one loopback round trip, under a millisecond at the size a
policy will actually be.

## Size: the framing does not constrain a policy

`maxFramePayload` is `16 << 20` = 16777216 bytes
(`attest/tunnel/tunnel.go:348`). A 64 KiB policy is 0.39% of it. Checked
end to end:

- 2 KiB, 64 KiB and 1 MiB pushes all carried and acked.
- 16777217 bytes — one over the bound — is refused by `writeFrame` before
  anything is written: `tunnel: sending the request: tunnel: framing violation:
  16777217 bytes exceeds the 16777216 byte maximum`. The bound is the sender's
  own check, so the peer never sees a violation and the tunnel is **not** torn
  down; the next exchange on the same channel succeeds. (Had the check been the
  receiver's, `Conn.refuse` at `attest/tunnel/tunnel.go:502` would have closed
  the connection.)

## Ordering

`Exchange` opens a stream of its own on every call
(`c.c.OpenStreamSync` at `attest/tunnel/tunnel.go:480`) and `Serve` answers each
accepted stream on its own goroutine (`attest/tunnel/tunnel.go:521`), so a push
cannot interleave with an application exchange and cannot be confused with one:
one stream is one frame is one exchange, and `readFrame` refuses trailing bytes
(`attest/tunnel/tunnel.go:396`-`:403`, ticket 11).

Measured: with a 400 ms application exchange in flight, a 2 KiB push started 50 ms
later returned its ack in **0.96 ms**, and the slow exchange returned 350 ms after
that. The push neither waited on the slow exchange nor received its response.

What this does *not* give is ordering *between* pushes, or between a push and the
application traffic. Concurrent `Exchange` calls are independent streams with no
defined completion order, so if ticket 22 ever needs "the policy was in force
before the next application exchange", A must sequence that itself — wait for the
ack, then proceed — which is what the ticket already says A does.

## A push before admission

Impossible today, and here is the construction that makes it so:

| step | file:line |
| --- | --- |
| `tunnel.Conn`'s fields are unexported and its only constructor, `newConn`, is unexported | `attest/tunnel/tunnel.go:415`, `:437` |
| `newConn` is called from exactly two places, both after admission: the listener, after `answerEstablishment` returned | `attest/tunnel/tunnel.go:197`, `:202` |
| …and `Dial`, after the QUIC handshake (where ratls judged the peer) and after the establishment round trip | `attest/tunnel/tunnel.go:250`, `:254`, `:258` |
| Early data is refused, so no stream can precede the handshake: `Allow0RTT: false` and `quic.DialAddr` rather than `DialAddrEarly` | `attest/tunnel/tunnel.go:143`, `:250` |
| `Cache.Get` hands out only what `Dial` returned, and returns the dial's error otherwise | `attest/tunnel/tunnel.go:606`, `:649` |
| `Tunneld.Peer` returns a `*Channel` only after `t.dialed.Get` succeeded | `attest/tunneld/tunneld.go:361` |
| `Channel.Exchange` takes the tunnel from the cache at the moment it runs | `attest/tunneld/tunneld.go:416` |
| B's side: `Serve` is started only on connections `listener.Accept` produced, which are the established ones | `attest/tunneld/tunneld.go:327` |

Measured: with B's set not admitting A's image, `a.Peer(ctx, "b")` returns no
channel and `tunneld: tunnel not established: … tls: bad certificate`, and B's
handler answered 0 exchanges and saw 0 pushes.

**One gap worth writing the ticket's test against.** `tunneld.Channel` is an
*exported struct* whose fields are all unexported, so `&tunneld.Channel{}`
compiles. Calling `Exchange` on one reaches no peer — but it panics with a nil
pointer dereference at `attest/tunneld/tunneld.go:420` (`c.t.dialed`, where `c.t`
is nil) rather than refusing. So "a push before admission is impossible by
construction" is true in the sense that matters — no bytes leave the process —
but the test ticket 22 wants should either assert the panic honestly or the
package should close it: unexport the struct behind an interface, or have
`Exchange` refuse a `Channel` with no tunneld the way it already refuses a closed
one. This spike does not change either package; it records the behaviour.

## Rerunning

The spike is **not** part of the tree. `e2_policypush_test.go.txt` here is a copy
of a test file that lived temporarily in `attest/tunneld/`; it was deleted after
the run, so `git status` is clean apart from this directory. To rerun it you must
copy it back in first:

```sh
cd /home/pniroula/Projects/gvisor-t22
export PATH="/usr/local/go/bin:$PATH"
cp docs/snp/evidence/ticket22/spikes/E2/e2_policypush_test.go.txt \
   attest/tunneld/e2_policypush_test.go

cd attest
E2_RAW_CSV=/tmp/e2-raw-timings.csv \
  go test ./tunneld/ -run 'TestE2' -v -count=1 -timeout 15m

# and put the tree back
rm /home/pniroula/Projects/gvisor-t22/attest/tunneld/e2_policypush_test.go
```

It compiles only inside `attest/tunneld/` as package `tunneld_test`: it reuses
`start`'s fixtures from `tunneld_test.go` (`platform`, `writeSet`, `writePolicy`,
`everyImage`, `admitting`, `authorPub`/`authorPriv`, `node`, `echo`, `ctx`,
`imageA`/`imageB`/`imageNone`). `E2_RAW_CSV` is optional; without it the
per-iteration timings are simply not written. `-short` skips the timing test.

The four tests:

| test | what it asserts |
| --- | --- |
| `TestE2PushCarriesAPolicyAndBringsBackAnAck` | 2 KiB / 64 KiB / 1 MiB pushes acked; an unknown version refused; the ordinary echo still works |
| `TestE2FrameCeiling` | one byte over 16 MiB is refused by the sender and the tunnel survives |
| `TestE2PushDoesNotInterleaveWithAnApplicationExchange` | a push completes on its own stream while a 400 ms exchange is in flight |
| `TestE2PushBeforeAdmissionIsImpossible` | no channel to an unadmitted peer, 0 exchanges served; and the manufactured-`Channel` gap above |
