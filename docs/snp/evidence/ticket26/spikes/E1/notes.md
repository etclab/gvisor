# E1 — narrowing under traffic: can the sentry's table be replaced while a stream is carrying bytes?

Ticket 26's first experiment, run on the workstation on 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t26`, branch
`ticket-26-the-sandbox-honors-a-pushed-policy`. No sudo, no hardware, no
tunneld, no API key and nothing paid.

The ticket's stop rule points at this experiment: *"Stop and report if E1 shows
the table cannot be replaced without dropping the workload, rather than working
around it with a restart."* It can be replaced, it does not drop the workload,
and the numbers below are what it costs.

## Setup

| thing | value |
|---|---|
| runsc | `make runsc` `-c opt`, sha256 `2083b906e8b4ad3231477ab1b9ffd06a992be02c54ac032081d19bed3790d986` |
| faketunneld | `faketunneld/`, sha256 `872fd0889ad016e4750f3e45ac8fd9aaaa0052e046dc2430c238c81fc467bc50` |
| seccheck-receiver | `../../tools/seccheck-receiver/`, sha256 `d7be04465f899c4af6f5c94de2307cde5bd220679497db2455ea085189d509dd` |
| workload | `e1-workload.sh`, sha256 `9371cb27221a3a65dd9dfaeda66958f0a8d9c8beecb1f33ca201b0b8700f942a` |
| busybox | `/bin/busybox` 1:1.36.1-6ubuntu3.1, sha256 `dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14` |
| sandbox flags | `--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=… --tunnel-table=… --pod-init-config=… --debug` |
| the slow body | 16,777,216 bytes, 65,536 per 50 ms, so one stream is open for about 13 s |

Everything here is reproduced by

    ./run-e1.sh <runsc> <workdir> <faketunneld> <seccheck-receiver> ./e1-workload.sh

and `output-01-narrowing-under-traffic.txt` is the untrimmed transcript of the
run these numbers come from. The prototype is not a patch: it is the
implementation as committed on this branch, and `run-e1.sh` names the binary's
sha256 so a later reader can tell which build answered.

**What the stand-in is.** `faketunneld/` is ticket 25's adapter-check stand-in
with two additions: it *pushes* policies through `attest/sandbox`'s
`Host.Apply` on a command from its stdin and prints the acknowledgement or the
refusal with the wall time of the round trip, and its exit serves its own bytes
rather than dialling anywhere — one name is a slow body of a fixed size, every
other permitted name a short page. There is no tunnel, no QUIC and no
attestation in it; **nothing here is evidence about tunneld.**

## The two runs

The table is twelve names: `bulk.peer-a:9000` (the slow body), `drop.peer-a:9001`
(a short page) and ten fillers `fill01…fill10.peer-a:9002` that exist so that a
narrowing can be measured more than twice.

| run | the stream is on | the first narrowing removes |
| --- | --- | --- |
| `narrow-other` | `bulk.peer-a` | `drop.peer-a` — the OTHER name |
| `narrow-self` | `bulk.peer-a` | `bulk.peer-a` — the name the open stream is **on** |

Each run pushes thirteen policies: `p00` is the whole table (the push that fixes
`f` and `x`), `p01` is the narrowing the workload watches for, `p02`–`p11` drop
one filler each, and `p99` tries to put every name back. Twelve of the thirteen
are accepted, so 24 narrowings were measured across the two runs.

**The narrowing is synchronised on the traffic, and that took a second attempt.**
The first version of this script slept four seconds after the first push and
then narrowed. It pushed the narrowing *ten seconds before the stream started*:
the workload's two `nslookup` calls take about seven seconds each through the
sentry's responder, so "under traffic" was not true of that run and its
`LONG COMPLETE` proved nothing. The script now waits for the workload's
`LONG STARTED` line and then lets the stream run for three seconds. In the
recorded run the narrowing lands at 19:05:25 with the stream started at
19:05:21 and finishing at 19:05:35.

## 1. The open stream survives, and the byte counts are equal

    narrow-other   workload: LONG STARTED pid=18 at 19:05:21
                   (the narrowing lands at 19:05:25)
                   workload: LONG COMPLETE bytes=16777216 expected=16777216 at 19:05:35

    narrow-self    workload: LONG STARTED pid=18 at 19:05:56
                   (the narrowing that removes bulk.peer-a lands at 19:05:59)
                   workload: LONG COMPLETE bytes=16777216 expected=16777216 at 19:06:09

Both runs take the whole body. The second is the one that says something: the
name the stream was **on** was removed from the policy in force, from the
resolver and from the table, four seconds into a thirteen-second transfer, and
the transfer still delivered all 16,777,216 bytes.

**That is by design and it is not a bug, but it is a limit and the record must
say so plainly: narrowing decides what may be OPENED next, and there is no
revocation.** A descriptor already handed to a socket is that socket's; the
sentry keeps no registry of attached endpoints per name, and `NarrowTunnel`
replaces the adapter without touching one. A policy pushed to stop an exfil in
progress would not stop it. What it stops is the next connection.

## 2. A new connect to the removed name is refused, at the resolver and at the address

The removed name, asked for by name:

    workload: NARROWED drop.peer-a:9001 stopped resolving on attempt 3 at 19:05:25:
              wget: bad address 'drop.peer-a:9001'
    workload: AFTER resolve drop.peer-a: … ** server can't find drop.peer-a: NXDOMAIN
    workload: AFTER GET http://drop.peer-a:9001/ rc=1 out='wget: bad address …'

and the same name's **old synthetic address**, dialled directly:

    workload: AFTER GET the removed name's old address http://100.64.1.1:9001/ rc=1
              out='wget: can't connect to remote host (100.64.1.1): Network is unreachable'

Both halves are recorded, with the reason that decided each:

    egress_refused protocol=dns name=drop.peer-a reason=unknown-name  time=2026-09-18T19:05:25…
    egress_refused protocol=dns name=drop.peer-a reason=unknown-name  time=2026-09-18T19:05:25…
    egress_refused protocol=tcp address=100.64.1.1 port=9001 reason=not-in-table
                   time=2026-09-18T19:05:25… container_id=t26-e1-narrow-other-… thread_id=30

Two DNS events for one name because busybox asks AAAA and A; the TCP event
carries a task's context and the DNS ones do not, which is ticket 25's finding
and unchanged here. The same pair appears in `narrow-self` for `bulk.peer-a` at
`100.64.1.0`.

## 3. Surviving names keep their addresses

    BEFORE resolve bulk.peer-a: … Name: bulk.peer-a Address: 100.64.1.0
    AFTER  resolve bulk.peer-a: … Name: bulk.peer-a Address: 100.64.1.0

across eleven narrowings in the same run, including ten that each removed a
different filler from the middle of the sorted list. The addresses are **not**
reallocated by sorted index at each narrowing: a surviving name carries its
binding forward unchanged, which is what makes an address a workload resolved
before a narrowing still the same destination after it. The sentry says the same
thing from its side, one line per name it drops:

    tunnel narrow: drop.peer-a:9001 at 100.64.1.1 is gone
    tunnel narrow: 11 of 12 names kept

## 4. What a swap costs

Three clocks, 24 narrowings each (12 per run), from
`output-01-narrowing-under-traffic.txt`:

| what is measured | n | min | median | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: |
| the table swap inside the sentry (`NarrowTunnel` + the boot-side table) | 24 | 0.058 ms | **0.161 ms** | 0.643 ms | 0.718 ms |
| the whole of `Policy.Narrow` in the sentry (parse, subset check, swap, record) | 24 | 0.233 ms | **0.616 ms** | 2.154 ms | 3.156 ms |
| `Host.Apply` wall time, from the call to its return | 24 | 2.015 ms | **3.161 ms** | 23.385 ms | 30.018 ms |

The first two are the sentry's own log lines (`tunnel narrow: applied in …, of
which the table swap was …`); the third is the stand-in's, and it is everything:
the contract's socket, the helper's callback goroutine, a fresh
`client.ConnectTo` on the control socket, urpc, the sentry, and the same path
back. **The gap between 0.6 ms and 3.2 ms is the boundary, not the enforcement.**
The two samples above 20 ms are both the *first* push of a run — the control
socket has never been dialled before, and the sandbox is still starting other
things.

The largest single sentry-side sample, 3.156 ms, is also a first push: twelve
names, twelve bindings built, and the Go allocator cold. Every later swap in the
same sandbox is under a millisecond.

## 5. What the workload observed

Nothing, except that a name stopped working. There is no signal, no error on the
open stream, no EOF, no reconnect, and no message of any kind: the narrowing is
invisible to a running process apart from the destinations it can no longer
reach. The workload's own account, in order, is in
`output-01-narrowing-under-traffic.txt` under `---- what the workload said ----`.

The surviving name keeps working *for new connections too* — `AFTER GET
http://bulk.peer-a:9000/ rc=0` in `narrow-other` — so a narrowing is not a
general disturbance of the adapter.

## 6. A widening is refused, and the refusal names the component

The thirteenth push puts every name back:

    APPLY p99-widen.json REFUSED elapsed=2.534217ms
      err=sandbox: policy refused: the sandbox refused it: policy refused:
          it widens n by [net:drop.peer-a:9001 net:fill01.peer-a:9002 … net:fill10.peer-a:9002]

The sentence is the sentry's, carried back through the helper and the contract
word for word: `attest/sandbox` prefixes its own `sandbox: policy refused: the
sandbox refused it:` and adds nothing else. The table in force is unchanged
afterwards, and the surviving name still works.

## 7. Two findings this experiment produced and did not fix

**(a) `--root` has 108 bytes to spend, and a policy push is where you find out.**
The first run of this script failed every push with

    policy refused: reaching the sentry at <…>/state/runsc-<id>.sock: invalid argument

`Policy.Narrow` is delivered over the sentry's control socket, whose path is
`--root` plus `runsc-<container id>.sock`. `pkg/unet.Connect` hands that path
straight to `connect(2)` in a `sockaddr_un`, which holds 108 bytes, so a deep
`--root` or a long container id is `EINVAL` — and `EINVAL` from a `connect` is
what the peer that pushed the policy is told. This is not new in this ticket
(every `runsc state`/`kill` on such a sandbox fails the same way) and nothing
here changes it; the harness now uses a short root under `/dev/shm`. **A
deployment that puts `--root` somewhere deep silently loses the ability to
narrow.** Recorded for the record's leftovers.

**(b) `nslookup` costs about seven seconds per name through the responder.**
Every `busybox nslookup` in these runs took ~7 s wall, against milliseconds for
the `wget` that follows it on the same name. The responder answers A and AAAA
(the transcript shows both) so the delay is in what busybox does *after* the
answers — most likely the reverse lookup of the server address, for which the
responder has no opinion and answers NXDOMAIN. Nothing in the design depends on
`nslookup`; it is used here only to print an address. Not investigated further.

## 8. Verdict

Apply-without-restart is real. A policy pushed over the contract replaces the
sentry's table in a running sandbox in a median of **0.16 ms** of swap and
**3.2 ms** of end-to-end wall time, with the workload running throughout, a
16 MiB transfer in flight delivering every byte, new connections to removed
names refused at the resolver and at their old addresses with the reason
recorded, and surviving names keeping the addresses they already had. The stop
rule is not triggered.

## 9. Files

| file | what |
| --- | --- |
| `run-e1.sh` | the two runs, exactly as run |
| `e1-workload.sh` | the workload, inside the sandbox |
| `faketunneld/` | the stand-in: `attest/sandbox`'s socket, a pushing `Host.Apply`, and an exit that serves its own bytes |
| `output-01-narrowing-under-traffic.txt` | the untrimmed transcript, including every policy pushed and its digest |
| `../../tools/seccheck-receiver/` | the receiver the `egress_refused` lines come from |
