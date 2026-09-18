# E3 — what one `alive` per second costs, and how long a tunnel takes to go down after it stops

Ticket 26's third experiment, run on the host on 2026-09-18.  Everything here is
reproduced by `./run.sh`, which copies `e3_spike_test.go` into `attest/tunneld`,
runs it there and removes it again.

E3 asks whether contract version 3's two constants are the right ones.  The
contract's gap is ticket 23's finding: an acknowledgement is a claim about the
past, measured there as a sandbox acknowledging 1.856 ms after `exec.Start` and
its workload dead at 43 ms with the tunnel still up.  Version 3 closes it with a
heartbeat — one `alive` message per `sandbox.DefaultPulse` carrying the digest of
the policy in force, and liveness lost after `sandbox.DefaultMisses` consecutive
misses, a digest that does not match, or a closed socket.  The constants are
`DefaultPulse = 1s` and `DefaultMisses = 3`.  E3 measures what they cost, what
they buy, and what the two alternatives the ticket names would have given
instead.

The three ways liveness is lost are driven by three signals to the sandbox
process, which is what makes them one harness:

| case | signal | what the far side sees |
|---|---|---|
| `kill` | `SIGKILL` | the socket closes |
| `wrong` | `SIGUSR1`, on which the child calls `Client.Alive` with a digest that is not the pushed one | a pulse for another policy |
| `stop` | `SIGSTOP` | nothing at all, with the socket still open |

`SIGSTOP` is the honest spelling of "a client that stops pulsing without
closing": the process is still there, its socket is still open, and nothing comes
out of it.  It is also a real failure mode rather than an invented one — a guest
paused, a sentry wedged — which is the case the miss count exists for.

## Setup

| thing | value |
|---|---|
| date | 2026-09-18T14:33:54-04:00 |
| host | Linux 6.11.0-rc3-snp-host-85ef1ac03941 x86_64 |
| cpu | 64 online, AMD EPYC 9354P 32-Core Processor |
| load average at the start | 24.18 12.14 5.77 — another agent's build was running throughout, so every number here is an upper bound rather than a quiet-machine best case |
| go | go1.26.3 linux/amd64 |
| commit | `5f7691a47` plus the uncommitted contract v3 working tree |
| spike | `e3_spike_test.go`, sha256 `0740c3d4815274322dbfa33163a057a526d2951e56f8f1b2f2974e76e8fde969` |
| code measured | `attest/sandbox/{live,socket,client,host}.go` and `attest/tunneld/push.go`, the prototype being what the branch then committed unchanged — there is no `patch-*.diff` because there was no difference.  Two things landed on those files *after* this run and touch nothing it measured: `attest/sandbox/host.go` gained `Host.said`, one console line per acknowledged push, on the `Apply` path and not on the heartbeat or the watch; and `attest/refusal.go`'s new doc comment was shortened.  Neither is on the send path, the receive path, the ticker or the teardown |
| wiring | two tunnelds on loopback with the fake platform (`start`, `startPushNode`, `toward`, `pushing` from the package's own harness), an `AF_UNIX` socket between the receiving one and a sandbox in a second process, and signals |
| network, hardware, keys | none.  No API call was made and no money was spent |

The parent measures the end of a phase by watching for a **sentinel digest** —
`e3e3…e3`, 64 hex, which no policy has.  The child pulses it when it is done and
the parent's `Watch` fires on the mismatch, which gives an instant the parent can
timestamp without `sandbox.Host` growing an accessor nothing in production would
use.

## 1. What a pulse costs

Line numbers are lines of `output-01-cost.txt`.

### Send side, in the sandbox

10 000 pulses through `Client.Alive`, each one timed on its own (lines 10–11):

| | value |
|---|---|
| total | 10 000 pulses in 306.831361 ms |
| mean | 30.174 µs |
| min | 5.087 µs |
| p50 | 17.015 µs |
| p90 | 35.213 µs |
| p99 | 84.727 µs |
| max | 14.797646 ms |

One pulse is one `sendmsg` of a 99-byte JSON message — 103 bytes on the wire,
with the length prefix — under one mutex.  The p50 of 17 µs is that syscall; the
tail is the machine, at load average 24, and the one 14.8 ms outlier in ten
thousand is a scheduling delay and not a cost.  **At one per second this is
0.003% of one core.**

### Receive side, in tunneld

Measured as this process's own `RUSAGE_SELF` user+system time (lines 4–7):

| | CPU | over |
|---|---|---|
| nothing attached | 614 µs | 10 s |
| one attachment pulsing at 1 Hz | 3.167 ms | 10 s |
| **difference, per pulse at 1 Hz** | **255.3 µs** | 10 pulses |
| a burst of 10 000 | 507.197 ms over 500.54665 ms wall | **50.719 µs per message** |

The two numbers are both real and answer different questions.  In a burst the
wakeup is amortised and 50.7 µs is the marginal cost of the message — the read,
the JSON, the two mutexes.  At one hertz, which is the rate the contract actually
runs at, each message costs a process wakeup as well, and 255.3 µs is what a
guest pays.  **That is 0.026% of one core per attached sandbox**, or 22 seconds
of CPU per day.  Neither number is a reason to choose one interval over another.

## 2. Drift

`output-02-drift.txt`.  Two views of the same minute: the ticker in the sandbox,
and the wall clock in tunneld.

| | value |
|---|---|
| 60 ticks of a 1 s `time.Ticker`, elapsed | 1m0.000165439s |
| cumulative drift over 60 s | **165.439 µs** |
| worst single tick lateness | **2.865325 ms** |
| interval, min / p50 / max | 997.904068 ms / 1.000028394 s / 1.002242084 s |
| 60 pulses, sent and received end to end | 1m0.250239781s, of which ≤250 ms is the watch's own quarter-pulse tick |

A Go `time.Ticker` does not accumulate drift — it adjusts — so the interesting
number is not the 165 µs but the 2.865 ms worst lateness, which is how late a
single pulse got on a machine at load average 24.  **The miss threshold has to be
larger than that lateness, and 3 s is 1 000 times it.**

## 3. Teardown, ten trials of each case

`output-03-teardown.txt`.  Each trial is a fresh pair of tunnelds, a policy
pushed over the tunnel, a stream held open on it by the pusher, and then the
sandbox made to fail.  The measured interval runs from the signal to the pusher's
held stream ending — which is what "the tunnel is down" means to the side that
pushed, since nothing about the reason crosses the wire.

The failure instant is deliberately swept: trial *i* fails at `2s + i·100ms`
after the acknowledgement, so the ten trials cover the whole interval rather than
landing on the beat ten times.  Without the sweep every trial reads the same
number and the spread the constants actually produce is invisible.

| case | n | min | median | max | mean |
|---|---|---|---|---|---|
| `kill` (socket closed) | 10 | 49.923943 ms | 150.597202 ms | 251.193851 ms | 150.166507 ms |
| `wrong` (digest mismatch) | 10 | 50.007518 ms | 150.666453 ms | 250.797411 ms | 150.349544 ms |
| `stop` (3 misses) | 10 | 2.100802209 s | 2.851786545 s | 3.25096344 s | 2.775334297 s |

Every trial, in the order they ran:

```
kill   251.193851ms 150.597202ms 49.966327ms 199.348285ms 99.560669ms
       251.136387ms 149.728905ms 49.923943ms 199.255057ms 100.954446ms
wrong  250.797411ms 150.666453ms 50.007518ms 200.641764ms 100.632676ms
       249.70971ms  149.832981ms 50.872968ms 200.369387ms 99.964581ms
stop   3.25096344s  3.150624302s 3.049837937s 2.950387062s 2.851786545s
       2.750351583s 2.649636755s 2.550634118s 2.448319025s 2.100802209s
```

All thirty were refused as `the policy pushed to the peer is no longer live`,
which is the eleventh reason in the taxonomy and the one this ticket adds.

### The model the numbers fit

A watch looks at what each attachment last said every `watchInterval`, which is
`DefaultPulse/4` = 250 ms.  So:

* **closed or mismatched**: detected at the first tick after the event, i.e. in
  `[0, 250 ms]`.  The ten `kill` and ten `wrong` trials land on
  {50, 100, 150, 200, 250} ms, which is the 100 ms sweep taken modulo the 250 ms
  tick, and the two cases are indistinguishable from each other — as they should
  be, since both are known the moment they arrive and only the tick separates
  them from being instant.
* **missed pulses**: liveness is lost when `now − last > M·P`, so the wall time
  from the failure is `M·P − A + G`, where `A ∈ [0, P)` is how old the last pulse
  already was and `G ∈ [0, P/4]` is the tick.  That is `[(M−1)·P, M·P + P/4]`.
  For M=3, P=1 s: **[2.000, 3.250] s**, and the measured range is
  [2.101, 3.251] s.  The sweep reproduces the whole interval, one trial per
  tenth.

## 4. What the two alternatives would have given

Applying the model, with the same measured 250 ms (or a quarter-interval) tick:

| pulse × misses | teardown after a stopped sandbox | margin before a false positive | receive cost per attachment |
|---|---|---|---|
| **1 s × 3 (built)** | **[2.00, 3.25] s**, measured [2.10, 3.25] | 3 s, ≈1 000× the worst measured lateness | 255 µs/s = 0.026% of a core |
| 0.5 s × 3 | [1.00, 1.625] s | 1.5 s, ≈520× | ≈510 µs/s = 0.05% of a core |
| 1 s × 2 | [1.00, 2.25] s | 2 s, ≈700× | unchanged |

Neither alternative is expensive and neither is dramatic.  0.5 s × 3 buys 1.6 s
of teardown for twice the wakeups; 1 s × 2 buys 1 s of teardown for free and
spends a third of the margin.

## 5. The verdict on the constants

**1 s and 3 misses stand.**  The reasoning, in the order it actually decided:

1. **Cost decides nothing.**  0.026% of one core on the receiving side and 0.003%
   on the sending side.  Any interval between 100 ms and 10 s is affordable, so
   the interval is not a performance choice and must not be argued as one.
2. **Jitter does not buy the third miss.**  The worst lateness of a pulse was
   2.865 ms over 60 ticks and the worst single send 14.8 ms out of 10 000, both
   on a 64-core machine at load average 24.  Two misses at a one-second pulse
   already leaves 2 s of margin, which is 700 times the worst thing measured.  A
   constant justified by measured jitter alone would be 2.
3. **The third miss is bought by what jitter does not sample**, and by what a
   false positive costs.  A guest paused for live migration, a sentry stalled, a
   second of scheduler starvation under a burst: none of these appear in a
   60-tick sample on an idle-ish host, and all of them stop a pulse for longer
   than 15 ms.  A false positive is not cheap — `docs/policy-push.md` records
   that a refusal is not cached, so the tunnel goes, the handshake is burned, and
   the delegator's caller is told it was refused.  Paying one extra second of
   exposure to avoid tearing down a working tunnel on a hiccup is the cheaper
   side of that trade.
4. **The exposure being bought down is unbounded today**, so the absolute number
   matters less than the fact that it is finite.  Ticket 23 measured the gap as
   "the tunnel is still up" with no end at all; [2.1, 3.3] s is not a compromise
   against 0, it is a bound against infinity.
5. **One second is the resolution, not the budget.**  A pulse per second is the
   granularity at which "the workload is gone" becomes a fact on the far side of
   a tunnel.  Making it 100 ms would make the teardown 300 ms and would also make
   the heartbeat the most frequent thing on the socket by two orders of
   magnitude, in a measured image where every wakeup is visible in a console
   transcript.

## 6. Findings the record must carry

* **The teardown is bimodal by design and that is the right shape.**  A sandbox
  that says the wrong thing, or stops saying anything by going away, is caught in
  ≤250 ms; a sandbox that goes quiet without going away takes 2.1–3.3 s.  The
  fast path covers the case ticket 23 named — the workload exits, the helper's
  link ends, the socket closes — so **the case the ticket was written for is the
  250 ms one**, not the three-second one.
* **The 250 ms is the watch's own tick and nothing else.**  Closing and
  mismatching are both known the instant the message (or the EOF) arrives; the
  watcher is a polling loop and rounds them up to its quarter-pulse.  Waking the
  watcher on each pulse instead would make both cases sub-millisecond.  It is not
  built: a quarter of a second is already an order of magnitude inside the miss
  path, and a poll is one loop instead of a fan-out from every attachment to
  every watch.
* **The pulse phase, not the failure, decides how long a miss takes.**  Anyone
  reading a single teardown number off a console is reading one sample from a
  1-second-wide uniform distribution.  The record should quote the interval.
* **Every number here was taken on a machine at load average 24.**  They are
  upper bounds.  A quiet host will do better and the constants do not depend on
  it.
* **Nothing was fixed here.**  Per the ticket's own rule, E3 measures and the
  definition of done builds.  The one design decision E3 did settle is the
  `watchInterval = DefaultPulse/4` above, which is why the close and mismatch
  numbers are what they are.
