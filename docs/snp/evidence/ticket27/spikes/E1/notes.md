# E1 — the window, and who is in it

Ticket 27's first experiment, run on the host on 2026-09-21. Everything here is
reproduced by `./run.sh`, which executes `e1_spike.go` against `bazel-bin/runsc/runsc_/runsc`.

E1 measures the attachment window on loopback across 25 runs, with tunneld and
the exit's client started the way the guest's init starts them and `runsc` started
after:
1. Time from tunneld listening on the sandbox socket to the exit's client attaching.
2. Time from `runsc` starting to the runsc helper attaching.
3. The time at which an early push lands relative to both.
4. Which client answered each push and what it answered.

## Setup

| thing | value |
|---|---|
| date | 2026-09-21T19:04:34Z |
| host | Linux 6.11.0-rc3-snp-host-85ef1ac03941 x86_64 |
| commit | `cea8ae91d294b39ac468cc4676e79bf9a20e0d6b` |
| runsc | `bazel-bin/runsc/runsc_/runsc` (opt build) |
| runs | 25 |
| push policy | version 1 envelope with `n = [test.example:80]`, `x = [/bin/busybox]` |

## The Data

All times are relative to $T_0$ (tunneld listening on unix socket):

| Run | Exit Attach | Runsc Start | Push Time | Helper Attach | From Runsc Start | Answered By | Answer | Helper Enforcing? |
|---|---|---|---|---|---|---|---|---|
| 01 | 961 µs | 1.284 ms | 2.338 ms | 119.863 ms | 118.579 ms | exit | ack | false |
| 02 | 520 µs | 639 µs | 1.814 ms | 114.315 ms | 113.677 ms | exit | ack | false |
| 03 | 580 µs | 799 µs | 2.149 ms | 127.696 ms | 126.897 ms | exit | ack | false |
| 04 | 331 µs | 470 µs | 1.488 ms | 144.194 ms | 143.724 ms | exit | ack | false |
| 05 | 294 µs | 387 µs | 1.436 ms | 147.329 ms | 146.943 ms | exit | ack | false |
| 06 | 477 µs | 710 µs | 2.065 ms | 163.345 ms | 162.636 ms | exit | ack | false |
| 07 | 464 µs | 752 µs | 2.401 ms | 138.079 ms | 137.327 ms | exit | ack | false |
| 08 | 580 µs | 938 µs | 2.057 ms | 98.211 ms | 97.273 ms | exit | ack | false |
| 09 | 461 µs | 983 µs | 2.971 ms | 133.713 ms | 132.731 ms | exit | ack | false |
| 10 | 538 µs | 729 µs | 2.171 ms | 134.756 ms | 134.027 ms | exit | ack | false |
| 11 | 610 µs | 887 µs | 2.678 ms | 186.926 ms | 186.040 ms | exit | ack | false |
| 12 | 521 µs | 684 µs | 1.736 ms | 168.224 ms | 167.541 ms | exit | ack | false |
| 13 | 599 µs | 744 µs | 2.306 ms | 173.542 ms | 172.798 ms | exit | ack | false |
| 14 | 863 µs | 1.189 ms | 2.580 ms | 131.222 ms | 130.034 ms | exit | ack | false |
| 15 | 354 µs | 671 µs | 1.782 ms | 141.908 ms | 141.237 ms | exit | ack | false |
| 16 | 557 µs | 1.072 ms | 2.387 ms | 154.141 ms | 153.068 ms | exit | ack | false |
| 17 | 403 µs | 594 µs | 2.704 ms | 162.520 ms | 161.926 ms | exit | ack | false |
| 18 | 409 µs | 650 µs | 1.892 ms | 129.639 ms | 128.989 ms | exit | ack | false |
| 19 | 452 µs | 795 µs | 2.378 ms | 136.291 ms | 135.495 ms | exit | ack | false |
| 20 | 276 µs | 479 µs | 1.444 ms | 118.099 ms | 117.620 ms | exit | ack | false |
| 21 | 426 µs | 820 µs | 2.259 ms | 159.870 ms | 159.051 ms | exit | ack | false |
| 22 | 329 µs | 497 µs | 1.594 ms | 151.553 ms | 151.056 ms | exit | ack | false |
| 23 | 655 µs | 998 µs | 2.424 ms | 128.901 ms | 127.903 ms | exit | ack | false |
| 24 | 412 µs | 569 µs | 1.640 ms | 125.137 ms | 124.568 ms | exit | ack | false |
| 25 | 642 µs | 845 µs | 1.900 ms | 135.417 ms | 134.572 ms | exit | ack | false |

## Statistics: Runsc Start -> Helper Attach

| Metric | Latency |
|---|---|
| Min | 97.273 ms |
| p50 | 135.495 ms |
| Mean | 140.228 ms |
| p90 | 167.541 ms |
| Max | 186.040 ms |

## Findings

1. **The exit client attaches in sub-millisecond time**: mean ~500 µs after tunneld begins listening on the socket.
2. **The runsc helper attaches in ~100–186 ms** from container process creation (`runsc run`).
3. **The push race (Leftover 21 reproduction)**: When a policy push lands early (e.g. at 1.4–3.0 ms after socket listen, simulating a peer dialing immediately upon boot), `Host.Apply` sees only one connection attached (`conns = [exit]`). It pushes to the exit client, which immediately acknowledges (`ack`). The push returns success (`SANDBOX applied`) to the caller in under 4 ms.
4. **Enforcement is absent**: 100% of early pushes (25 of 25) were answered by the exit. The enforcing runsc helper attached ~100–150 ms later and received nothing.
5. **Attach delay is bounded**: Across all 25 runs, the helper attachment was bounded between 97 ms and 186 ms (consistent with leftover 19's 130–201 ms cluster).
6. **Can `Host.Apply` wait?**: Yes. `DefaultPushTimeout` is 10 s (`10,000 ms`). The maximum attach time observed was 186 ms, and even leftover 19's outlier of 2.138 s leaves an ~80% safety margin under 10 s. Waiting for the enforcing attachment inside the existing caller deadline is feasible without raising `DefaultPushTimeout`.
