# E3 — liveness after the tunnel is gone

Ticket 27's third experiment, run on the host on 2026-09-21. Everything here is
reproduced by `./run.sh`, which executes `e3_spike_test.go` as a test inside
`attest/tunneld`.

E3 measures what happens when a policy is pushed, the tunnel idles out under its
default 60 s idle timeout (`tunnel.DefaultIdleTimeout`), and the sandbox stops
enforcing afterwards:
1. What the host's watch observes.
2. How long after the failure it observes it.
3. What tunneld logs.
4. What a stream opened afterwards does.
5. Covers both failure paths: `kill` (socket close) and `stop` (three missed pulses).

## Setup

| thing | value |
|---|---|
| date | 2026-09-21T19:06:10Z |
| host | Linux 6.11.0-rc3-snp-host-85ef1ac03941 x86_64 |
| commit | `cea8ae91d294b39ac468cc4676e79bf9a20e0d6b` |
| tunnel idle timeout | 60 s default (`tunnel.DefaultIdleTimeout`) |
| wait for idle | 62 s |
| policy | `policyV1` (digest `8c1062e8310ede7c8b9c0ff20057b17681fa6d6f6e8b236535ae2bc75978cea4`) |

## Results

### 1. `kill` (Workload process killed with `SIGKILL` — socket closes)

| Metric | Observation |
|---|---|
| Host watch detection | `the sandbox closed its socket` |
| Latency from kill | **250.404 ms** (detected on the first 250 ms tick of `watchInterval`) |
| Tunneld logs | **0 new refusals** (silent) |
| Stream attempt afterwards | Fails: `tunneld: unknown peer: "b" is not in the peer table` (`output.txt:16`) |

### 2. `stop` (Workload paused with `SIGSTOP` — socket remains open, pulses cease)

| Metric | Observation |
|---|---|
| Host watch detection | `it missed 3 pulses` |
| Latency from stop | **3.000 s** (`DefaultMisses * DefaultPulse` = 3 × 1 s) |
| Tunneld logs | **0 new refusals** (silent) |
| Stream attempt afterwards | Fails: `tunneld: unknown peer: "b" is not in the peer table` (`output.txt:30`) |

## Findings

1. **`watchLiveness` terminates with the tunnel**: On master, `watchLiveness` in `attest/tunneld/push.go:263-264` polls `conn.Live()` on each 1 s tick. When the tunnel idles out after 60 s, `conn.Live()` becomes false, and `watchLiveness` returns silently.
2. **Tunneld remains silent when liveness is lost**: After `watchLiveness` terminates, nobody in tunneld is watching the sandbox. When the workload is killed or stopped, `Host.Watch` still detects the loss (in 250 ms for close, 3.0 s for missed pulses), but tunneld logs nothing, records no refusal, and performs no action.
3. **The defect of the alternative**: If a miss with no open tunnel only logs or does nothing, a stopped/unpoliced sandbox whose socket remains connected can still receive streams.
4. **Resolution for open question 3**: When liveness is lost and no tunnel is open, the attachment must be dropped, the host's policy state marked not-live, logged as `ReasonPolicyNotLive` stating that no tunnel was closed because none was open, and no stream handed to that sandbox again until a policy is applied.
