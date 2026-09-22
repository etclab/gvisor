# E2 — a policy delivered twice

Ticket 27's second experiment, run on the host on 2026-09-21. Everything here is
reproduced by `./run.sh`, which executes `e2_spike.go` against `bazel-bin/runsc/runsc_/runsc`.

E2 asks whether late-attach delivery is available, and at what cost:
1. Apply a policy to a sandbox.
2. Deliver the same bytes again to the same sentry (replay of policy in force).
3. Separately deliver to a sentry that has just attached with no policy in force.
4. Record what `Policy.Narrow` answers each time, the digest it returns, whether the subset check reads a replay of the policy in force as a narrowing of itself, and the cost per delivery.

## Setup

| thing | value |
|---|---|
| date | 2026-09-21T19:05:15Z |
| host | Linux 6.11.0-rc3-snp-host-85ef1ac03941 x86_64 |
| commit | `cea8ae91d294b39ac468cc4676e79bf9a20e0d6b` |
| runsc | `bazel-bin/runsc/runsc_/runsc` (opt build) |
| policy | `{"format":"policy","version":1,"n":[{"host":"test.example","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}` |
| digest | `e1a4ddd603e1edfba4479099c174dd815534b9174c4c74ea32a08f88ad7ce3e8` |

## Results

### 1. Delivery to the Same Sentry

| Step | Call | Status | Digest | Latency |
|---|---|---|---|---|
| Delivery 1 | First push to sentry A | `err=<nil>` | `e1a4ddd6...` | 4.861 ms |
| Delivery 2 | Replay of same policy to sentry A | `err=<nil>` | `e1a4ddd6...` | 2.264 ms |

### 2. Replay Benchmark (50 Trials on Sentry A)

| Metric | Latency |
|---|---|
| Min | 906 µs |
| p50 | 1.252 ms |
| Mean | 1.867 ms |
| p90 | 2.838 ms |
| Max | 18.148 ms |

### 3. Delivery to Fresh Sentry B (No Policy in Force)

| Call | Status | Digest | Latency |
|---|---|---|---|
| Delivery to sentry B | `err=<nil>` | `e1a4ddd6...` | 3.182 ms |

## Findings

1. **Subset check behavior**: The subset check in `runsc/boot/policy.go` compares the atoms of the incoming policy against the atoms in force (`base = tn.policy.inForce`). When the incoming policy is identical to the policy in force, every atom is contained in `base`, so `policySubset` returns `nil`. The sentry accepts the replay as a non-widening narrowing of itself.
2. **Digest consistency**: The sentry returns the exact SHA-256 digest on both initial application and replay (`e1a4ddd603e1edfba4479099c174dd815534b9174c4c74ea32a08f88ad7ce3e8`).
3. **Delivery cost**: The marginal cost of delivering a policy replay to a running sentry is ~1.25 ms (p50), ~1.87 ms (mean). A first delivery took 3.181803 ms to sentry B and 4.860595 ms to sentry A.
4. **Availability of late-attach delivery**: Late-attach delivery is completely available at low cost (~1–2 ms) and requires no sentry changes. A host can keep the policy in force and replay it to an enforcing attachment that arrives late; the sentry applies it and pulses the matching digest immediately.
