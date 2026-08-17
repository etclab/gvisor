# The ladder

Five rungs, each removing one kind of authority an agent gets for free, each with a
demo that shows the previous rung's attack succeeding and this rung's blocking it.

Design narrative: `agent-sandbox/deck.html`. Implementation contract:
[`specs/00-conventions.md`](specs/00-conventions.md) — read it before any rung.

| Rung | Name | Status | Tag | Flags | Claim |
|---|---|---|---|---|---|
| 0 | [Ambient authority](rung0/README.md) | implemented | `rung-0` | none (config only) | reachable damage equals the broker's tool allowlist plus one allowlisted host plus `/scratch` |
| 1 | [Task scoping](rung1/README.md) | implemented | `rung-1` | `--ladder-task-scope` (claim 4 only) | reachable damage equals **this task's** manifest — its tool set, its allowlisted hosts, its own scratch — and a grant can be narrowed mid-task but never widened |
| 2 | [Taint bit](rung2/README.md) | implemented | `rung-2` | `--ladder-taint` (+ `--ladder-untrusted-paths`, `--ladder-privileged-sinks`) | reading from a labeled-untrusted source sets a monotonic sandbox-wide bit in the runtime, after which writes to the broker socket are refused before the bytes leave the sandbox |
| 3 | [Two agents, confused deputy](rung3/README.md) | implemented | `rung-3` | `--ladder-attest` (+ `--ladder-peer-channels`, `--ladder-identity`, `--ladder-grants`) | a message leaving a sandbox for a peer is stamped by the runtime with the sender's identity, taint bit and grants, which the sending agent cannot forge or suppress; the receiver inherits an accepted tainted message's taint, so rung 2's gate refuses the call the message asked for |
| 4 | Chain attenuation | not started | — | `--ladder-chain` | — |

## Running a demo

```
make demo RUNG=0                              # the three-check demo for one rung
make demo RUNG=0 ARGS=--baseline-runtime=runc # baseline under plain runc
make demo-all                                 # every implemented rung, for regressions
make build                                    # just build the images
make clean                                    # remove containers, networks, images, state
```

Every demo runs three checks in order — BASELINE (the attack, which must succeed),
ENFORCED (the same attack, which must be blocked with named evidence), CONTROL (a
legitimate task, which must still work) — and exits 0 only if all three met
expectation. A rung may add further `ENFORCED-N` blocks for claims the three do not
cover; rung 1 adds two. A committed transcript of a passing run lives in each rung's
`expected/`.

## Prerequisites

- **docker**, with the caller in the `docker` group. Root is not required for rung 0.
- **a `runsc` runtime registered with the docker daemon.** Check with
  `docker info --format '{{json .Runtimes}}' | grep -o runsc`. Rungs 0 and 1 run against
  whatever runsc is installed — rung 1's task scoping is orchestration, not a patch. A
  runtime built from this tree is needed only for the parts gated behind a `--ladder-*`
  flag: one optional block in rung 1, and **all** of rungs 2 and 3, whose claims live
  inside the runtime. Each rung's README gives the exact registration command. Rung 3
  needs rung 2's `ladder-taint` runtime still registered — its BASELINE runs against
  it, because rung 2's configuration *is* rung 3's baseline.
- **python3** on the host, for the broker.
- No internet access, no API keys, no cloud account. Every host the sandboxed agent can
  reach is a local container.

## Layout

```
ladder/
  specs/        the implementation briefs, copied in from the design repo
  common/       harness shared by every rung: agent, broker, probes, world, helpers
  rung0/ ...    per rung: README (the artifact to read), demo.sh, config, expected/
```

`common/README.md` describes the harness. The short version: **the agent is a script,
not a model.** The sandbox cannot tell a syscall made by a hijacked LLM from one made
by a shell script, so every demo drives a deterministic stand-in, and every run is
offline, fast, and identical. A real LLM appears only in an optional capstone after
rung 4.

## Ground rules that outlive any one rung

- **Verify before trusting the specs.** They were written without this tree open. Each
  rung README has a "Spec corrections" section; rung 0's has eight entries.
- **Never weaken an earlier rung to make a later one work.** If rung N needs rung N−1
  relaxed, that is a design finding to report, not an edit to make.
- **Flag-gated patches, default off.** One HEAD binary demos every level live; a
  presentation flips a flag instead of rebuilding Bazel mid-talk.
- **The boundaries between rungs are the point.** Each rung's README ends with the crack
  it deliberately leaves open. That section is a feature of the writeup, not an
  admission.
