# The ladder

Five rungs, each removing one kind of authority an agent gets for free, each with a
demo that shows the previous rung's attack succeeding and this rung's blocking it.

Design narrative: `agent-sandbox/deck.html`. Implementation contract:
[`specs/00-conventions.md`](specs/00-conventions.md) — read it before any rung.

| Rung | Name | Status | Tag | Flags | Claim |
|---|---|---|---|---|---|
| 0 | [Ambient authority](rung0/README.md) | implemented | `rung-0` | none (config only) | reachable damage equals the broker's tool allowlist plus one allowlisted host plus `/scratch` |
| 1 | Task scoping | not started | — | `--ladder-task-scope` | — |
| 2 | Taint bit | not started | — | `--ladder-taint` | — |
| 3 | Attested labels | not started | — | `--ladder-attest` | — |
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
expectation. A committed transcript of a passing run lives in each rung's `expected/`.

## Prerequisites

- **docker**, with the caller in the `docker` group. Root is not required for rung 0.
- **a `runsc` runtime registered with the docker daemon.** Check with
  `docker info --format '{{json .Runtimes}}' | grep -o runsc`. Rung 0 runs against
  whatever runsc is installed; from rung 1 on the runtime must be built from this tree,
  since the `--ladder-*` flags only exist here.
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
