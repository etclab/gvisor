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
| 4 | [Chain attenuation](rung4/README.md) | implemented | `rung-4` | `--ladder-chain` (+ rung 3's four) | a privileged call is authorized against the **chain** that produced it — the capability the user's goal minted, narrowed at every hop and never widened, plus the taint and origin the runtime accumulates — so an out-of-scope parameter is refused at the broker and a middle hop's attempt to widen what it passes on is refused at the relay |

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
  it, because rung 2's configuration *is* rung 3's baseline. Rung 4 needs rung 3's
  `ladder-attest` runtime for the same reason, plus its own `ladder-chain`; it is also
  the one rung whose enforcement is mostly **outside** the runtime, so its flag gates
  provenance rather than the denials — see "The verdict" below.
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

## The verdict: where runtime enforcement stopped helping

This is the framing research question of the whole exercise (deck slide 14), and the five
rungs answer it more sharply than any one of them does alone. Written down here because it
outlives rung 4.

**The runtime is the right place for a fact about a sandbox. It is the wrong place for a
decision about an action.**

Every rung that put enforcement in the runtime enforced a *sandbox-scoped fact* that
nothing outside the sandbox could observe or fake:

| Rung | What the runtime holds | Why nothing outside could |
|---|---|---|
| 2 | did untrusted bytes enter this sandbox | the read happens below the agent; no host process sees it |
| 3 | who this sandbox is, and its taint bit, on every outbound message | the stamp is prepended below the syscall boundary, so the agent's bytes never touch it |
| 4 | the first untrusted source anywhere upstream | only the sentry that performed the read ever knew the path |

Every rung that tried to decide *whether an action is allowed* ended up outside the
runtime, and rung 1 and rung 4 got there from opposite directions. Rung 1 discovered that
per-task scoping needed no patch at all — it is orchestration, and only mid-task
attenuation of an already-installed filter had to be in the runtime. Rung 4 discovered
that chain-aware authorization *cannot* be in the runtime: the decision needs the goal's
capability, the delegations made at three different times, and the correlation of two
connections that no single sentry sees. Measured, in rung 4's own `ENFORCED-3` block: with
`--ladder-chain` off, both of rung 4's denials still fire, because both are broker logic.
Only the origin is lost.

The line, stated as a test to apply to the next mechanism: **if the question is "what
happened to this sandbox", it belongs in the runtime, and the runtime is the only place it
can be answered truthfully. If the question is "may this action happen", it belongs at the
enforcement point that holds the credential, and putting it in the runtime means teaching
the kernel your application protocol.**

Two consequences worth carrying forward:

- **The runtime's contribution to a multi-hop system is provenance, not authorization.**
  That is a smaller claim than the ladder set out to make and a more defensible one. It is
  also what makes the authorization trustworthy: the broker's decision is only as good as
  the labels it is handed, and the labels are the part an agent cannot forge.
- **The layers can disagree, and the blunter one wins.** Rung 4's `ENFORCED-4` has rung
  2's per-sandbox gate refusing a write that rung 4's capability check had authorized,
  because the gate is closer to the syscall. Coarse runtime enforcement pre-empts fine
  host-side enforcement, whatever the intended ordering. Nobody designed that; it falls
  out of where the two mechanisms live.

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
