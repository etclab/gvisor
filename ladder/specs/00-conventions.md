# Ladder Conventions — shared contract for all rungs

Read this before any rung spec. It defines the repo layout, naming, harness, demo
contract, and README format that every rung must follow. Rung specs assume these
conventions and only describe what is *new*.

Design narrative lives in `deck.html` of the `agent-sandbox` design repo. These specs
are the implementation contract. The fork's per-rung READMEs are the artifact the team
reads.

---

## 0. Ground rules

**Verify before trusting this document.** Every gVisor-internal path, flag, and API
named in these specs is a *hypothesis written from outside the tree*. gVisor moves. If
a named file, flag, or function does not exist or does not work as described, that is
expected — find the real one, and record the correction in the rung README under
"Spec corrections". Do not invent a workaround that fakes the enforcement.

**Verify runsc behavior against upstream docs, not memory.** Network modes, overlay
flags, and the control API have all changed across releases. Check
`gvisor.dev/docs` and `runsc <cmd> --help` for the checked-out revision.

**Bar is research prototype.** Functionality and clarity of the enforcement claim beat
robustness, performance, and generality. No production hardening, no multi-arch, no
upstreamability requirement. Do not refactor gVisor subsystems to make a patch elegant.

**Minimal diffs.** A reviewer must be able to read `git diff rung-(N-1)..rung-N` and see
the whole mechanism. Keep patches surgical and localized. Prefer adding a small file
over threading changes through many.

**Never weaken an earlier rung to make a later one work.** Rung N must still pass
rung N−1's demo. If a later rung requires relaxing an earlier claim, stop and report —
that is a design finding, not an implementation detail.

**No LLM in the loop.** See §4. Demos must be deterministic and runnable offline.

---

## 1. Fork layout

Everything the ladder adds lives in one top-level directory, plus gated patches inside
the gVisor tree itself.

```
<gvisor-fork>/
  ladder/
    README.md            # ladder index: rung table, status, how to run any demo
    Makefile             # `make demo RUNG=n`, `make build`, `make demo-all`
    common/
      README.md
      fake_agent/        # scripted stand-in for an agent (see §4)
      broker/            # tool broker: holds credentials, outside every sandbox
      probes/            # per-channel probe scripts (env creds, metadata IP, egress, fs, exec)
      lib.sh             # shared shell helpers: assert_denied, assert_allowed, log capture
    rung0/  … rung4/
      README.md          # self-contained, see §5
      demo.sh            # the three-check demo, see §3
      expected/          # committed transcript(s) of a passing run
      <configs, manifests, fixtures for this rung>
  <gvisor tree>          # patches for rungs 1-4, each behind a --ladder-* flag
```

Nothing outside `ladder/` and the gated patches should change. Do not modify upstream
tests or CI.

---

## 2. Git, tags, and flags

**Branch:** one linear branch, `ladder`. Cumulative history mirrors the ladder's
semantics — rung N builds on rung N−1.

**Tags:** `rung-0` … `rung-4`, one per completed rung, on the commit where its demo
passes. Tags are milestones for checkout and for `git diff rung-1..rung-2` as a
presentation artifact.

**Commits:** small and labeled, `ladder(rungN): <what>`. Check `git log --oneline -10`
on the fork first; if it has a different convention, match the fork.

**Flags — the important one.** Every runtime patch is gated behind its own runsc flag,
default **off**:

| Rung | Flag | Effect when off |
|---|---|---|
| 1 | `--ladder-task-scope` | no per-task narrowing |
| 2 | `--ladder-taint` | no taint tracking |
| 3 | `--ladder-attest` | no label stamping on outbound messages |
| 4 | `--ladder-chain` | no chain/capability verification |

Rationale: one HEAD binary can then demo *every* level live. A presentation runs the
same attack with the flag off (succeeds) and on (blocked) in the same session, with no
rebuild and no checkout — Bazel builds are too slow to rebuild mid-demo. Flags compose:
rung 3's demo runs with `--ladder-taint --ladder-attest`.

Flag plumbing lives where runsc's other flags live — expect `runsc/config/config.go`
and `runsc/config/flags.go`, then threaded to the sandbox/boot process. Confirm in tree.

---

## 3. Demo contract

Every rung has `ladder/rungN/demo.sh` running **exactly three checks**, in this order:

1. **BASELINE** — the attack under rung N−1's settings (flag off, or previous rung's
   config). Must **succeed**. Proves the attack is real and the demo can observe it.
2. **ENFORCED** — the same attack under rung N. Must be **blocked**, with named
   evidence: a specific exit code, a denial log line, or an error string. Print the
   evidence.
3. **CONTROL** — a *legitimate* task under rung N. Must **succeed**. Proves the rung
   did not simply break everything.

A rung without a passing BASELINE is not demonstrated — it may be enforcing nothing.
A rung without a passing CONTROL is not useful — it may be denying everything.

Requirements:

- `demo.sh` exits 0 only if all three checks meet expectation; non-zero otherwise.
- Output format per check: `[BASELINE] ... => SUCCEEDED (expected)`, one line of
  evidence, blank line. Keep it readable on a projector — short lines, no debug spew
  unless a check fails.
- Prints a final `RESULT: PASS|FAIL` line and a one-line summary of the enforcement
  claim exercised.
- Self-contained: no network access to the internet, no API keys, no cloud account.
  Hosts the demo must reach are local (see §4).
- Idempotent and re-runnable; cleans up sandboxes/containers it starts, including on
  failure (`trap`).
- Runs as a normal user where possible; if root or specific capabilities are needed,
  state that at the top of `demo.sh` and in the README.
- Commit a captured passing transcript to `ladder/rungN/expected/`. Team presentations
  must not depend on live infra. Note the revision and date in the transcript header.

---

## 4. Shared harness (`ladder/common/`)

**The agent is a script, not a model.** The sandbox cannot distinguish a syscall made by
a hijacked LLM from one made by a shell script, so the demos use a deterministic
stand-in. This keeps runs fast, offline, reproducible, and free of API keys on the
remote boxes. A real LLM appears only in an optional capstone demo after rung 4.

`fake_agent/` — a small program (Go or Python; pick one and keep it) that takes a
script of actions and executes them, reporting per-action success/failure:

- `probe-env-creds`, `probe-metadata`, `probe-egress <host>`, `probe-fs-write <path>`,
  `probe-exec <binary>`
- `read-source <path|url>` — used from rung 2 on; the source carries a label
- `call-broker <tool> <args>` — the only sanctioned path to a world-effect
- `send-agent <peer> <message>` — used from rung 3 on
- `--obey-instructions` — when reading a source, parse an embedded instruction from its
  content and execute it. This is the injection stand-in: it makes "untrusted input
  steered the agent" a mechanical, deterministic fact.

`broker/` — a stub tool broker that runs **outside** every sandbox, holds the only
credentials, listens on a unix socket bound into the sandbox, and exposes a few named
tools (e.g. `read_wiki`, `read_metrics`, `write_config <key> <value>`). It logs every
request with its decision and reason. From rung 3 on it also validates message labels.
Keep it dumb — it is a test fixture, not the research contribution, except where a
rung's spec explicitly moves authorization logic into it.

`probes/` — the per-channel attack probes of §Rung 0, reusable by later rungs.

`lib.sh` — `assert_denied`, `assert_allowed`, `capture_runsc_log`, `require_root`,
`cleanup_sandboxes`, and the `[BASELINE]/[ENFORCED]/[CONTROL]` printers. All rungs use
these so output is uniform across demos.

**Local stand-ins for the outside world:** run a local HTTP server for "the web" and
another for "the wiki", each on its own port/IP so egress allowlisting is meaningful.
For the cloud metadata endpoint, probe `169.254.169.254` directly — expect connection
failure as the pass condition, and be explicit that "no listener" and "blocked" look
alike, so the BASELINE check must show the probe succeeding against a *local* stand-in
listener bound to that address (or an equivalent) to prove the probe works.

---

## 5. Per-rung README (required format)

`ladder/rungN/README.md` must stand alone: a team member who opens only that file
should learn what is enforced, how, what is not, and how to see it.

```markdown
# Rung N — <name>

Status: implemented | partial | sketch
Deck: agent-sandbox/deck.html, slides X–Y
Tag: rung-N   Flags: --ladder-<x>   Verified on: gVisor <rev>, <kernel>, <date>

## Enforcement claim
Numbered, checkable assertions of what is newly DENIED that rung N−1 allowed.
Each assertion names the demo check that exercises it.

## Problem
One paragraph. Why the previous rung is insufficient.

## Mechanism
How it works, with file:line pointers into this fork. Config vs patch. What the flag
gates. For patches: which layer intercepts, and why that layer is the right one.

## Threat model delta
What this rung assumes. What it explicitly does not defend against.

## Explicitly NOT enforced (the crack → rung N+1)
The known gap, stated plainly. This is a feature of the writeup, not an admission.

## Demo
./demo.sh — three checks (baseline / enforced / control), see expected/.
Prerequisites, runtime, root requirement. Expected output inline or referenced.

## Spec corrections
Where this rung's spec was wrong about gVisor (paths, flags, APIs) and what is true
instead. Empty section is fine — say "none".

## Open questions
```

Also update `ladder/README.md`'s rung table (status, tag, flags, one-line claim) as
each rung lands.

---

## 6. Definition of done (every rung)

1. `make demo RUNG=n` passes on a clean checkout of the tag, on the remote Linux box.
2. Rungs 0..n−1 demos still pass (`make demo-all`) — no regressions in earlier claims.
3. `ladder/rungN/README.md` complete, including "Spec corrections" and the crack.
4. Passing transcript committed under `expected/`.
5. `ladder/README.md` rung table updated.
6. Patch (if any) gated behind its flag; with the flag off, upstream behavior is
   unchanged. State how this was checked (e.g. a named subset of gVisor's own tests, or
   an explicit statement that only the demo was used to check it).
7. Tag `rung-n` pushed.

---

## 7. Hand-back report

When a rung is done, report to the requester:

- What was built, as file paths and the flag name.
- **Actual demo output** — paste the three-check result. Never claim a pass without it.
- Spec corrections: what this document or the rung spec got wrong about gVisor.
- Where the enforcement is weaker than the claim, if anywhere. Be specific; an
  over-claimed README is worse than a partial one.
- What the next rung will need that does not exist yet.
- Time/complexity signal: was this rung's patch surgical or invasive?

---

## 8. Anti-goals

- Do not build a policy language, a general capability framework, or an
  agent-orchestration platform. Each rung adds the minimum mechanism its claim needs.
- Do not put enforcement in a prompt. Prompt-level mitigations are out of scope for
  the entire ladder; the point is enforcement below the agent.
- Do not aim for upstream-mergeable gVisor patches.
- Do not make demos depend on cloud accounts, real credentials, or internet access.
- Do not silently expand scope to the next rung because it is convenient — the ladder's
  value is in the boundaries between rungs.
