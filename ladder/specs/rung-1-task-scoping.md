# Rung 1 — Role ≠ task

Read `00-conventions.md` and rung 0's README first. Deck: slide 8. Tag: `rung-1`.
Flag: `--ladder-task-scope`.

Mostly orchestration. One optional light runtime patch (mid-task attenuation). Do the
orchestration part first and completely; attempt the patch only if it is cheap.

---

## Landed — 2026-08-16

Implemented on tag `rung-1`. All four claims met, including the optional patch: 15 demo
checks under stock runsc with no root, 18 with `--with-runtime-patch`, `make demo-all`
passing. **The body below is left as written — it is the record of what was believed
before the tree was open.** Corrections live in `ladder/rung1/README.md` under "Spec
corrections"; eight entries, of which two change how a later rung should read this file:

- The generator emits **docker run arguments, not an OCI `config.json`**. Docker already
  synthesizes the OCI spec, and rung 0's deny-by-default egress *is* a docker `--internal`
  network — hand-writing a bundle would have needed root and thrown away half the
  enforcement.
- **`--ladder-task-scope` gates only claim 4's in-runtime half.** Claims 1–3 are pure
  orchestration and hold on stock upstream runsc. See the corrected flag table in
  `00-conventions.md` §2.

---

## Problem (P1)

Rung 0's grants are per-agent and static, fixed at deploy time as the union of everything
the agent's role might ever need. Any single task uses a fraction of that union. A
metrics-reading task sits in a sandbox that can also reach the wiki and call
`write_config`. The sandbox is minimal relative to the role, not the task.

---

## Enforcement claim

1. Each task runs in a **fresh, ephemeral sandbox** whose network allowlist, mounts, and
   broker tool set are derived from that task's manifest — not from the agent's role.
2. An action permitted for task B (e.g. reaching the wiki host, calling `write_config`)
   is **denied inside task A's sandbox**, even though the same agent image performs both.
3. The sandbox is destroyed at task end; no state carries to the next task (verify a
   scratch write from task A is not visible in task B).
4. *(Optional, if the patch lands)* Grants can be **narrowed mid-task** through a runtime
   control channel, and never widened; a narrowing takes effect on subsequent syscalls
   within the same running sandbox.

---

## What to build

```
ladder/rung1/
  README.md
  demo.sh
  manifests/
    task-a-read-metrics.yaml     # or .json — pick one format, keep it dumb
    task-b-update-config.yaml
  gen_spec.<sh|py|go>            # manifest -> OCI config.json + runsc invocation
  expected/
```

**Task manifest** — the smallest thing that works. Suggested fields:

```yaml
task_id: read-metrics-svcX
agent_image: ladder/fake-agent
network_allow: [ "metrics.local:9101" ]     # hosts this task may reach
mounts:
  scratch: rw
broker_tools: [ "read_metrics" ]            # tools this task may call
ttl_seconds: 120
```

Resist adding conditions, wildcards, or inheritance. The research question here is
plumbing, not policy language (conventions §8).

**Generator** — deterministic manifest → OCI spec + runsc flags + broker scoping. It
must be readable; a reviewer should trace a manifest field to the resulting restriction.

**Broker scoping** — the broker must know which task a connection belongs to and refuse
tools outside that task's set. Simplest workable approach: one broker socket per task
sandbox, created by the launcher with the task's tool set attached. Avoid passing a task
ID *from inside* the sandbox — the agent could lie about it. Note in the README why the
binding must be established outside the sandbox; this is the first appearance of the
unforgeability idea that rung 3 generalizes.

---

## Optional patch: mid-task attenuation

Only if cheap. Goal: a running sandbox's network allowlist can be tightened without
restarting it — e.g. after the agent finishes its "gather" phase, drop web egress before
it enters an "act" phase.

Investigate before designing:

- runsc's control interface — expect a urpc-based control server reachable from the host
  (look around `runsc/boot/controller.go`, `pkg/control`, and what `runsc debug` /
  `runsc events` use). Determine whether a new control method can be added cheaply.
- Where a netstack-level host filter would hook if rung 0's filtering ended up outside
  the sandbox. If rung 0's filter is external (nftables/proxy), mid-task attenuation may
  be implementable *entirely outside* runsc by rewriting the external rules — that is a
  legitimate and much cheaper answer. Say so if you take it.

Whichever route, the API must be **attenuation-only**: the control call can remove hosts
or tools, never add. Enforce that in the handler and test it — attempting to widen must
fail. This is the first mechanical appearance of the monotonicity property that rungs 3
and 4 depend on.

If the patch does not land, mark claim 4 as not implemented in the README and record why.
Do not fake it.

---

## Demo (`ladder/rung1/demo.sh`)

1. **BASELINE** — flag off / rung-0 config: the single role-scoped sandbox performs task
   A's action *and* task B's action (reach wiki, call `write_config`). **Both succeed** —
   this is exactly rung 0's residual over-permission, made visible.
2. **ENFORCED** — launch from `task-a-read-metrics.yaml`; the agent attempts task B's
   action. **Denied**, with evidence from both layers: network denial and broker refusal
   naming the task ID. Then show a scratch write from task A is absent in a fresh task B
   sandbox.
3. **CONTROL** — task A performs its own action (`read_metrics`, reach `metrics.local`)
   and **succeeds**; separately, task B launched from its own manifest performs
   `write_config` and **succeeds**. Proves scoping is per-task, not a blanket denial.

If the attenuation patch landed, add a fourth block (label it `[ENFORCED-2]`): inside one
running sandbox, an allowlisted host is reachable, a narrowing control call is issued, the
same host becomes unreachable, and a widening call is **rejected**.

---

## Acceptance criteria

- Two manifests differing only in grants produce demonstrably different sandboxes from
  the same agent image.
- Denials are visible at both the network layer and the broker, with the task ID in the
  broker's log line.
- The generator is deterministic: same manifest → same spec (diff two runs).
- Rung 0's demo still passes.
- Claim 4 is either demonstrated or explicitly marked not implemented.

---

## Explicitly NOT enforced (the crack → rung 2)

A task-scoped sandbox still executes **whatever the agent decides to do within scope**.
Rung 1 bounds the action set; it says nothing about *why* an action was chosen. Once the
agent ingests attacker-controlled content, the attacker chooses from the in-scope set —
and for any task worth doing, the in-scope set contains something worth abusing.

Rung 1 also assumes the task manifest is correct and tight. Who authors it, and how a
user's intent becomes a scope, is out of scope for the whole ladder (backlog).

---

## Report back

Conventions §7, plus:

- Whether mid-task attenuation was implementable, where the hook lives, and its cost.
- Whether the control path (if built) is reachable **only** from the host — an
  attenuation API the sandbox can call is a hole; confirm which side owns it.
- How the broker binds a connection to a task ID, and your confidence that the sandbox
  cannot forge it.
