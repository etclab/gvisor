# Rung 5b — Federated runtimes, task-template model

Read `00-conventions.md` and rungs 0–4 first. Deck: pending. Tag: `rung-5b`.
Flag: `--ladder-fed` (proxy-level; shares the flag and substrate with 5a).

**Sibling spec:** `rung-5a-standing-services.md`. §2 of 5a (the federation substrate:
wormhole enrollment, cached QUIC-RPK host-pair connections, stamped exporter-bound
streams, Noise road-not-taken) applies here **verbatim** and is built once in
`ladder/common/fed/`. This file specifies only what differs: agents are not standing
services but **ephemeral computations stood up from templates per task**.

---

## 1. The 5b model: runtimes + templates, agents as spawned tasks

The persistent fabric is runtimes and **role templates** — an agent image plus its
role-level grant ceiling (reader, ops, …), registered at deploy time and identified by
digest. Agent instances do not pre-exist their work. "Agent-to-agent communication" is
**task A causing the creation of task B on some runtime**: authorized function
invocation, not peer networking.

A cross-host stream is therefore a **spawn envelope**, not a conversation:

```
{ caller chain (rung-4: origin, hops, accumulated taint),
  delegated capability for the child   (must be ⊆ caller's own — attenuation at spawn),
  role template digest, task payload,
  expiry, nonce/sequence }             — all runtime-signed, exporter-bound
```

The receiving runtime verifies the envelope, mints a fresh rung-1 sandbox from
**(template grant ceiling ∩ delegated capability)**, runs the task, streams results
back with the child's outbound stamp, and destroys the sandbox. Rung-4 attenuation gets
a single natural choke point: spawn time. Callee identity is
`(runtime key, template digest, task ID minted at spawn)` — you cannot authenticate an
agent that does not exist yet, so what is authenticated is the runtime and the measured
template. (The digest is deliberate future-proofing: the attestation rung can attest the
runtime binary *and* have it report the digest of what it spawned.)

**Why this model is the security-preferred one** (record in README): agent lifetime =
task lifetime, so **taint dies with the task** — rung 2's "long-lived agent becomes
permanently tainted" cost evaporates, which is what makes the coarse-but-sound taint bit
livable; there is no warm daemon accumulating context, credentials, or taint; the far
side stays task-scoped, so rung 1 holds across hosts. A standing service (5a) is
expressible here as a degenerate long-TTL task, but the reverse recovery is impossible.

## 2. Enforcement claim

Claims 1–3 of 5a (proxy-only path, registry-refused impostors, stamp verification)
apply unchanged. Additionally:

4. A spawn is admitted only if **delegated ⊆ caller's own capability**; a widening
   attempt is denied and logged (`granted ⊄ caller's`). The child sandbox's effective
   grants are demonstrably `template ceiling ∩ delegated` — show a grant present in the
   ceiling but absent from the delegation being unavailable to the child.
5. The child sandbox is **destroyed at task end**: scratch state from task 1 is absent
   in task 2 of the same template on the same host; the child's taint dies with it —
   a tainted task followed by a clean task of the same template leaves the second clean.
6. **Zero-grant warm pool rule.** If pre-warmed sandboxes are used for burst latency,
   they hold **zero grants until bind time**: no network, no broker socket, no mounts
   beyond scratch until a verified envelope is bound to them. Demonstrate a pre-bind
   warm sandbox can reach nothing. A pool of pre-granted sandboxes would silently
   recreate role-scoped authority — rung 1 undone by an optimization; this rule is
   load-bearing, not a nicety.
   **Warm pools must not be built on checkpoint/restore.** The fork's implementation
   notes record that ladder state (taint bit, chain) is package globals excluded from
   saved state, so restore *launders* it — a restored sandbox comes back clean
   regardless of history. Until that open item is fixed, warm = freshly booted and
   never-yet-granted, not snapshotted. If C/R-based warm start is ever wanted for
   latency, fixing ladder-state serialization becomes a hard prerequisite; say so in
   the README rather than quietly using restore.
7. Basic spawn admission control: spawn rights are part of the capability; a caller
   whose capability lacks `spawn:<template>` is refused; a simple per-caller rate limit
   exists. (Resource-exhaustion DoS beyond this is out of threat model — backlog.)

## 3. What to build

```
ladder/rung5b/
  README.md
  demo.sh
  templates/           # role templates: image ref + grant ceiling + digest
  scenario/            # host A runs an orchestrator task; reader and ops exist only
                       # as templates on hosts B and C until spawned
  expected/
```

Reuses `ladder/common/fed/` (built by whichever variant lands first) and rung 1's
manifest→OCI generator for the mint step: the spawn envelope is, deliberately, a rung-1
task manifest that arrived over the network with a capability chain attached. Make that
identity explicit in code — one mint path, two invocation sources (local, federated).

Runtimes keep a small **task tree** (parent → children, result routing, TTLs) so a
parent's death doesn't orphan results. Bookkeeping, not architecture; keep it dumb.
Persistent agent state ("memory") is out of scope; if a task needs it, it is an explicit
mounted resource in the manifest — note this in the README as the model working as
intended (state you must name is state you can scope).

## 4. Demo (`ladder/rung5b/demo.sh`)

1. **BASELINE** — flag off: an impostor host submits a forged spawn envelope with an
   inflated capability; the ops task is minted and performs the privileged action.
   Also show 5a-baseline transit attacks if not already covered by the shared substrate
   demo — do not duplicate work; reference it.
2. **ENFORCED** — flag on:
   (i) impostor spawn refused at handshake;
   (ii) **widening spawn denied**: orchestrator delegates more than it holds →
   `granted ⊄ caller's`;
   (iii) in-ceiling-but-not-delegated grant unavailable inside the child (claim 4);
   (iv) replayed and expired envelopes rejected;
   (v) ephemerality: tainted reader task → destroyed → next reader task clean; scratch
   gone (claim 5);
   (vi) warm-pool pre-bind sandbox shown unable to reach anything (claim 6);
   (vii) caller without `spawn:ops` refused (claim 7).
3. **CONTROL** — the full goal cross-host at agent-pace: orchestrator task spawns a
   reader task on host B and an ops task on host C, legitimate config fix lands.
   **Print the burst numbers:** cold spawn latency, warm-pool spawn latency, K
   concurrent spawns all completing unattended. Agent-pace is a demo assertion.

## 5. Acceptance criteria

- All claims individually evidenced; denials happen in the receiving proxy/runtime
  before any sandbox is minted (for 4/7) or before payload processing (for stamps).
- One mint path shared by local (rung 1) and federated invocation, shown by pointing at
  the code in the README.
- The taint-dies-with-task demonstration is explicit — this is the headline security
  argument for the model; give it its own output block.
- Rungs 0–4 pass; flag off ⇒ rung-4 behavior; 5a (if built) unaffected.
- Latency table (cold vs warm spawn vs stream-open) committed in `expected/`.

## 6. Explicitly NOT enforced (the crack → attestation rung, + model residuals)

- **Same trust crack as 5a:** keys by ceremony, no attestation — an enrolled-but-hostile
  runtime can mint anything and stamp lies. Both attestation slots (admission-time aTLS,
  per-connection SEAT-style) remain open by construction; the template digest adds a
  third: attested runtimes reporting measured spawns.
- **Template supply chain:** the digest names the template but nothing verifies what a
  digest *should* be — template registration is trusted deploy-time input.
- **Spawn economics:** rate limit is a placeholder; spawn-storm DoS, queueing, and
  fairness are backlog.
- Cold-start latency bounds honesty: if warm pools prove necessary for realistic bursts,
  the zero-grant rule's cost (bind-time grant injection) must be measured, not assumed.

## 7. Report back

Conventions §7, plus: cold vs warm spawn numbers and whether the zero-grant bind is
what makes warm pools slow (if it is, that tension is a finding — the optimization
pressure that erodes task-scoping is exactly the thing to document); how much of rung 1's
mint path was reusable unchanged; task-tree edge cases hit (parent death mid-spawn);
and a direct comparison paragraph against 5a if both were built: lines of code, demo
latency, and which claims each model could NOT express.
