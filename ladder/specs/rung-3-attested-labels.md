# Rung 3 — Two agents, confused deputy

Read `00-conventions.md` and rungs 0–2 first. Deck: slides 11–12. Tag: `rung-3`.
Flags: `--ladder-attest` (composes with `--ladder-taint`).

First multi-agent rung. Two sandboxes, one hop. Authority logic starts moving into the
broker, but the runtime keeps the job that only it can do: making labels unforgeable.

---

## Problem (P3)

Two sandboxed agents, one hop. The callee's sandbox authorizes by **callee identity** —
its own scope, its own broker socket, its own taint state. So any caller that can send the
callee a message borrows the callee's authority. The classic confused deputy, now across
a sandbox boundary.

Concretely, in the working scenario: **Reader** (untrusted input, no privileged tools)
sends a message to **Ops** (prod credentials, never ingests untrusted input directly).
Ops is clean by rung 2's reckoning — it never read anything untrusted — so it acts. The
taint stayed behind in Reader's sandbox, and the read/act split bought nothing, because
the split assumed the actor's *inputs* were trustworthy.

Note what this means for rung 2: the read/act architecture is not a fix, it is a
*relocation* of the problem to the channel between the halves.

---

## Enforcement claim

1. Every message leaving a sandbox toward a peer agent is **stamped by the runtime** with
   metadata the sandboxed agent cannot forge or suppress: sender sandbox identity, current
   taint bit, and the sender's capability set (its rung-1 task grants).
2. If the agent writes its own fields claiming to be someone else, cleaner, or more
   capable, the runtime's stamp **overrides** them; the receiver sees the true values.
   Show the forged header and the delivered header side by side.
3. The receiving side (runtime and/or broker) **enforces an acceptance policy** on those
   labels: a message stamped tainted may not cause a privileged action at the receiver
   without an explicit allowance.
4. The receiver's taint state **inherits** from an accepted tainted message — Ops becomes
   tainted by acting on Reader's tainted output, so rung 2's gate applies to it.
5. A message with no valid stamp (e.g. an agent trying to reach a peer over a channel the
   runtime does not mediate) is **not deliverable**.

Claim 5 is load-bearing: stamping is only meaningful if the stamped path is the *only*
path. Rung 0's egress control is what makes that true — say so in the README, since it is
the first place the ladder's rungs visibly compose.

---

## What rung 2 leaves you (verified against the implementation, not assumed)

Five facts that bear directly on the choices below. Read them before picking a stamp
placement.

- **The interception point this rung wants already exists.**
  `pkg/sentry/socket/unix/` labels a socket at `connect(2)` and checks every
  `Write`/`SendMsg` against sandbox state, with a per-socket field already on the
  `Socket` struct. Sentry-side stamping is the same shape with a different verb, so the
  "highest cost" label on that option is probably overstated.
- **Taint state reaches the host over the control API** — `Ladder.Status` /
  `runsc ladder-status`, added by rung 2 in rung 1's `LadderNarrow` shape. Two caveats
  that bear on the *recommended* host-side proxy: the call needs **root**, because
  docker's runsc state directory is root-owned, and it only answers while the sandbox is
  **running**. A proxy that queries per message will feel both. Consider having the
  runtime push, or holding a handle, rather than shelling out per message.
- **There is no way to *set* the bit from the host.** `Ladder.Status` is read-only by
  design. Claim 4 — the receiver inherits taint — needs a new control method. Adding a
  *setting* one is safe: it is monotonic and tightening-only, the same argument rung 1
  made for `LadderNarrow`. Adding a *clearing* one retracts rung 2's claim 3; if this
  rung finds it needs one, that is a design finding to report, not an implementation
  detail.
- **Checkpoint/restore clears the taint bit.** It is a package-level global and not part
  of saved state. Rung 1's `ladderScope` has the identical problem. If rung 3's labels
  are to survive a restore, the ladder's state has to become savable — one job covering
  rungs 1, 2 and 4.
- **The scenario's two sandboxes already exist as manifests.** Rung 2 ships
  `split-reader.yaml` (untrusted mount, no broker socket) and `split-actor.yaml` (broker
  socket, no untrusted mount), and `gen_spec.py` grew `mounts.broker` and
  `mounts.untrusted` to express them. Rung 3's Reader and Ops are those two plus a
  channel between them, which is also the honest way to show the "relocation" point in
  the problem statement: the split demonstrably works in rung 2's demo, and this rung
  is what breaks it.

---

## What to build

```
ladder/rung3/
  README.md
  demo.sh
  scenario/               # two-sandbox setup: reader + ops, manifests per rung 1
  fixtures/               # injected content for reader; forged-header attempt
  expected/
```

Plus the gated patch. **Design the message path first** and write it in the README before
coding; the security argument depends entirely on where the stamp is applied.

**Message transport.** Keep it dumb: agent-to-agent messages go through a runtime-mediated
channel — most likely a unix socket bound into the sandbox that is proxied on the host,
or a connection to the broker acting as a message router. Prefer whatever reuses rung 2's
interception point. What matters is that the sandbox has **no other route to the peer**
(rung 0's egress deny-by-default) and that the stamping happens on the outside of the
agent's control.

**Stamp placement — pick one, justify it:**

- *In the Sentry, on the write path* — same hook family as rung 2's gate; strongest claim
  (the bytes are labeled before they leave the guest kernel), highest cost.
- *In a host-side proxy owned by the runtime* — the sandbox's only reachable endpoint is
  the proxy; the proxy knows which sandbox the connection came from and queries/holds its
  taint state. Cheaper, and the unforgeability argument still holds as long as the sandbox
  cannot reach the peer directly. **Recommended default.**

If you take the host-side proxy, the runtime still owns the taint bit, so the proxy must
learn it from the runtime (control API or log/event channel), not from the message. Make
that data path explicit in the README — if the proxy learns taint from the message, the
whole rung is circular and proves nothing.

**Acceptance policy** — keep it a two-line rule, not a language: a tainted message may
inform the receiver, but a privileged tool call whose *parameters derive from* a tainted
message is denied unless the parameter is on the task's allowlist. Rung 3 can approximate
"derive from" as "the receiver is tainted", which is exactly claim 4.

---

## Demo (`ladder/rung3/demo.sh`)

Scenario: Reader ingests an injected page instructing a privileged config change; Reader
sends its "findings" to Ops; Ops calls `write_config`.

1. **BASELINE** — `--ladder-attest` off (rung 2 on). Reader is tainted and correctly
   blocked from acting itself — *and then* hands the instruction to Ops, which is clean
   and executes it. **The privileged action succeeds.** This is the money slide: rung 2's
   protection is fully bypassed by one hop, without any hop exceeding its permissions.
2. **ENFORCED** — with `--ladder-attest`. Three parts:
   (i) the message arrives stamped tainted and the privileged call at Ops is **denied**,
   with the receiver-side evidence line;
   (ii) Reader attempts to **forge** clean/high-capability headers — print the forged and
   the delivered headers side by side to show the override;
   (iii) Reader attempts to reach Ops **directly**, bypassing the mediated channel —
   undeliverable (rung 0 egress denial).
3. **CONTROL** — the same two-agent chain doing legitimate work: Reader reads a *benign*
   source, sends findings to Ops, Ops performs the config change and **succeeds**.
   Cross-sandbox collaboration still works when nothing untrusted entered.

Add a fourth block if cheap: Ops, having accepted a tainted message, is now itself tainted
(claim 4) — demonstrate by having it attempt a second privileged call.

---

## Acceptance criteria

- Forged headers demonstrably overridden, shown as a side-by-side diff in the output.
- The proxy/Sentry obtains taint state from the **runtime**, not from message content —
  state the path explicitly in the README.
- Direct peer contact bypassing the mediated channel is impossible, and the demo shows the
  attempt failing.
- Rungs 0–2 demos still pass.
- Flag off ⇒ rung-2 behavior unchanged.

---

## Explicitly NOT enforced (the crack → rung 4)

- **One hop only.** With A→B solved, A→B→C re-launders: each hop sees only its immediate
  caller, so a label that is meaningful pairwise still loses the *chain*. Rung 3's
  receiver knows its sender was tainted; it does not know what the user originally
  authorized, nor that B's request to C exceeds what A could have asked for.
- **Identity is local.** "Sandbox identity" here means "the runtime on this host says so".
  Across hosts or clouds there is no attestation, no key, no verification — and the
  scenario explicitly places these agents in different cloud environments. Note this
  bluntly; cross-cloud attestation is a backlog item, not part of the ladder.
- **Coarse binary taint.** No notion of *which* parameter came from tainted data.

---

## Report back

Conventions §7, plus:

- Where the stamp is applied and the precise argument for why the agent cannot forge or
  bypass it — including which earlier rung's mechanism that argument depends on.
- Whether Sentry-side stamping was attempted; if rejected, why (cost, layering).
- How taint state reaches the stamper.
- Whether the acceptance policy wanted to become a policy language, and how you resisted.
