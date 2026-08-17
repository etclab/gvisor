# Rung 4 — N hops, authority laundering

Read `00-conventions.md` and rungs 0–3 first. Deck: slide 13. Tag: `rung-4`.
Flags: `--ladder-chain` (composes with `--ladder-taint --ladder-attest`).

The destination. This is where the original problem statement lived — but every mechanism
it uses was earned by an earlier rung.

---

## Problem (P4)

Three hops: Reader → Orchestrator → Ops. Rung 3 gives each hop truthful labels about its
*immediate* caller, but not about the chain. Provenance is lost in the middle: Ops learns
its caller (Orchestrator) is clean and appropriately capable, and cannot see that the
instruction originated in attacker-controlled content two hops back, nor what the user
actually authorized at the root.

The full walkthrough (deck slide 13): an injected web page shapes Reader's findings;
Orchestrator treats those findings as trustworthy analysis and tasks Ops; Ops executes
with prod credentials. **No hop exceeded its own permissions.** Untrusted input exercised
prod authority by passing through hops that each behaved correctly.

Note the two distinct leaks — they need different mechanisms, and conflating them is the
main design risk of this rung:

- **Taint provenance** is lost (rung 3's label does not survive re-emission by a middle
  hop that is itself clean).
- **Authority provenance** is absent (nothing ties Ops' action back to what the user's
  original goal permitted).

---

## Enforcement claim

1. **Chain labels accumulate.** A message's stamp carries the transitive taint of the
   whole chain, not just the last hop. Orchestrator re-emitting Reader's tainted content
   produces a message stamped tainted, even though Orchestrator read nothing untrusted.
2. **Attenuation-only delegation.** The user's trigger mints a capability set for the
   goal. Each hop may narrow it, never widen it. The runtime/broker verifies at every hop
   that `granted ⊆ caller's own set`; a widening attempt is denied and logged.
3. **Chain-aware authorization at the sink.** A privileged tool call is authorized against
   the *chain*: the accumulated capability set and the accumulated taint, not the
   immediate caller's identity.
4. **Out-of-scope actions fail closed at the enforcement point**, even when the acting
   agent's ambient credentials would permit them — e.g. `write_config auth_disabled true`
   is denied because the key is outside the root capability's allowlist, though Ops'
   credentials could set it.
5. Tainted content may **inform** analysis but may not **parameterize** a privileged
   operation unless the parameter passes an allowlist/validator (or, if you build it, an
   explicit user confirmation step).

---

## What to build

```
ladder/rung4/
  README.md
  demo.sh
  scenario/            # three sandboxes: reader, orchestrator, ops
  capabilities/        # root capability set for the goal + per-hop attenuations
  fixtures/            # injected page (out-of-scope action) + benign page (in-scope fix)
  expected/
```

**Capability representation — keep it minimal.** A signed or broker-held record is enough:

```json
{ "goal_id": "svcX-latency-2026-08-17",
  "tools": { "read_metrics": {}, "read_wiki": {},
             "write_config": { "keys": ["cache_size", "pool_max", "timeout_ms"] } },
  "taint": "clean",
  "chain": ["user"] }
```

Do **not** implement Macaroons, Biscuit, or SPIFFE. Name them in the README as the real
mechanisms this stands in for, and say what a real deployment would use them for
(cryptographic attenuation and caveat verification without a central authority; workload
identity across clouds). Building one is a distraction from the rung's claim. If the
broker holds capability state centrally, say so and note the honest limitation: the
demo's unforgeability comes from centralization plus rung 3's stamping, not from crypto.

**Where verification lives.** The `granted ⊆ caller's` check and the sink authorization
belong in the broker (it is the enforcement point); the runtime's contribution is the
unforgeable binding of a connection to a sandbox and its accumulated labels — rung 3's
machinery, extended so the stamp carries chain state rather than only local state.

**Do not build**: an intent→scope translator. Who writes the root capability from a user's
natural-language goal is a backlog item; the demo hand-writes it. State this prominently —
it is the largest assumption in the entire ladder, and a reviewer will ask.

---

## Demo (`ladder/rung4/demo.sh`)

Goal: *"Investigate why service X is slow and fix its config."* Root capability as above.

1. **BASELINE** — `--ladder-chain` off (rungs 2–3 on). Reader ingests the injected page;
   Orchestrator, itself clean, relays the recommendation as analysis; Ops executes
   `write_config auth_disabled true`. **Succeeds.** Print the per-hop view at each step to
   show why: each hop saw a plausible, in-scope request from a trusted-looking caller.
2. **ENFORCED** — with `--ladder-chain`. Show:
   (i) the chain-accumulated stamp arriving at Ops marked tainted, with the chain
   `[user, reader, orchestrator]` and the origin visible;
   (ii) the `write_config auth_disabled` call **denied** — key outside the root
   capability's allowlist — with the denial naming both the offending key and the goal_id;
   (iii) Orchestrator attempting to **widen** the capability it passes to Ops (adding a
   tool or key it was not granted) → **denied**, `granted ⊄ caller's`;
   (iv) note in the output that Ops' credentials *could* have performed the action — the
   denial came from the capability check, not from lacking credentials. Make this explicit;
   it is the entire point of the rung.
3. **CONTROL** — the legitimate path: Reader reads a benign source recommending
   `cache_size`, chain runs to Ops, `write_config cache_size 512` **succeeds** because the
   key is inside the root allowlist. The system still does its job.

Optional fourth block — the honest hard case, worth demoing even if it fails: the
legitimate fix is *described in an untrusted page*, so the correct parameter is itself
tainted. Show what your policy does (denied by claim 5, or allowed because the key passes
the allowlist validator). Whichever it is, this is the most interesting slide in the deck
for a research audience — it is where taint tracking and usefulness collide. Discuss it in
the README rather than resolving it.

---

## Acceptance criteria

- Three sandboxes, three hops, real messages between them.
- Chain visible at the sink: origin, hops, accumulated taint, effective capability.
- Both denial types demonstrated separately: **out-of-scope parameter** (claim 4) and
  **attempted widening** (claim 2). They are different failures; do not collapse them.
- The demo prints, for the BASELINE, the per-hop local view that made each hop's behavior
  locally correct. The finding is that local correctness composes into a global failure.
- Rungs 0–3 demos still pass.

---

## Explicitly NOT enforced (backlog, not a next rung)

- **Intent → scope.** The root capability is hand-written. Over-scope it and attenuation
  is theater.
- **Cross-cloud identity/attestation.** Still "the local runtime says so." The scenario's
  premise (different cloud environments) is not actually met by the implementation.
- **Capability theft and replay** across hosts.
- **Taint laundering by summarization** at the semantic level: rung 4 tracks the label
  through a middle hop, but a hop that *summarizes* tainted content into new bytes is
  handled only because the label is carried by the runtime, not by content analysis. If
  an agent ever re-enters content through an unlabeled path, the chain breaks. Test this
  if time permits and report.
- **Granularity:** message-level, not field-level taint. Nothing knows *which* parameter
  came from tainted data — claim 5 is enforced by allowlist, not by data flow.

---

## Outcome (rung 4, implemented — tag `rung-4`)

Answering this spec's own questions, and recording where it was wrong about this tree.
Full detail in `ladder/rung4/README.md`; the ladder-wide verdict is in `ladder/README.md`.

- **P4's first leak does not exist in this tree, and the BASELINE had to be rebuilt around
  that.** "Rung 3's label does not survive re-emission by a middle hop that is itself
  clean" is false here: rung 3's `Ingest` taints the *receiving sandbox* and `Stamp` reads
  the bit at send time, so a clean middle hop stamps `taint=1` on everything it sends after
  accepting a tainted message. Rung 3's own crack section calls this an accidental
  half-step. Consequence: any three-hop attack whose taint rung 3 can see is *blocked by
  rung 3*, so a passing BASELINE had to use the channel rung 2 does not label — an HTTP
  fetch, which is also the deck's actual scenario — and the leak rung 3 never addressed,
  which is authority. What rung 4 adds to the taint story is therefore the hop list and
  the **origin**, not the bit.
- **Where chain state is carried: both, and the split is the finding.** The hop list and
  origin travel in the stamp (rung 3's machinery, `v=2`, `StampLen` widened 128→256), and
  the capability state is held broker-side in one host process (`common/chaind/chaind.py`),
  keyed by hop name — the broker learns the hop from its own `--task-id` and the relay
  learns it from which socket the connection landed on. The reason it is not one or the
  other: the origin is the path the first hop read, which only that sentry ever knew, so no
  host-side component can reconstruct it; the capability arithmetic needs the goal record
  and three delegations made at different times, which no single sentry sees.
- **Conventions §2's rung-4 row is over-claimed** — the third rung in a row to correct that
  table. Measured by the `ENFORCED-3` block (same attack, `--ladder-chain` off): the taint
  bit still crosses three hops, the widening is still refused, the out-of-scope key is
  still refused. Only the origin is lost. Corrected row: *with the flag off, provenance
  detail is lost; capability verification is unaffected, because it never lived in the
  runtime.*
- **`granted ⊆ caller's` was straightforward and wants no capability library.**
  `chaind.subset` is twelve lines with one subtlety: a delegation that omits a `keys`
  constraint the delegator holds is asking for the tool *unconstrained*, which is a
  widening rather than a default. This is evidence **against** adopting Biscuit or
  Macaroons for the arithmetic and **for** adopting them for what they actually provide —
  attenuation and caveat verification without a central authority, which is precisely the
  limitation this demo has. A follow-up that reaches for Biscuit to get subset checking is
  solving the easy half.
- **The optional fourth block (tainted-but-correct parameter) is the most useful result.**
  The capability layer allows it — the key passes the allowlist, which is claim 5's
  exemption working — and rung 2's per-sandbox gate refuses it anyway, because it fires at
  the socket write and never looks at the parameter. So **claim 5's exemption is
  unreachable in this tree whenever the tainted bytes came through a labeled path**, and a
  correct, in-scope, goal-authorized change is lost. The demo prints both verdicts on the
  same call rather than resolving the disagreement.
- **Patch size:** 299 added lines across 9 files in `pkg/` and `runsc/`, of which 212 are
  the one new file (95 of those comment or blank); the changes threaded through existing
  files come to 87 lines. The host side moved further: 876 lines across 12 files in
  `ladder/common/`, including 452 lines of new capability authority. The smallest runtime
  patch of any rung that has one, and the ratio is the rung's main finding.
- **Not done, and now four rungs old:** ladder state is still package globals and still not
  part of saved state, so checkpoint/restore launders the chain as well as the taint bit.
  Rung 3 predicted rung 4 would have to fix this "anyway". It did not — nothing in the demo
  depends on it, and the fix is a refactor across three rungs' globals.

---

## Report back

Conventions §7, plus:

- Where chain state is carried (stamp payload vs broker-side lookup keyed by connection)
  and why.
- Whether the `granted ⊆ caller's` check was straightforward or wanted a real capability
  library — evidence for or against adopting Biscuit/Macaroons in a follow-up.
- What happened in the optional fourth block (tainted-but-correct parameter).
- **The ladder's overall verdict:** where did runtime-level enforcement stop helping, and
  where did authorization logic have to move into the broker? That answer is the framing
  research question of the whole exercise (deck slide 14) and should be written up as a
  short section in `ladder/README.md`, not just in this rung's file.
