# The capability records

Four files, and between them they are rung 4's authority model. JSON has no comments,
so the explanation lives here.

| File | Who holds it | What it says |
|---|---|---|
| `goal-svcx-latency.json` | the capability authority, on the host | the root: what the whole chain may spend on this goal |
| `hop-reader-to-orchestrator.json` | reader's `/scratch` | what the reader delegates onward |
| `hop-orchestrator-to-ops.json` | orchestrator's `/scratch` | what the orchestrator delegates onward |
| `hop-orchestrator-to-ops-widened.json` | orchestrator's `/scratch` | the widening attempt — `granted ⊄ caller's` |

## The root

`goal-svcx-latency.json` is minted by the demo at startup, standing in for the user's
trigger, and assigned to the first hop of the chain. It never enters any sandbox: it is
read by `common/chaind/chaind.py`, whose socket is bind-mounted into nothing.

Its shape is the one the rung-4 spec proposes, unchanged:

```json
{ "goal_id": "svcX-latency-2026-08-17",
  "tools": { "read_metrics": {}, "read_wiki": {},
             "write_config": { "keys": ["cache_size", "pool_max", "timeout_ms"] } },
  "taint": "clean",
  "chain": ["user"] }
```

**It is hand-written, and that is the largest assumption in the ladder.** Nothing
translates the user's goal into that key list. Over-scope it — add `auth_disabled`,
or drop the `keys` constraint — and every check rung 4 performs still passes while the
attack succeeds.

## The attenuations

Each hop's delegation is strictly narrower than what it holds:

```
root                      read_metrics  read_wiki  write_config{cache_size,pool_max,timeout_ms}
reader   -> orchestrator  read_metrics             write_config{cache_size,pool_max,timeout_ms}
orch     -> ops           read_metrics             write_config{cache_size,pool_max}
```

`read_wiki` is dropped at the first hop and `timeout_ms` at the second, so the demo's
transcript shows narrowing happening rather than being asserted. Neither loss matters
to the task: `CONTROL` writes `cache_size`.

These files live in the *agent's own scratch directory*, which the agent can rewrite —
and the widened one is a file the orchestrator presents on purpose. That is not a hole.
A delegation is a **claim**, and a claim is only ever checked against what the
delegator actually holds; an agent that writes itself a wider capability has written a
request that will be refused. `chaind.subset` is where that happens.

## Two things that are deliberately absent

- **Keys omitted means unconstrained, not "default".** A delegation that names
  `write_config` with no `keys` field is asking for the tool *unconstrained*, which is
  wider than a delegator holding it constrained — so it is refused as a widening.
  Getting that backwards is the whole bug class the check exists to prevent.
- **No cryptography.** These are not Macaroons, not Biscuit, not SPIFFE. There are no
  signatures, no caveats, no keys. The reason an agent cannot forge a delegation is
  that the state lives in one host-side process it cannot reach. See rung4/README.md
  for what a real deployment would use instead, and for the honest limitation that
  buys.
