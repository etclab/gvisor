# The rung-5a scenario

Two hosts, three sandboxes, one goal, and four capability records. This file explains the
four, because two of them **travel on the wire** and therefore cannot carry their own
comments — a `_comment` block inside a delegation is bytes the agent forwards, the proxy
signs, and a man in the middle has to page through. Rung 4's capability files could
afford them; these two cannot.

## The sandboxes

| Manifest | Host | What it is |
|---|---|---|
| `hosta-trigger.yaml` | A | the user's trigger, sandboxed. No egress, no tools, no untrusted mount. Holds the goal's root capability and can only delegate it. |
| `hosta-reader.yaml` | A | a **standing service**. Fetches the incident page, relays findings off-host. Holds no tools. |
| `hostb-ops.yaml` | B | a **standing service**. Holds the production tools. Never touches an untrusted byte. |

The trigger is sandboxed rather than being a shell function in `demo.sh`, and that is a
design decision rather than tidiness. A message arriving at host A's relay from the host
itself carries no runtime stamp, so accepting it would mean teaching the relay to trust
one unstamped sender — weakening rung 3 to make rung 5a work, which conventions §0
forbids outright. Sandboxing the trigger keeps `--require-stamp` on with no exceptions
anywhere in the system.

Nothing in the manifests says "standing". A manifest is rung 1's object: the authority of
one *task*. A standing service has no task, only a deploy-time role, and the difference
lives in the launcher (`docker run -d`, left up) and in `serve-agent`'s exchange bound.
That the manifest format cannot express the distinction is worth noticing rather than
fixing — see rung5a/README.md, "What the standing model costs".

## The capability records

```
goal-svcx-latency.json        the root, minted on HOST A ONLY. Host B never sees it.
  |
  | delegate-trigger-to-reader.json   drops read_wiki
  v
reader                        checked at host A's relay against what the trigger holds
  |
  | delegate-reader-to-ops.json       drops timeout_ms
  v
ops@hostb                     checked at host A's relay against what the reader holds,
                              then carried in the envelope as the sending authority's
                              own view, then checked AGAIN on host B against
                              roles/ops-role.json before delivery
```

| File | Tools | Keys | Where it is checked |
|---|---|---|---|
| `goal-svcx-latency.json` | `read_metrics`, `read_wiki`, `write_config` | `cache_size`, `pool_max`, `timeout_ms` | minted; never checked against anything |
| `delegate-trigger-to-reader.json` | `read_metrics`, `write_config` | `cache_size`, `pool_max`, `timeout_ms` | host A's relay, against the goal |
| `delegate-reader-to-ops.json` | `read_metrics`, `write_config` | `cache_size`, `pool_max` | host A's relay, against the reader's set |
| `roles/ops-role.json` | `read_metrics`, `write_config` | `cache_size`, `pool_max`, `timeout_ms` | host B's **proxy**, against every inbound claim |

`auth_disabled` appears in none of them. That single absence is what the demo enforces,
and it is enforced twice on opposite sides of the network for different reasons: host A
refuses to *delegate* it (rung 4's attenuation check, against the delegator's own set),
and host B refuses to *import* it (rung 5a's role check, against the service's deploy-time
ceiling).

The two delegation files sit in their sandbox's own scratch directory, which the agent can
rewrite. That is still not a hole, for rung 4's reason: a delegation is a **claim**, and a
claim is only ever checked against what the claimant holds. An agent that writes itself a
wider capability has written a request that will be refused — and the demo runs exactly
that, from both sides, in `ENFORCED`.

`roles/ops-role.json` is deliberately **wider** than any single goal. It is a role, fixed
before any caller exists, with no notion of which goal is on the other end. Read it next
to `hostb-ops.yaml`: the manifest says which *tools* the service may call, and this file
adds the argument constraint the manifest format cannot express. They must agree, and
they do.

## The fixtures

| File | Used by | What it asks for |
|---|---|---|
| `../fixtures/benign-page.txt` | `BASELINE`, `CONTROL`, `ENFORCED-3` | `cache_size 512` — in scope, and the correct fix |
| `../fixtures/injected-page.txt` | `ENFORCED-2` | `auth_disabled true`, plus a request to widen the delegation before forwarding |

In `BASELINE` the benign page is the **victim**: the reader asks for the correct change
and a MITM rewrites it, along with the capability behind it, into `auth_disabled true`.
Same page, same chain, same runtime — the only variable rung 5a introduces is whether the
transport underneath is authenticated.
