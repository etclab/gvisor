# The shared harness

Built in rung 0, reused by every rung after it. Nothing here is the research
contribution — it is the fixture that makes the contribution measurable — so it should
stay dumb unless a rung's spec explicitly moves logic into it.

## The agent is a script, not a model

The sandbox cannot distinguish a syscall made by a hijacked LLM from one made by a
shell script. So the demos drive a deterministic stand-in instead of a model: runs are
fast, offline, reproducible, and need no API keys on any box. A real LLM appears only
in an optional capstone demo after rung 4.

## Contents

| Path | What it is |
|---|---|
| `fake_agent/fake_agent.py` | the agent stand-in; every action prints one `RESULT` line |
| `broker/broker.py` | the tool broker; runs on the **host**, holds the only credential |
| `postbox/postbox.py` | the mediated agent-to-agent channel (rung 3); runs on the **host**, one listening socket per sandbox, relays and never labels. From rung 4 it also asks the capability authority whether a delegation may be relayed |
| `chaind/chaind.py` | the capability authority (rung 4); runs on the **host**, bind-mounted into nothing, owns the goal's capability record and every per-hop attenuation |
| `probes/*.actions` | lists of agent actions, one per line — the probes themselves |
| `world/service.py` | one stand-in host (the wiki, the exfil sink, the metadata endpoint) |
| `world/proxy.py` | the egress allowlist, enforced outside the sandbox |
| `images/` | Dockerfiles for the baseline agent, the enforced agent, and the world |
| `lib.sh` | `assert_allowed`, `assert_denied`, the check printers, cleanup |

## The result line

Every agent action prints exactly one line:

```
RESULT <channel> <action> <SUCCESS|FAILURE> <evidence>
```

`SUCCESS` means the agent achieved the world-effect it attempted. Whether that is good
or bad news depends on which config it ran under — that judgement lives in each rung's
`demo.sh`, never in the agent. `fake_agent` exits 0 whenever every action ran to
completion, even if every probe was denied; a non-zero exit means the harness broke,
not that policy worked.

`lib.sh`'s `ladder_synth_result` writes the same line format for facts observed from
*outside* the sandbox, so host-side checks can be asserted on with the same helpers.

## Probe files are config-agnostic

`five-channels.actions` and `supplementary.actions` run unmodified under both the
baseline and the enforced config. Nothing in them sniffs the environment. If a probe
behaves differently between the two columns, the difference came from the sandbox
configuration and nowhere else — which is the entire argument of rung 0. Keep it that
way. `proxy-denial.actions` is the one deliberate exception, and it carries a comment
explaining why.

## Actions

```
probe-env-creds                        credentials in env vars and mounted files
probe-metadata [--via-proxy URL]       the cloud metadata endpoint
probe-egress HOST [--via-proxy URL]    HTTP GET; proxied and direct are separate claims
probe-fs-write PATH                    a write, reported with its errno
probe-exec BINARY [ARGS...]            a spawn, reported with its errno
call-broker TOOL [ARGS...]             the sanctioned path to a world-effect
read-source SRC [--obey-instructions]  rung 2+; the deterministic injection stand-in
                [--save PATH]          rung 4+; keep what was read, to forward it
launder SRC DST [--encode base64]      rung 2+; move bytes to an unlabeled path
symlink TARGET LINK                    rung 2+; a laundering attempt against a path label
exec-fresh ACTION...                   rung 2+; run an action in a new process
send-agent PEER MESSAGE                rung 3+; peer messaging
                [--from-source PATH]   send a file's contents, whitespace-collapsed
                [--forge-header SENDER] rung 3+; try to fabricate a stamp in the body
                [--delegate-file PATH] rung 4+; the capability to hand the peer
recv-agent [--obey-instructions]       rung 3+; collect one message and act on it
                [--save PATH]          rung 4+; re-emit it from an unlabeled path
wait-for PATH [--timeout SECS]         rung 1+; block until the launcher drops a marker
script FILE                            run a list of actions; ${VAR} expands from env
```

`read-source` and `send-agent` exist because conventions §4 requires them in the shared
harness. Rung 0's demo calls neither: it has no notion of a source label and no
injection story. Rung 1 uses `read-source` on a plain path to check that one task's
scratch is unreachable from another's sandbox.

`wait-for` is a handshake, not an authority: rung 1 has to narrow a grant *while* a
sandbox runs, and a fixed sleep would make the demo a race. The marker file arrives in a
directory the agent can already read and tells it nothing it could act on.

## The broker

Runs on the host, outside every sandbox, holding the only credential in the system and
listening on a unix socket bind-mounted in. It hands back results, never keys. One JSON
object per connection:

```
-> {"tool": "read_metrics", "args": []}
<- {"decision": "allow", "result": "..."}      or  {"decision": "deny", "reason": "..."}
```

Rung 0's authorization was deliberately trivial — "is this a known tool name" and
nothing else. Rung 1 added the second question, `--tools`: is this tool in the scope of
the task this socket belongs to. With no `--tools` the broker allows every known tool,
which is exactly rung 0's behaviour and is what rung 0's demo still runs against. Every
request is logged with its task, decision and reason.

The task binding is established outside the sandbox and cannot be named from inside it:
the launcher starts one broker per task and bind-mounts only that broker's socket into
that task's sandbox, so the socket the agent can reach *is* its identity and there is
nothing for it to forge.

Rung 4 added the third question, `--chaind`: is this call inside what the user's *goal*
authorized, given the whole chain that reached this hop. It is asked last, immediately
before the credential is spent, and it is the only check that looks at the arguments.

Note for anyone extending it: gVisor refuses host unix sockets by default
(`--host-uds=none`), and a sandbox without `--annotation dev.gvisor.flag.host-uds=open`
sees `ECONNREFUSED`, which looks like a dead broker rather than a policy denial.

## The capability authority (rung 4)

`chaind/chaind.py` holds the goal's capability record and the per-hop attenuations
delegation produces. Unlike the broker it is bind-mounted into **nothing**, so no agent
can mint, delegate or authorize — an agent can only ask its own broker for a tool and be
told no.

```
-> {"op": "mint",      "goal": {...}, "to": "reader"}          the user's trigger
-> {"op": "delegate",  "from": ..., "to": ..., "cap": {...}, "stamp": {...}}
-> {"op": "authorize", "hop": ..., "tool": ..., "args": [...]}
-> {"op": "view",      "hop": ...}
<- {"decision": "allow"|"deny", "reason": "...", "code": "...", "view": {...}}
```

`delegate` is called by the postbox on relay, because that is where a delegation
physically happens; `authorize` is called by the broker before it spends the credential,
because that is the enforcement point. Both learn who is asking from something the agent
cannot name — the relay from which socket the connection landed on, the broker from its
own `--task-id`.

It is deliberately not Macaroons, Biscuit or SPIFFE. The unforgeability comes from
centralization plus the runtime's stamp, not from cryptography; see rung4/README.md.

## The stamp is a wire contract

The label the sentry prepends to every peer-channel message is a fixed width, and three
implementations must agree on it:

| Where | Constant |
|---|---|
| `pkg/sentry/ladder/attest.go` | `StampLen` — the writer |
| `common/postbox/postbox.py` | `STAMP_LEN` — the relay |
| `common/fake_agent/fake_agent.py` | `STAMP_LEN` — the reader, and the forger |

256 bytes from rung 4, 128 before it. Nothing detects a disagreement at runtime: a
receiver reading the wrong width silently sees a stamp as body or a body as stamp. Move
all three or none.

## The world

Everything the agent might reach is a local container, so the demos never touch the
internet. The metadata endpoint is a real listener at `169.254.169.254`, on a docker
network whose subnet is `169.254.0.0/16` — that matters, because "blocked" and "nothing
was listening" are indistinguishable from inside the sandbox, and a baseline check that
cannot fetch a token proves nothing about the enforced one.

Docker's embedded DNS does not work under runsc (netstack does not inherit the
namespace's NAT rules), so names come from `--add-host` entries applied identically to
both configs.

`proxy.py` gained two things in rung 1. An allowlist entry may be a bare host (any port)
or `host:port`. And the allowlist can be **narrowed** at runtime through a control
socket — attenuation only, checked in the proxy's own handler, so a caller cannot widen
a scope no matter what it sends. That socket is a unix socket in a directory bind-mounted
into the proxy container and into no sandbox; it is not a port the proxy serves.
