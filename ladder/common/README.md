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
send-agent PEER MESSAGE                rung 3+; peer messaging
script FILE                            run a list of actions; ${VAR} expands from env
```

`read-source` and `send-agent` exist because conventions §4 requires them in the shared
harness. Rung 0's demo calls neither: it has no notion of a source label and no
injection story.

## The broker

Runs on the host, outside every sandbox, holding the only credential in the system and
listening on a unix socket bind-mounted in. It hands back results, never keys. One JSON
object per connection:

```
-> {"tool": "read_metrics", "args": []}
<- {"decision": "allow", "result": "..."}      or  {"decision": "deny", "reason": "..."}
```

Rung 0's authorization is deliberately trivial — "is this a known tool name" and
nothing else — so that the rung-1 diff, which narrows the tool set per task, is legible
as a diff. Every request is logged with its decision and reason.

Note for anyone extending it: gVisor refuses host unix sockets by default
(`--host-uds=none`), and a sandbox without `--annotation dev.gvisor.flag.host-uds=open`
sees `ECONNREFUSED`, which looks like a dead broker rather than a policy denial.

## The world

Everything the agent might reach is a local container, so the demos never touch the
internet. The metadata endpoint is a real listener at `169.254.169.254`, on a docker
network whose subnet is `169.254.0.0/16` — that matters, because "blocked" and "nothing
was listening" are indistinguishable from inside the sandbox, and a baseline check that
cannot fetch a token proves nothing about the enforced one.

Docker's embedded DNS does not work under runsc (netstack does not inherit the
namespace's NAT rules), so names come from `--add-host` entries applied identically to
both configs.
