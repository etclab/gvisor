# Rung 1 — Task scoping (role ≠ task)

Status: implemented
Deck: agent-sandbox/deck.html, slide 8
Tag: `rung-1`   Flags: `--ladder-task-scope` (gates claim 4's in-runtime half only)
Verified on: gVisor `e8d730ce1` (tag rung-0) + this rung's patch, Linux 6.8.0-1010-intel, 2026-08-16

## Enforcement claim

1. **Each task runs in a fresh sandbox derived from that task's manifest**, not from the
   agent's role: its network allowlist, its mount, and its broker tool set all come from
   one file. Exercised by CONTROL (each task does its own work and succeeds) and by the
   generator's own output, which a reviewer can read in `expected/`.
2. **An action permitted for task B is denied inside task A's sandbox**, though the same
   image performs both. Exercised by ENFORCED: `probes/task-b.actions` — the identical
   bytes that succeed in task B — is blocked twice in task A, once by the network and
   once by the broker, and the broker's denial names the task.
3. **No state carries between tasks.** Exercised by ENFORCED: task A writes
   `/scratch/task-a-was-here`, that file is still on the host under task A's directory,
   and it is `ENOENT` inside a fresh task B sandbox.
4. **Grants can be narrowed mid-task and never widened.** Exercised twice, at two
   enforcement points, on one running sandbox each time:
   - ENFORCED-2, outside the runtime: a host-only control socket on the task's proxy.
   - ENFORCED-2b, inside the runtime: `runsc ladder-narrow` replacing netstack's IPv4
     filter table, gated by `--ladder-task-scope`. Both refuse a widening request.

## Problem

Rung 0's grants are per-agent and static, fixed at deploy time as the union of
everything the agent's role might ever need. Any single task uses a fraction of that
union: a metrics-reading task sits in a sandbox that can also reach the wiki and call
`write_config`, because some *other* task someday will. The sandbox is minimal relative
to the role and generous relative to the task, and the gap is exactly the attacker's
working set. `manifests/role-union.yaml` is that union written down; the demo's BASELINE
is rung 0 working exactly as claimed, which is the point.

## Mechanism

**Orchestration, mostly.** Claims 1–3 need no gVisor patch and no root.

`gen_spec.py` reads a manifest and emits four files into the task's spec directory
(`rung1/gen_spec.py:190` `cmd_emit`). Nothing else grants the task anything:

| manifest field | becomes | enforced by |
|---|---|---|
| `task_id` | the names of the network, proxy, broker socket and scratch dir | the launcher, outside the sandbox |
| `network_allow` | `--allow` on a proxy serving only this task | `common/world/proxy.py:60` `allows()` |
| `broker_tools` | `--tools` on a broker serving only this task | `common/broker/broker.py:107` |
| `mounts.scratch` | one bind mount, under this task's directory | docker + `--read-only` |
| `ttl_seconds` | a hard `timeout` around the sandbox | `rung1/demo.sh` `run_in_task` |

The emitted `agent.args` is deterministic: runtime-only values (the task's directory,
its proxy's address, the runtime name) are left as `${VAR}` for `lib.sh`'s
`ladder_load_args` to expand at launch, so the spec is a pure function of the manifest.
`demo.sh` proves this by emitting the same manifest twice and diffing.

**Why the task binding cannot be forged.** The sandbox is never told its task id and has
no way to send one. It finds one network, one proxy, one broker socket — and *which
socket it can reach is its identity*. The binding is established by the launcher before
the sandbox exists (`demo.sh` `launch_task`), so there is no protocol message in which
the agent could lie about which task it is. Taking a task id from inside the sandbox
would have made the whole rung decorative. This is the first appearance of the
unforgeability idea rung 3 generalizes.

**The patch (claim 4, in-runtime half).** 286 added lines across 8 files, one of them
new (`git diff --stat rung-0..rung-1 -- runsc/`):

- `runsc/config/config.go:466` — `LadderTaskScope bool \`flag:"ladder-task-scope"\``,
  registered at `runsc/config/flags.go:180`. Default off. Config reaches the boot
  process by reflection over these tags, so no serialization code was touched.
- `runsc/boot/network.go:681` — `(*Network).LadderNarrow`, on the urpc receiver netstack
  already registers. It builds an IPv4 `filter` table whose OUTPUT chain accepts the
  allowed destination prefixes and drops the rest, then calls
  `Stack.IPTables().ReplaceTable(stack.FilterID, ...)`. runsc never populates the filter
  table at boot (it ships only `nat`, `runsc/sandbox/network_unsafe.go:69`), so this is
  additive rather than a rewrite of existing rules.
- `runsc/boot/network.go:718` — the monotonicity check. The first call establishes the
  scope unconstrained; every later call must be address-space contained in the installed
  scope or it returns an error *before* `ReplaceTable`, changing nothing.
- `runsc/boot/controller.go:161` — the method-name constant;
  `runsc/sandbox/sandbox.go:2245` — the host-side wrapper; `runsc/cmd/ladder.go` — the
  `runsc ladder-narrow <container-id> <cidr>...` subcommand.

**Why that layer.** Egress policy has to be enforced somewhere the agent cannot reach.
The proxy (ENFORCED-2) is outside the sandbox but inside the network the agent talks to;
netstack (ENFORCED-2b) is below the syscall the agent makes, so the packet never leaves.
The control path is host-only: runsc's control socket is a UDS on the *host* filesystem
whose FD is donated to the sandbox before chroot, and gVisor deliberately does not use
abstract sockets for it (`runsc/sandbox/sandbox.go:97`). Nothing bind-mounts it inside.

## Threat model delta

Assumes the manifest is correct and tight, that the launcher is trusted, and that the
agent is fully hostile inside its sandbox. It does **not** assume the agent is honest
about anything, because nothing asks it.

Does not defend against: a wrong manifest; a compromised launcher or broker; anything
rung 0 already excluded. Two specific holes worth naming rather than burying:

- **`--net-raw` would undo the in-runtime narrowing.** An in-sandbox process with
  `CAP_NET_ADMIN` and a raw socket can call the same `ReplaceTable` through
  `setsockopt(IPT_SO_SET_REPLACE)` (`pkg/sentry/socket/netstack/netstack.go:2902`). With
  runsc's default `--net-raw=false` and this rung's `--cap-drop=ALL --user=65534`, it
  cannot; the `ladder-scope` runtime is registered without `--net-raw` for that reason.
  The gate is host-authoritative under default flags, not tamper-proof under all flags.
- **IPv6 egress is not attenuated.** The patch installs an IPv4 filter table only; the
  v6 table stays at its permissive default. The demo's world is IPv4-only, so the demo
  cannot see this. It is a real gap, not a theoretical one.

## Explicitly NOT enforced (the crack → rung 2)

A task-scoped sandbox still executes **whatever the agent decides to do within scope**.
Rung 1 bounds the action set; it says nothing about *why* an action was chosen. Task B
may write config and read the wiki — so once task B's agent ingests attacker-controlled
content from that wiki, the attacker chooses from task B's in-scope set, and that set
contains a mutating tool. Narrowing helps only if someone knows when to narrow.

For any task worth doing, the in-scope set contains something worth abusing. Rung 2's
taint bit is the first mechanism that distinguishes an action the user asked for from an
identical action a document asked for.

Also out of scope, deliberately: who authors the manifest, and how a user's intent
becomes a scope. That is a backlog item for the whole ladder, not for this rung.

## Demo

```
./demo.sh                        # 15 checks, no root required
./demo.sh --with-runtime-patch   # adds ENFORCED-2b (3 more checks)
./demo.sh --keep                 # leave the world up for poking at
```

Blocks: BASELINE (the role sandbox does both tasks' work, and must succeed), ENFORCED
(task A's sandbox refuses task B's work and cannot see task A's earlier scratch),
CONTROL (each task does its own work and succeeds), ENFORCED-2 (narrowing mid-task, at
the proxy), and with the flag, ENFORCED-2b (the same, inside netstack).

Prerequisites for the default run: docker group membership, a `runsc` runtime, python3.
**No root.** `--with-runtime-patch` additionally needs a runsc built from this tree and
a docker runtime registered with the flag, plus a live sudo credential because docker's
runsc state directory is root-owned:

```
make runsc && mkdir -p bin && make copy TARGETS=runsc DESTINATION=bin/
sudo cp ./bin/runsc /usr/local/bin/runsc
sudo /usr/local/bin/runsc install --config_file=/etc/docker/daemon.json \
     --experimental=true --runtime=ladder-scope -- --ladder-task-scope
sudo systemctl reload docker
sudo -v && ./demo.sh --with-runtime-patch
```

Transcripts of passing runs are in `expected/`.

## Spec corrections

Where the rung-1 spec or conventions §2 were wrong about this tree, and what is true:

1. **The generator emits docker run arguments, not an OCI `config.json`.** The spec asked
   for "manifest -> OCI config.json + runsc invocation". Docker already synthesizes the
   OCI spec, and rung 0's deny-by-default egress *is* a docker `--internal` network with
   one occupant. Hand-writing a bundle and calling `runsc run` would need root and would
   throw away the topology that provides half the enforcement. The generated `agent.args`
   is the same artifact by another name, and stays readable field-by-field.
2. **`--ladder-task-scope` gates less than conventions §2 implies.** The flag table says
   the rung-1 flag means "no per-task narrowing" when off. In fact claims 1–3 are pure
   orchestration: with the flag off, and indeed with stock upstream runsc, per-task
   scoping is fully enforced. The flag gates only claim 4's in-runtime half. Reported
   rather than papered over, per conventions §0 — the alternative was to move working
   enforcement into the runtime for the sake of matching a table.
3. **Mid-task attenuation is implementable entirely outside runsc**, as the spec
   suspected. Rung 0's filter is external, so narrowing is a control call to the proxy.
   Both routes are implemented; the external one needs no patch, no build and no root.
4. **The `filter` table is empty at boot.** Verified: `runsc/sandbox/network_unsafe.go:69`
   hardcodes the table name `nat`, and `runsc/boot/network.go` only ever calls
   `netfilter.SetEntries` with that blob. Installing a filter table at runtime therefore
   adds rules rather than replacing rules someone else relies on.
5. **`runsc ladder-narrow` exits 128 on rejection, not 1.** `runsc/cli/cli.go` maps every
   non-success exit to 128. A demo must assert non-zero, never `-eq 1`.
6. **Docker keeps runsc state under one root for every runtime**
   (`/var/run/docker/runtime-runc/moby` here), not a per-runtime directory. `demo.sh`
   reads the path out of the sandbox process's own argv rather than guessing; the first
   version of this demo guessed and silently skipped the whole block.
7. **python3's standard library has no YAML parser** and the ladder installs nothing, so
   `gen_spec.py` parses a small explicit subset and *rejects* anything else, including
   unknown fields. A field that silently fails to parse is a grant that silently fails to
   apply.
8. **Rung 0's spec-correction 5 still binds:** docker's embedded DNS does not work under
   runsc, so every task gets identical `--add-host` entries for the whole world. A
   denial is then always the allowlist talking and never a name that failed to resolve.

## Open questions

- **Checkpoint/restore resets the scope.** `controller.refreshHandlers()` registers a
  fresh `&Network{}` on restore, so `ladderScope` returns to nil and the next control
  call could re-widen. Fine for a prototype, wrong for anything real; rung 4's chain
  attenuation will need the scope to be part of saved state.
- **One proxy and one broker per task is fine at three tasks and silly at three hundred.**
  The unforgeability argument only needs the binding to be established outside the
  sandbox, not a whole process per task. A single broker keyed by the socket it accepted
  on would preserve the property; it was not worth the code here.
- **`ttl_seconds` bounds the sandbox, not the grant.** Nothing expires an allowlist entry
  early. Rung 4 may want time-bounded capabilities, at which point the manifest grows a
  field and this note becomes a design question rather than a limitation.
