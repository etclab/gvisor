# Running the agent use case against this runsc fork

This directory drives `boundclaw-agent-usecase` (a separate repo — a three-agent
confused-deputy demo) against the `runsc` built from **this** tree, in one
command per pass. Nothing in the use-case repo is modified: the passes differ
only by which container runtime each agent runs under, which is exactly how that
repo was designed to be swept.

The `ladder/` demos elsewhere in this tree are a separate, self-contained
exhibit. This directory is only about the use case.

## From a clean clone

A fresh clone lands on `master`, which has neither this directory nor `ladder/`.
The work is on the `usecase` branch:

```bash
git clone git@github.com:etclab/gvisor.git
cd gvisor
git checkout usecase

cd usecase
make register     # build runsc from this tree + register boundclaw-runsc.  needs sudo
make sweep        # all three passes, then one comparison table
```

That is the whole setup — two commands after the checkout. Everything else is
fetched or built on demand: `make register` builds runsc with bazel **inside a
container** (`tools/bazel.mk`), so docker is the only build dependency — no host
bazel, Go, or Python toolchain — and the use case itself is cloned automatically
if it is not already on disk (see [below](#where-the-use-case-comes-from)).

Budget 10-20 minutes for the first `make register` on a cold bazel cache; it is
seconds afterwards. `make pass1` alone needs no `register` and no sudo, and is
the fastest way to confirm the plumbing works before building anything.

## What each pass is

| Pass | Runtime layout | Command | Verdict (measured) |
|------|----------------|---------|--------------------|
| 1 | all three agents on the default runtime (runc) | `make pass1` | `ATTACK SUCCEEDED` |
| 2 | all three under `boundclaw-runsc` (this fork) | `make pass2` | `ATTACK SUCCEEDED` — see note |
| 3 | health+insurer under the fork, financial on runc | `make pass3` | `ATTACK SUCCEEDED` |

The confused-deputy attack succeeds in **every** pass right now — that is the
measured result, not a placeholder.
The runtime this fork registers carries the sentry's provenance stamp, but the
`--ladder-*` enforcement flags gate unix-socket / container-annotation paths
that this pure-HTTP workload never crosses, so the fork does not yet narrow an
over-broad HTTP scope. Pass 2/3 are wired and reproducible so that the day the
fork grows HTTP-path enforcement, the verdict flips with **no change to this
harness** — only the expected value in `run.sh`. Until then the harness records
the honest baseline instead of pretending to block.

The use-case image itself is confirmed to run under gVisor — a smoke test of the
built image under `--runtime=runsc` imports uvicorn/httpx/pydantic cleanly and
reports `kernel: 4.19.0-gvisor` — so pass 2/3 fail only if the runtime is
missing, not because the workload is incompatible.

### gVisor breaks Docker's embedded DNS — worked around here

Rehearsing pass 2 against the stock `runsc` runtime turned up a real blocker.
Under gVisor the containers cannot resolve each other's service names:

```
httpx.ConnectError: [Errno -3] Temporary failure in name resolution
```

Docker publishes its embedded resolver at `127.0.0.11` inside the container's
network namespace via host-side iptables DNAT, and gVisor's netstack does not
inherit those rules, so the resolver is unreachable from the sandbox. Verified
directly: under `--runtime=runsc`, `getent hosts financial-verification` fails
while the same command under `--runtime=runc` returns `192.168.16.2`. It is
*only* name resolution — connecting to the peer's raw IP from inside the
sandbox returns HTTP 200 fine.

`net-static.yml` works around it by pinning the three agents to fixed addresses
(`172.31.77.11/.12/.13`) and giving each one `extra_hosts` entries for the other
two, which puts the names in `/etc/hosts` and never consults the resolver. It is
applied to **all three passes**, not just the gVisor ones, so that the runtime
stays the only variable across the sweep.

This is a property of running this workload under gVisor at all, not of the
BoundClaw fork specifically — worth knowing before reading anything into a
pass-2 connection failure.

## Prerequisites

- **docker** with compose v2, caller in the `docker` group. This is also the
  build dependency: bazel runs in a container, so no host bazel or Go is needed.
- **curl** and **jq** on the host.
- **git access to the use-case repo**, unless you already have a checkout to
  point at — the auto-clone uses an SSH URL. `USECASE_DIR` avoids needing it.
- **sudo**, for pass 2/3 only: registering a runtime edits
  `/etc/docker/daemon.json` and reloads docker. Pass 1 needs none of this.
- No host `uv` / `httpx` needed — the attack harness runs *inside* a throwaway
  container on the compose network, reusing the built image. (If you'd rather run
  it on the host, `uv run python -m attack.run …` from the use-case repo still
  works once `uv` is installed; the container path is the zero-dependency
  default.)
- The agents are pinned to `172.31.77.0/24` (see `net-static.yml`). If that
  collides with an existing docker network, change the subnet there.

## Where the use case comes from

It does not have to be a sibling checkout. `run.sh` resolves it in three steps
and uses the first that works:

1. `$USECASE_DIR`, if set — an explicit checkout anywhere. Errors if the path
   does not exist rather than silently falling through.
2. `../boundclaw-agent-usecase` next to this repo, if present. Preferred over a
   clone of our own so local edits to it are picked up.
3. otherwise, clones it to `usecase/.agent-usecase/` (gitignored) and pins it to
   the revision the results below were measured against.

So a fresh machine needs no manual setup — the first `make pass1` fetches what
it needs:

```
use case not found as a sibling -- cloning git@github.com:jbcallv/boundclaw-agent-usecase.git
cloned to .../usecase/.agent-usecase, pinned to 12b1e9f82
```

Later runs reuse that clone without touching the network. Two knobs if the
defaults are wrong: `USECASE_URL` to clone from somewhere else, and
`USECASE_REV` to pin a different revision (say, to test the use case's own newer
work against this runtime). The clone needs access to that repo; if it fails,
the error names `USECASE_DIR` as the way out.

## One-time setup

```bash
cd usecase
make register     # builds bin/runsc from this tree, registers boundclaw-runsc,
                  # reloads docker.  Needs sudo.  Idempotent (re-run any time).
make status       # confirm: runtime registered + which runsc version it points at
```

`register` points the runtime straight at `../bin/runsc`, so after the first
registration every `make runsc` rebuild is picked up by the next container
start — no sudo, no docker reload. Pass 1 needs none of this.

Expect a few minutes on a cold bazel cache (`-c opt //runsc` is ~3 min here);
incremental rebuilds after that are fast. Note this deliberately differs from
the `make runsc && make copy TARGETS=runsc` sequence in the rung READMEs: a bare
`make copy` builds in the *default* config, so that sequence builds runsc twice
and installs the fastbuild binary. `make runsc` here passes `OPTIONS="-c opt"`
to copy so there is exactly one build and the opt binary is the one installed.

## Run

```bash
make pass1        # baseline (no setup required)
make pass2        # under the fork
make pass3        # mixed adoption

make sweep        # all three in order, then one comparison table
./summarise.sh    # re-print that table from whatever is already in results/
```

Each run builds the images, starts the three agents, waits for them, fires the
attack (a `clean` control then the `poisoned` variant), captures evidence, tears
the stack down, and prints a verdict comparing observed vs. expected. `sweep`
keeps going if one pass mismatches, so you always get the full table, and exits
non-zero if any did.

The table is the comparison to paste into the writeup. All three passes have
been run on this machine against `runsc version rung-5a`:

```
PASS   RUNTIMES                  SCOPE AT FINANCIAL     VERDICT
1      3xrunc                    full_account_detail    ATTACK SUCCEEDED
2      3xboundclaw-runsc         full_account_detail    ATTACK SUCCEEDED
3      2xboundclaw-runsc 1xrunc  full_account_detail    ATTACK SUCCEEDED
```

The `clean` control stayed at `eligibility_check` in every pass, so the
escalation is attributable to the injected note rather than to the harness.

## What you get

Every run writes a timestamped dir under `results/` (gitignored):

- `runtimes.txt` — `docker inspect` proof of the runtime each container got
  (this is the authoritative "did it actually run under the fork" check).
- `attack-clean.log`, `attack-poisoned.log` — the harness output.
- `financial-audit.json` — the financial agent's `/audit`, i.e. the exact
  `scope` each request carried. This is the artifact the paper cares about.
- `runsc-logs/` — the fork's per-container debug logs (pass 2/3 only; may be
  root-owned).
- `compose-up.log` — build/start output.

## Switching to a real LLM

Stub mode (default) never calls the API and costs nothing. For a live run:

```bash
LLM_MODE=live ANTHROPIC_API_KEY=sk-... ANTHROPIC_MODEL=claude-sonnet-5 make pass1
```

Only the health-assistant and insurer-orchestrator agents ever call the model;
the financial agent is rule-based in both modes.

## Rebuilding the fork later

```bash
make runsc        # rebuild ../bin/runsc from HEAD; no re-registration needed
```

`make status` prints the version string of the binary the runtime points at, so
you can always attribute a result dir to a specific build.

## Files here

| File | What it is |
|---|---|
| `Makefile` | the entry points above |
| `run.sh` | one pass end-to-end: up → wait → attack → capture → down → verdict |
| `net-static.yml` | fixed addresses + `/etc/hosts` entries; the gVisor DNS workaround |
| `summarise.sh` | comparison table over the latest run of each pass |
| `.agent-usecase/` | the use-case clone, only if there was no sibling (gitignored) |
| `results/` | timestamped evidence per run (gitignored) |
