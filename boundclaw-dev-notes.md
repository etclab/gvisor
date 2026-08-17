# BoundClaw dev notes

Fork-local notes: what lives in this tree that upstream gVisor does not have, how to
run it, and the operational gotchas that cost time to rediscover. Everything here is
a pointer plus the things that are not written down anywhere else — the detail lives
in each directory's own README.

`AGENTS.md` and the root `README.md` are deliberately kept byte-identical to
upstream, so fork-specific orientation goes here instead of diverging them.

## What this fork adds

| Directory | What it is |
|---|---|
| [`ladder/`](ladder/README.md) | six rungs, each removing one kind of authority an agent gets for free, each with a demo that shows the previous rung's attack succeeding and this one's blocking it |
| [`usecase/`](usecase/README.md) | a three-agent confused-deputy demo from a separate repo, driven unmodified against this tree's runsc |
| `pkg/`, `runsc/` | the `--ladder-*` flags the rungs are gated behind; default off |

## Running the ladder

```bash
cd ladder
make demo RUNG=0     # one rung's three-check demo (RUNG=5a for the federation rung)
make demo-all        # every implemented rung, for regressions
```

Rungs 2 and above need a runtime built from this tree, registered under a per-rung
name. Each rung's README gives the exact registration command.

## Running the use case

Separate exhibit, not a rung. Where the ladder drives scripted stand-ins offline,
this runs real HTTP services and can optionally call a real model, so it is where to
look for what this work does to an application nobody wrote for it. Three passes that
differ only in which container runtime each agent runs under.

```bash
cd usecase
make register        # once, needs sudo: builds bin/runsc, registers boundclaw-runsc
make sweep           # all three passes, then one comparison table
```

It drives the `boundclaw-agent-usecase` repo without modifying it, and needs no host
Python — the attack harness runs in a container. That repo does not have to be checked
out next to this one: `run.sh` takes `$USECASE_DIR` if set, falls back to a sibling
checkout, and otherwise clones a pinned copy under `usecase/.agent-usecase/`, so a
fresh machine needs no manual setup. Full detail, including what each pass means and
what evidence it captures, is in [`usecase/README.md`](usecase/README.md).

As of the last run all three passes end `ATTACK SUCCEEDED`. That is the honest
baseline, not a failure: the fork carries provenance over this HTTP path, but no
`--ladder-*` flag gates it, so nothing yet narrows an over-broad scope. When
HTTP-path enforcement lands, flip the `EXPECT` constant for pass 2 in `usecase/run.sh`
and nothing else changes.

## Gotchas worth not rediscovering

**gVisor cannot reach Docker's embedded DNS.** Under runsc, containers cannot resolve
each other's service names — Docker publishes its resolver at `127.0.0.11` via
host-side iptables DNAT, and the netstack does not inherit those rules. Symptom is
`[Errno -3] Temporary failure in name resolution`. It is *only* name resolution;
connecting to a peer's raw IP from inside the sandbox is fine. `usecase/net-static.yml`
works around it with fixed addresses plus `extra_hosts`. Worth knowing before reading
anything into a connection failure under gVisor.

**`make copy TARGETS=runsc` builds in the default config, not `-c opt`.** So the
`make runsc && make copy TARGETS=runsc DESTINATION=bin/` sequence in the rung READMEs
builds runsc *twice*, in two different configurations, and it is the fastbuild binary
that ends up in `bin/`. Passing `OPTIONS="-c opt"` to `copy` makes the build and the
copy agree, so there is one build and the opt binary is installed — that is what
`usecase/Makefile`'s `runsc` target does. The rung READMEs still document the
two-build sequence.

**One runtime name, several checkouts.** A registered runtime records an absolute
path to a binary. With more than one clone of this tree around, `boundclaw-runsc` can
be registered and resolve to a *different* clone's runsc, so results get attributed to
the wrong build. `cd usecase && make status` prints where the name actually resolves
and warns when it is not the current checkout. Re-run `make register` from the
checkout you mean to test.

**Sentry debug logs need `--debug-log`.** The sentry's log emitter is `io.Discard`
unless a debug log is configured (`runsc/cli/cli.go`), so without it the `LADDER
TAINT` / `STAMP` / `DENY` lines the demos grep for do not exist anywhere. `--debug` is
*not* needed — those lines are logged at warning level. The logs land as root-owned
files under `/tmp/`, which an unprivileged caller cannot clear between runs; select by
mtime rather than assuming the directory is empty.
