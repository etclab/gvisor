# Rung 0 — Ambient authority

Read `00-conventions.md` first. Deck: slides 5–7. Tag: `rung-0`. Flags: none.

**Config only — no gVisor code changes in this rung.** If you find yourself patching the
tree, stop: either the config approach was not exhausted, or you have found a real
limitation worth reporting.

---

## Problem (P0)

An agent's *possible* actions are its environment's permissions — ambient credentials,
open network, writable filesystem, arbitrary exec. Its *needed* actions are its task's
requirements. The gap between them is latent blast radius. No attacker is required: a
hallucinated "helpful" action is enough. Authority is ambient in the environment, so an
agent can act outside its task's needs.

---

## Enforcement claim

Under the rung-0 sandbox, an agent process cannot:

1. **Credentials** — read cloud/API credentials from its environment: no secrets in env
   vars, no `~/.aws` or equivalent config files, no mounted service-account token, no
   reachable cloud metadata endpoint (`169.254.169.254`).
2. **Network** — reach any host outside an explicit allowlist; egress is deny-by-default.
3. **Filesystem** — write anywhere except a designated scratch path; root filesystem is
   read-only and no host paths are visible beyond those explicitly bound.
4. **Exec** — run binaries outside the image's intended tool set, in particular none that
   reopen channels 1–3.

And it *can* still do exactly one useful thing: call the tool broker over its unix
socket, which performs privileged actions on its behalf using credentials the sandbox
never sees.

**Success criterion:** the set of world-effects the agent can cause equals the broker's
tool allowlist and nothing else — i.e. reachable damage is *enumerable from config*.
The rung-0 deliverable is a channel-by-channel table that shows this.

---

## What to build

```
ladder/rung0/
  README.md
  demo.sh
  config/
    baseline/        # deliberately typical, permissive setup (the BASELINE)
    rung0/           # the locked-down setup (the ENFORCED config)
  expected/
ladder/common/       # harness per conventions §4 — built here, reused by later rungs
```

Rung 0 is where the shared harness (`fake_agent`, `broker`, `probes`, `lib.sh`) is
created. Budget accordingly: most of this rung's work is harness, not policy.

---

## Mechanism

**Sandbox:** stock `runsc`. Use it however is most convenient on the box — either
directly (`runsc run` with a hand-written OCI `config.json`) or via Docker with runsc
registered as a runtime. Prefer whichever gives you cleaner control over mounts,
environment, and network namespace; document the choice.

**Per channel:**

1. *Credentials* — construct the OCI spec's `process.env` to contain nothing sensitive;
   bind no credential paths; ensure no service-account file is mounted. The metadata
   endpoint is handled as a network case (below); note in the README that on a real
   cloud VM this is the difference between "no route" and "unreachable link-local
   address".
2. *Network* — this is the one requiring real investigation. Confirm what the checked-out
   runsc actually offers before choosing:
   - `--network=none` — trivially satisfies deny-by-default but kills the LLM API and any
     legitimate host, so it is only useful as one end of the comparison.
   - `--network=sandbox` — user-space netstack. Determine whether the current revision
     exposes any built-in host/CIDR filtering. **Assume it does not** until you confirm
     otherwise.
   - **Most likely correct approach:** put the sandbox in its own network namespace and
     enforce the allowlist *outside* the sandbox with nftables/iptables, and/or route all
     HTTP(S) through a local filtering proxy that enforces the host allowlist. Either is
     acceptable for rung 0 — the claim is about the *sandbox's* reachable set, not about
     where the filter is implemented. Document precisely where the filter lives, because
     rung 2+ may want it inside the runtime.
   - Record in the README which mechanism you used and why, plus what runsc did *not*
     provide. That negative result is useful.
3. *Filesystem* — read-only root plus a writable scratch mount. Check what the current
   tree calls the overlay flag (`--overlay`, `--overlay2`, or successor) and whether the
   OCI spec's `root.readonly` plus explicit mounts is sufficient on its own. Bind no host
   paths beyond scratch and the broker socket.
4. *Exec* — keep the image minimal (no shell tooling, no curl/wget, no cloud SDKs) so
   there is little to exec. Note explicitly in the README that this is a *containment*
   measure, not an authorization one: nothing stops the agent exec'ing what is present.
   Do not add a syscall-level exec policy here; that is a later rung's shape.

**Broker:** runs on the host, holds the only credentials, listens on a unix socket bound
into the sandbox. Rung 0's broker performs no authorization beyond "is this a known tool
name" — do not build policy here yet.

---

## Demo (`ladder/rung0/demo.sh`)

Per conventions §3, three checks. Rung 0's BASELINE is a permissive-but-realistic
container (plain `runc`, or runsc with host network and typical mounts) representing how
an agent gets deployed by default.

1. **BASELINE** — run `fake_agent` with all five probes under `config/baseline/`:
   env-cred read, metadata endpoint fetch, egress to a non-allowlisted host, write
   outside scratch, exec an arbitrary binary. **All five must succeed.** Print the
   channel-by-channel table. If any probe fails here, the probe is broken — fix the
   probe, not the expectation.
2. **ENFORCED** — same five probes under `config/rung0/`. **All five must fail**, each
   with its evidence line (errno, connection refused/unreachable, permission denied,
   exec failure). Print the same table with the outcomes flipped.
3. **CONTROL** — under `config/rung0/`, the agent calls the broker for a legitimate tool
   (e.g. `read_metrics`) and it **succeeds**, and reaches one allowlisted host. Proves the
   lockdown did not simply sever everything.

Local stand-ins: run local listeners for "allowlisted host" and "non-allowlisted host".
For the metadata probe, make sure BASELINE demonstrates the probe *working* against a
local listener standing in for the metadata IP — otherwise "blocked" is
indistinguishable from "nothing was listening", and the ENFORCED result proves nothing.
This distinction must be stated in the README.

---

## Acceptance criteria

- Five channels × two configs table, produced by the demo, committed in `expected/`.
- README's enforcement claim maps each of the four channels to the probe that exercises
  it and the evidence string that proves it.
- The README states, in one sentence, the complete enumerated set of world-effects the
  rung-0 agent can cause.
- No changes to the gVisor tree. `git diff` touches only `ladder/`.

---

## Explicitly NOT enforced (the crack → rung 1)

The allowlists (network hosts, mounts, broker tools) are fixed **per agent at deploy
time**, and are necessarily the *union* of everything that agent's role might ever need —
it needs the LLM API, some hosts, some tools. So rung 0's sandbox is minimal relative to
the **role**, never to the **task**. A task that only needs to read metrics still sits in
a sandbox that can reach the wiki and call `write_config`.

State this in the README as the motivation for rung 1. Do not fix it here.

---

## Report back

Conventions §7, plus specifically:

- **Which network mechanism you used** and what runsc offered natively. This decides
  whether rung 2's enforcement point can live inside the runtime or must stay outside.
- Whether runsc-direct or Docker+runsc proved more workable, and what bit you.
- Whether the metadata-endpoint probe could be made honest (working BASELINE listener) or
  only approximated.
