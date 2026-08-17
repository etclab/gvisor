# Rung 4 — N hops, authority laundering

Status: implemented
Deck: agent-sandbox/deck.html, slides 13–14
Tag: `rung-4`   Flags: `--ladder-chain` (composes with rung 3's `--ladder-attest`,
`--ladder-peer-channels`, and the per-container `--ladder-identity` / `--ladder-grants`)
Verified on: gVisor `release-20260810.0-67-ge81dec090e2b`, Linux 6.8.0-1010-intel,
2026-08-17

The destination. Three hops, and the thing that decides the privileged call at the end
is no longer the acting agent's identity, scope or taint state — it is the capability
the user's goal minted, attenuated at every hop and never widened, plus the provenance
the runtime accumulated along the way.

---

## Enforcement claim

1. **Chain labels accumulate in the sentry.** A message's stamp names every hop it has
   passed through and the first untrusted source anywhere upstream, both accumulated on
   the receive path from the stamp that arrived. A middle hop that read nothing
   untrusted re-emits both truthfully and cannot edit or suppress either. Exercised by
   `ENFORCED` (`chain=reader>orchestrator` in the stamp ops was handed) and by
   `ENFORCED-2` (`taint=1 origin=/untrusted/injected-page.txt` stamped by a sandbox with
   no untrusted mount, log line `LADDER CHAIN extend sender=reader
   inbound="reader" origin="/untrusted/injected-page.txt" chain=reader`).
   **Read claim 1 with spec correction 1**: the taint *bit* already crossed hops in rung
   3. What rung 4 adds is the hop list and the origin.
2. **Attenuation-only delegation.** Each hop may narrow the capability it passes on and
   never widen it; `granted ⊆ caller's own set` is checked at the relay, before the
   message exists, and a widening attempt is denied and logged. Exercised by `ENFORCED`
   (`granted is not contained in the caller's own set: tool 'write_config': key(s)
   auth_disabled not held by the delegator`) against `BASELINE`, where the identical
   widening is delivered because nothing checks a delegation.
3. **Chain-aware authorization at the sink, failing closed.** A privileged call is
   authorized against the accumulated capability of the chain that produced it, not
   against the calling agent's identity or its rung-1 tool scope. A hop that is in no
   chain is authorized against nothing. Exercised by `ENFORCED`: the chain view at the
   sink (`chain=user>reader>orchestrator>ops`, `effective=read_metrics
   write_config{cache_size,pool_max}`), and `hop 'nobody' is not in any chain for this
   goal, so there is nothing to authorize this call against`.
4. **An out-of-scope parameter fails closed at the enforcement point even though the
   acting agent's credentials would permit it.** Exercised by `ENFORCED`: `key
   'auth_disabled' is outside the capability allowlist for goal svcX-latency-2026-08-17
   (allowed: cache_size,pool_max; chain user>reader>orchestrator>ops)`. That the
   credential would have worked is not asserted, it is *demonstrated* — the same broker
   holding the same credential wrote `auth_disabled=true` in `BASELINE`, and nothing
   about ops differs between the two blocks.
5. **Tainted content may inform analysis but may not parameterize a privileged operation
   unless the parameter passes the allowlist.** Half-enforced, and the honest reading is
   in "Where taint and usefulness collide": the capability layer implements the
   exemption, and in this tree the exemption is *unreachable*, because rung 2's
   per-sandbox gate refuses the call before the broker is reached. Exercised by
   `ENFORCED-4`, which prints both verdicts on the same call.
6. **The accumulated chain is readable from the host without the relay's cooperation.**
   `runsc ladder-status` reports it over the control socket. Exercised by `ENFORCED-5`
   (`--with-control-query`): `LADDER chain chain=true hops=reader>orchestrator
   origin="/untrusted/injected-page.txt"`, read out of a sandbox that has no mount for
   that path.

---

## Problem

Rung 3 gives each hop a truthful, unforgeable label about its *immediate* caller, and
that is enough for one hop. With three, two different things leak, and conflating them
is the main design risk of this rung.

**Authority provenance is absent.** Nothing ties ops's action back to what the user's
goal permitted. Ops holds `write_config` in its rung-1 manifest; the credential the
broker holds would set any key at all; rung 3's `grants` field is per-tool and is not
consulted by anything. Every layer rungs 0–3 built answers "may this task call
`write_config`" — yes — and no layer anywhere answers "is `auth_disabled` inside what
the user asked for". A page that nobody authenticated ends up spending production
authority through three hops that each behaved correctly, and the middle hop has almost
no permissions to exceed.

**Taint provenance is thin.** Rung 3's inheritance does carry the *bit* transitively
(rung 3's own crack section calls this an "accidental half-step"), so a receiver knows
something untrusted is upstream. It does not know *what*, or through which hops — and
an operator holding "this sandbox is tainted, source `peer:orchestrator`" has a dead end
rather than an incident.

---

## Mechanism

### The three hops

```
reader          orchestrator            ops
wiki.corp:80    no untrusted mount      broker socket (read_metrics, write_config)
no broker sock  no broker socket        no untrusted mount
untrusted: ro   no egress               wiki.corp
peer            peer                    peer
```

Three manifests, three `--internal` networks, three brokers, three mailboxes on one
relay, no shared writable mount — rung 1's launcher and rung 3's postbox, unchanged,
with one more task. See `manifests/`.

The middle hop is worth staring at: it has no untrusted mount, no broker socket, no
egress and no tools. It is the cleanest sandbox in the demo by every measure rungs 0–3
offer, and it is where provenance was being lost.

**The untrusted source arrives over HTTP.** `fixtures/injected-page.txt` is served by
the wiki container and fetched by the reader through its own proxy, because that is the
deck's scenario ("an injected web page shapes Reader's findings") and because it makes
the two problems separable: rung 2 labels *mounts*, so bytes arriving over a socket
taint nothing, and the chain carrying the instruction is clean from end to end by every
measure rungs 0–3 offer. Nothing was weakened to arrange that — rung 2's README records
per-connection labeling as considered and not implemented (its Mechanism decision (a)
and open question 2) — but rung 4 is the first rung to *use* the gap, and a reviewer
should see it named. `ENFORCED-2` runs the identical chain against the identical page
read from `/untrusted` instead, so both worlds are demonstrated rather than argued.

### Where the capability lives, and why it is not in the runtime

`common/chaind/chaind.py`, on the host, bind-mounted into nothing. It owns the goal
record and every per-hop attenuation derived from it, and it answers three questions:

| Op | Called by | Question |
|---|---|---|
| `mint` | `demo.sh`, standing in for the user's trigger | assign the root capability to hop 1 |
| `delegate` | the postbox, on relay (`postbox.py:228`) | is `granted ⊆ what this hop holds`? |
| `authorize` | the broker, before spending the credential (`broker.py:130`) | is this call inside the chain's capability? |

The two verification points are where the spec puts them, and for the reason it gives:
the broker holds the credential, so a denial there is a denial in fact; the relay is
where a delegation physically happens. Both are outside every sandbox, and each learns
*who is asking* from something the agent cannot name — the broker from its own
`--task-id` (one broker per task), the relay from which socket the connection landed on.

`chaind.subset` (`chaind.py:90`) is the whole of claim 2 and it is twelve lines. Two
axes: every tool in the grant must be held, and a `keys` constraint the holder carries
must be carried and narrowed by the grant. **Omitting the constraint is a widening, not
a default** — a delegation naming `write_config` with no `keys` field is asking for it
unconstrained. Getting that backwards is the entire bug class the check exists to
prevent, and the demo's smoke path covers it.

Deliberately **not** Macaroons, Biscuit, or SPIFFE. What they would be for in a real
deployment: Macaroons or Biscuit for cryptographic attenuation and caveat verification,
so a hop can narrow a capability and a verifier can check the result *without a central
authority* holding the state; SPIFFE for workload identity across clouds, so "hop `ops`"
means something when the hops are in different accounts. The honest limitation of what
is here instead: **the unforgeability comes from centralization plus rung 3's stamping,
not from cryptography.** One process holds all the state, and the only reason an agent
cannot forge a delegation is that it cannot reach that socket. See "Threat model delta".

### What the runtime adds: `chain` and `origin`

`pkg/sentry/ladder/chain.go`, 212 lines, gated on `--ladder-chain`:

- `Extend` (`chain.go:110`) is called from rung 3's `Ingest` (`attest.go:231`) on every
  stamped message, **before the taint check** — a clean hop is still a hop, and a
  receiver that recorded only the tainted ones would report a chain with holes. It
  appends unseen hops in arrival order and records the origin if it has none.
- `ChainHops` (`chain.go:146`) returns upstream hops plus this sandbox's identity, and
  `chainFields` (`chain.go:185`) appends them to the stamp on the send path.
- `Origin` (`chain.go:168`) prefers the inherited origin over the local taint source: a
  sandbox that both received tainted content and read its own labeled file reports the
  upstream one, because that is the one its peer could not have told it.

Monotonic, like the taint bit: only appends, no call shortens a chain or clears an
origin, and a sandbox with two upstreams accumulates the union. Over-approximation is
sound for the same reason it is sound for taint — a chain naming a hop the instruction
did not traverse costs precision; one that omits a hop is a false clean.

### The stamp, v=2

```
LADDER-STAMP v=1 sender=orchestrator taint=1 grants=
LADDER-STAMP v=2 sender=orchestrator taint=1 grants= chain=reader>orchestrator origin=/untrusted/injected-page.txt
```

Rung 4's two fields come **last** and the version goes to `v=2`, so a rung-3 stamp is
byte-for-byte what it was, truncation of an over-long stamp eats rung 4's fields before
the sender or the taint bit, and `parseStamp` (`attest.go:244`) — keyed on field names,
not positions — reads a v=1 stamp from a peer whose runtime lacks this rung and simply
yields no chain.

`StampLen` went from 128 to **256** (`attest.go:66`): a three-hop chain plus an absolute
path does not fit in 128. That constant is a wire contract shared by three
implementations — `attest.go`, `postbox.py`, `fake_agent.py` — and nothing detects a
disagreement at runtime, so rung 4 wrote that down in all three places. Rung 3's
README, which quoted the number twice, was corrected.

### The two denials

They are different failures at different places, and the demo never collapses them:

```
widening   POSTBOX drop from=orchestrator to=ops reason=capability-widening
           CHAIND  delegate from=orchestrator to=ops decision=deny reason=granted is not
                   contained in the caller's own set: tool 'write_config': key(s)
                   auth_disabled not held by the delegator (holds: cache_size,pool_max,timeout_ms)

the write  CHAIND  authorize hop=ops tool=write_config args=['auth_disabled', 'true']
                   decision=deny reason=key 'auth_disabled' is outside the capability
                   allowlist for goal svcX-latency-2026-08-17 (allowed: cache_size,pool_max;
                   chain user>reader>orchestrator>ops; origin -)
```

The first is refused before the message exists, so the widened capability never reaches
ops. The second is refused with ops holding a valid, correctly attenuated capability —
it is the *parameter* that is out of scope.

### The rest of the patch

| What | Where |
|---|---|
| chain and origin accumulation, the whole rung-4 runtime | `pkg/sentry/ladder/chain.go` |
| appended to the stamp on the send path | `pkg/sentry/ladder/attest.go:164` |
| accumulated on the receive path | `pkg/sentry/ladder/attest.go:231` |
| the flag | `runsc/config/config.go:512`, `runsc/config/flags.go:191` |
| installed once, before any task exists | `runsc/boot/loader.go:604` |
| reported to the host | `runsc/boot/ladder.go:63`, `runsc/cmd/ladder.go:160` |
| the capability authority (host-side, new) | `ladder/common/chaind/chaind.py` |
| delegation checked at the relay | `ladder/common/postbox/postbox.py:228` |
| the sink authorized against the chain | `ladder/common/broker/broker.py:130` |

**Patch size:** `git diff --stat rung-3..rung-4 -- pkg/ runsc/` is 9 files, 299
insertions, 12 deletions — of which **212 are the new `chain.go`**, and 95 of those 212 are
comment or blank. The changes threaded through files that already existed come to 87
insertions across 8 files: a call inserted into `Ingest`, a string concatenated in
`Stamp`, a flag, a status field.

The harness moved further than the runtime did: `git diff --stat rung-3..rung-4 --
ladder/common/` is 12 files and 876 insertions, including 452 lines of new capability
authority. That ratio is the rung's main finding, not an accident of style — see "Spec
corrections" and the verdict in `ladder/README.md`.

---

## Where taint and usefulness collide

`ENFORCED-4` is the spec's optional fourth block, and it is the most interesting result
in the rung. `fixtures/injected-inscope-page.txt` is attacker-authored and asks for
`write_config cache_size 512` — the *correct* fix, inside the goal's allowlist, very
likely what the operator would have asked for. The only reason it is right is that this
particular attacker happened to be right.

The two layers disagree, and the demo prints both verdicts on the same call:

```
capability authority  allow  in scope for goal svcX-latency-2026-08-17 via chain user>reader>orchestrator>ops
rung 2's taint gate   deny   LADDER DENY sink=/broker/broker.sock taint=set source=peer:orchestrator
```

The capability layer implements claim 5's exemption: the parameter passed the allowlist,
which is standing in for a validator, so it is allowed — and logged loudly
(`decision=allow reason=parameter-passed-allowlist-despite-tainted-chain`). Rung 2's gate
is on the *sandbox*, fires at the socket write, and never looks at the parameter. It
wins, because it is closer to the syscall.

So in this tree, **claim 5's exemption is unreachable whenever the tainted bytes arrived
through a labeled path.** A correct, in-scope, goal-authorized change was refused, and
the demo asserts the loss rather than glossing it (`the cost: a correct, in-scope,
authorized change was refused`).

Three ways out, none taken here:

- **Field-level taint.** Know that `512` came from tainted bytes and `cache_size` did
  not. That is a data-flow problem, not a label problem, and message-level granularity
  cannot express it.
- **Declassification through a validator, in the runtime.** Rung 2's crack already
  describes it: a gate that accepts an allowlisted *parameter* from a tainted sandbox is
  precisely the "principled declassifier" it deferred. Rung 4 shows where it would have
  to live — the runtime would have to understand the broker's protocol, which is a much
  bigger commitment than a path prefix.
- **Ordering the two layers deliberately** — let the capability check run first and have
  it *authorize* a specific write past the taint gate. That is a declassifier with extra
  steps, and it puts the runtime's refusal at the mercy of a host-side process.

Rung 4 does not resolve this. It makes the collision reproducible, which is the most a
demo can honestly do with it.

---

## Threat model delta

**Assumes.** One host, one operator, a trusted launcher. The runtime is trusted; the
agents are not. `chaind`, the broker and the postbox are trusted and reachable only from
the host user. The root capability is correct.

**The largest assumption, stated where a reviewer will look for it: the root capability
is hand-written.** Nothing translates "investigate why service X is slow and fix its
config" into `write_config{cache_size, pool_max, timeout_ms}`. Add `auth_disabled` to
that list, or drop the `keys` constraint, and every check rung 4 performs still passes
while the attack succeeds. Attenuation is exactly as good as the thing being attenuated.
Who writes that record from a natural-language goal is a backlog item and not a solved
problem — see `capabilities/README.md` and the `chaind.py` docstring, which both say so
at the top.

**Does not defend against.**

- **A compromised broker, relay or capability authority.** All three are host-side
  fixtures holding all the state. Compromise any one and the model is over.
- **Capability theft or replay.** There is no nonce, no expiry, no binding of a
  capability to a message. A record lives until the daemon restarts, and any hop that
  can reach the relay can spend what it holds as often as it likes.
- **Cross-host anything.** Identity is still "the runtime on this host says so", and the
  scenario's premise — hops in different cloud environments — is still not met. Two
  hosts running this patch would believe each other's stamps for no reason at all.
- **An out-of-band path between hops.** Claim 1 is worth nothing if a second route
  exists. That still rests on rung 0's topology, not on this rung.
- **Content-level laundering.** Rung 4 tracks the label through a middle hop because the
  label is on the sandbox. A hop that summarizes tainted content into new bytes is
  handled; a hop that gets content in through an unlabeled path is not, and the HTTP
  fetch this demo is built on is exactly that case. `ENFORCED-3` measures how much of the
  rung survives it: the capability half, all of it.
- **Checkpoint/restore.** Still unfixed, now for four rungs. `chainHops` and
  `chainOrigin` are package globals and are not saved state, so a save/restore cycle
  launders the chain along with the taint bit. Rung 3 predicted rung 4 would have to fix
  this "anyway"; it did not. Making ladder state savable is a refactor across three
  rungs' globals with no demo depending on it, and doing it badly would be worse than
  the honest note. It remains the oldest open item in the ladder.

---

## Explicitly NOT enforced (the crack → beyond the ladder)

The ladder ends here, so this section is a backlog rather than a next rung.

- **Intent → scope.** The root capability is hand-written. This is the crack, and it is
  bigger than any single rung's mechanism.
- **Cryptographic attenuation.** Centralization is doing the work that Macaroons or
  Biscuit would do, and it is the reason the demo cannot survive a hop in another
  account.
- **Field-level provenance.** Nothing knows *which* parameter came from tainted data.
  Claim 5 is enforced by allowlist, not by data flow.
- **Argument-level scope for anything but `write_config`.** The `keys` constraint is a
  one-off. There is no policy language, deliberately (conventions §8), but that means
  every new tool needs its constraint hand-coded in `chaind`.
- **Revocation.** Nothing can withdraw a capability from a hop mid-chain. Rung 1 built
  mid-task attenuation for egress and rung 4 did not extend it to capabilities.
- **The relay as a single point of trust.** Every delegation goes through one process
  that knows every hop. That is a plausible deployment shape and a poor research answer;
  see the verdict in `ladder/README.md`.

---

## Demo

```
./demo.sh                       # six blocks, 43 checks, no root
./demo.sh --with-control-query  # seven blocks, 45 checks; run `sudo -v` first
./demo.sh --keep                # leave the world up for poking at
```

Verify through `make demo RUNG=4` and `make demo-all` rather than running `demo.sh`
directly — rung 4 is in `IMPLEMENTED_RUNGS`, so the regression sweep covers it.

Blocks: **BASELINE** runs rungs 2–3's settings and the attack succeeds — ops writes
`auth_disabled=true`, and the block prints the per-hop local view that made each hop's
behaviour locally correct. **ENFORCED** adds `--ladder-chain` and the capability
authority: the widening is refused at the relay, the write is refused at the broker, the
chain is visible at the sink, and a hop in no chain is authorized against nothing.
**CONTROL** serves a page recommending an in-scope key on the same URL through the same
chain, and `write_config cache_size 512` succeeds. **ENFORCED-2** runs the identical
attack through the labeled path, where taint and origin accumulate across a middle hop
that read nothing untrusted. **ENFORCED-3** repeats that with `--ladder-chain` off and is
this rung's verdict run as an experiment. **ENFORCED-4** is the hard case. **ENFORCED-5**
asks the middle hop's runtime, from the host, what chain it has accumulated.

**Prerequisites.** docker group membership, python3, and a runsc built from this tree,
registered as **both** `ladder-attest` (rung 3's runtime — `ENFORCED-3` runs against it,
because rung 3's configuration *is* rung 4's control for the flag) and `ladder-chain`:

```
make runsc && mkdir -p bin && make copy TARGETS=runsc DESTINATION=bin/
sudo cp ./bin/runsc /usr/local/bin/runsc
sudo mkdir -p /tmp/ladder-runsc && sudo chmod 0777 /tmp/ladder-runsc
sudo /usr/local/bin/runsc install --config_file=/etc/docker/daemon.json \
     --experimental=true --runtime=ladder-chain -- \
     --ladder-taint --ladder-untrusted-paths=/untrusted --ladder-privileged-sinks=/broker \
     --ladder-attest --ladder-peer-channels=/peer \
     --ladder-chain \
     --debug-log=/tmp/ladder-runsc/%ID%.%COMMAND%.log
sudo systemctl reload docker
```

`--debug-log` is not decoration: the sentry's emitter is `io.Discard` without it
(`runsc/cli/cli.go:232`), so the `LADDER CHAIN extend` and `LADDER DENY` lines two checks
grep for would not exist anywhere. `--ladder-chain` is deliberately **not** on
`overrideAllowlist` (`runsc/config/flags.go:247`): it is a gate, like `--ladder-attest`,
and whether provenance is recorded at all stays an administrator's decision. Rung 4 adds
no per-container flag — the chain is assembled from the identity rung 3 already stamps.

A committed transcript of a passing run is in `expected/`.

**How the flag-off case was checked.** `make demo-all` after this rung: rung 0 (23
checks), rung 1 (15), rung 2 (31), rung 3 (26), rung 4 (43) — all PASS, including rungs 2
and 3, which run against the same rebuilt binary with `--ladder-chain` absent. That is
the check that matters for the stamp widening: rung 3's demo compares a forged header
against a delivered one and greps the stamp's fields, and it still passes with a 256-byte
stamp. No gVisor unit or syscall test was run; the flag-off path is one branch in
`chainFields` and `Extend`, and only the ladder demos were used to check it.

---

## Spec corrections

Where the rung-4 spec and conventions §2 were wrong about this tree, and what is true:

1. **Claim 1 was already satisfied by rung 3, and the spec's framing of the first leak is
   wrong for this tree.** The spec says "rung 3's label does not survive re-emission by a
   middle hop that is itself clean". It does. Rung 3's `Ingest` taints the *receiving
   sandbox*, and `Stamp` reads the bit at send time, so a clean middle hop that accepts a
   tainted message stamps `taint=1` on everything it sends afterwards — rung 3's own
   crack section calls this an "accidental half-step". What is genuinely missing at rung 3
   is not the bit but the **hop list and the origin**, and only the second of those turns
   out to need the runtime at all. Rung 4's BASELINE had to be rebuilt around that: an
   attack whose taint is visible to rung 3 is *blocked by rung 3*, so BASELINE uses the
   channel rung 2 does not label (HTTP) and the leak rung 3 never addressed (authority).
2. **Conventions §2's rung-4 row is over-claimed, and this is the third rung in a row to
   correct that table.** The row reads "no chain/capability verification" when the flag is
   off. Measured, by `ENFORCED-3`: with `--ladder-chain` off, the taint bit still crosses
   three hops (rung 3), the delegation check still refuses a widening (broker logic), and
   the out-of-scope key is still out of scope (broker logic). **Only the origin is lost** —
   because the origin is the path the first hop actually read, which only that hop's
   sentry ever knew, and no host-side component can reconstruct it. The corrected row:
   *with `--ladder-chain` off, provenance detail is lost; capability verification is
   unaffected because it never lived in the runtime.* Applying the conventions' own test
   ("put in the runtime only what cannot be enforced outside it") honestly: the origin
   passes, the hop list does not — the relay could assemble it — and the hop list is in
   the runtime anyway, because it is what the origin travels next to and because it is
   what a receiving *agent* can see without asking the relay.
3. **"Where verification lives" was right, and it is the answer to the framing question
   rather than a detail.** The spec puts `granted ⊆ caller's` and the sink authorization
   in the broker and the unforgeable binding in the runtime. That split is exactly what
   the implementation wanted, and the sizes say why: 299 lines of runtime, a third of it
   comment, against 876 lines of host-side harness. The full verdict is in
   `ladder/README.md`.
4. **The `granted ⊆ caller's` check did not want a capability library.** `chaind.subset`
   is twelve lines and one subtlety (an omitted constraint is a widening). This is
   evidence *against* adopting Biscuit or Macaroons for the arithmetic and *for* adopting
   them for what they actually provide — decentralized verification and cross-host
   identity — neither of which this demo needs and both of which it lacks. A follow-up
   that reaches for Biscuit to get subset checking is solving the easy half.
5. **`StampLen` is a wire contract and nothing enforces it.** Not stated anywhere in the
   spec, and load-bearing: three implementations must agree on the width, a disagreement
   is silent (a receiver reads a stamp as body or a body as stamp), and rung 4 had to
   widen it. Now written down in all three files, and rung 3's two stale references to
   "128 bytes" were fixed.
6. **The chain record at a sink includes the sink.** The spec's example chain is
   `[user, reader, orchestrator]`; `chaind`'s record for hop `ops` is
   `user>reader>orchestrator>ops`. The spec's list is what the *stamp* carries (the
   sender's chain); the record adds the holder because the record answers "what may this
   hop do", and a hop's own name belongs in the answer.
7. **`--ladder-chain` needs no per-container configuration**, which breaks the pattern
   rungs 2 and 3 established (rung 2 needed two configuration flags, rung 3 needed three,
   two of them per-container). Rung 4 needs none: the chain is built from rung 3's
   identity and rung 3's channel list. The trend conventions §2 warned about — "expect the
   same shape" — did not continue, and the reason is that rung 4 put almost nothing new in
   the runtime.

### Was this hard?

The runtime patch was the easiest of the three: 299 lines, one new file and 87 lines
threaded through files that already existed, no new
interception point, no new syscall path. Everything rung 4 needed on the send and receive
paths was already there because rung 3 built it — `Extend` is a call inserted into
`Ingest`, and `chainFields` is a string concatenated in `Stamp`.

The host-side work was where the time went, and one design question took most of it:
*how does the broker learn the chain of the message that tasked this hop?* The broker
sees a tool call on a socket; the chain arrives in a stamp on a different socket, at the
relay, minutes earlier. Three options were considered — the agent forwards the stamp it
received (forgeable, so useless), the broker queries `runsc ladder-status` (needs root,
needs the container id, and couples the broker to the runtime), or one host-side authority
holds the state and both the relay and the broker consult it. The third is what shipped,
and it is *why* the answer to the ladder's framing question came out the way it did: the
moment the enforcement point needs to correlate two connections it did not both see, it
needs state, and state on the host is not the runtime's to hold.

---

## Open questions

1. **Is the runtime's chain field worth having, given that the relay could assemble it?**
   Two arguments for it survived `ENFORCED-3`. The origin genuinely cannot be
   reconstructed host-side. And the chain in the stamp is the only provenance a *receiving
   agent* can read — an agent-level policy ("I will not act on instructions whose origin
   is untrusted") has nothing else to consult, and unlike a prompt-level mitigation it
   would be reading a label its own kernel wrote. Neither argument makes it load-bearing
   for a denial, and the README says so rather than dressing it up.
2. **Should the two layers be ordered deliberately?** `ENFORCED-4` shows rung 2's gate
   pre-empting a decision the capability layer was better equipped to make. Any fix means
   the runtime deferring to a host-side process, which is a strictly worse trust story.
   Whether "the blunt layer wins" is the right default is a genuine design question and
   this rung does not answer it.
3. **Does message-level taint plus argument-level capability actually compose?** They
   nearly do here, and only because `write_config`'s parameter happens to be an
   enumerable key. For a tool whose argument is free text the allowlist degenerates and
   claim 5 has nothing left to stand on.
4. **How would revocation work at all?** Nothing in the design can withdraw a capability
   from a hop that already holds one. Rung 1's mid-task attenuation is the shape of an
   answer (attenuation-only, from the host, through a channel the sandbox cannot reach)
   and nobody has tried it for capabilities.
5. **Checkpoint/restore, for the fourth rung running.** The chain is a package global.
   Everything the ladder tracks launders through a save/restore cycle. This should be one
   commit and it has never been the most valuable one available.
