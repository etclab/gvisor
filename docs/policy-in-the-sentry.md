# Policy in the sentry: a pushed policy a running sandbox honours, and says it is honouring

Ticket 26. Ticket 25 put an adapter in the sentry and gave it a table read once at boot; a policy
pushed over the contract reached the helper, which logged it and acknowledged it, and narrowed
nothing. This is the thing Deno could not do. Five pieces. (1) `Apply` reaches the sentry: the
helper beside the sandbox forwards the pushed bytes on the control socket as `Policy.Narrow`
(`runsc/boot/controller.go:157`, `runsc/boot/policy.go:101`), which replaces ticket 25's in-sentry
table **in place, with no restart and no lost workload**. (2) A component-wise `P1 ⊑ P0` over
sorted deduplicated atoms — `n ⊆`, `f ⊆`, `x ⊆` — with a widening refused in a sentence that names
the component (`policy.go:440`). (3) `N` enforced in the connect hook and in the DNS responder,
`X` enforced by a seccheck sink that returns `EACCES` on the digest the execve point already
computed (`pkg/sentry/policyx/policyx.go:207`), `F` approximated by read-only, locked, noexec
mounts and by nothing else. (4) Contract v3: an `alive` message from the sandbox every second
carrying the sha256 of the policy in force, a watch on the host, and the taxonomy's eleventh
reason when it stops (`attest/sandbox/live.go:45-60`, `attest/tunneld/push.go:244`,
`attest/refusal.go:123`). (5) The six RQ5 remote-cost components. Three spikes stand under it,
under `docs/snp/evidence/ticket26/spikes/`: **E1** (narrowing under traffic), **E2** (the exec
sink's cost and reach), **E3** (heartbeat cost and teardown timing), beside an **adapter check**
(`docs/snp/evidence/ticket26/adapter-check/`) that asserts all seven obligations of one sandbox at
once. **Tunneld's push path is ticket 22's and ticket 23's** — what this ticket adds to it is the
watch and one reason, and nothing about the wire, the ordering or the once-per-tunnel rule
changed. Work done 2026-09-18, base `6dfa00a1d`, 21 commits, tip `3acfe11b5` — the state every
number here was taken against; the sections still carrying a placeholder are filled by the runs
that follow. Nothing merged, nothing pushed.

**In one sentence:** apply-without-restart is real and is the whole reason this sandbox is gVisor
— a policy pushed over the contract replaces the sentry's table in a median of **0.18 ms** of swap
and **3.5 ms** of end-to-end wall time, with a 16 MiB transfer in flight delivering every one of
its bytes — but what a narrowing decides is what may be **opened next** and nothing else: a
descriptor already handed to a socket is that socket's, `f` is parsed and subset-checked and
enforced by nothing, an `x` that names an interpreter does not grant the scripts it runs, and the
only thing that keeps an acknowledgement from being a claim about a past that has already ended is
one `alive` message a second carrying the digest of what is actually in force.

---

## The narrowing path

Six hops, and the enforcement is in one of them.

| hop | where | what it does |
|---|---|---|
| tunneld receives the push | `attest/tunneld/push.go:183` `applyPushed`, `:196` `applyOrRefuse` | reads the envelope, calls `Apply` on the sandbox beside it, once per `*tunnel.Conn` |
| the contract carries it | `attest/sandbox/host.go:128` `Host.Apply` | `{"id":n,"type":"apply","policy":"<base64>"}` to every attached sandbox; the first refusal is the answer |
| the helper forwards it | `runsc/cmd/tunnel_helper.go:171` `apply`, `:188` `narrow` | dials the control socket per apply, one `Policy.Narrow` call |
| the sentry judges it | `runsc/boot/policy.go:101` `Policy.Narrow`, `:159` `Tunnel.narrow` | parse, canonicalise, digest, subset check, swap, record |
| the adapter is replaced | `pkg/sentry/socket/netstack/tunnel.go:279` `NarrowTunnel` | a second adapter carrying the surviving bindings, published by one pointer store |
| the helper says so | `runsc/cmd/tunnel_helper.go:225` `live` | one `alive` for the new digest, synchronously, before the acknowledgement |

**The helper decides nothing.** It holds no policy, parses no component and writes no refusal: it
dials, makes one call, and carries the sentry's sentence back word for word, unwrapping
`urpc.RemoteError` so that the text the peer is told is the text the sentry wrote
(`tunnel_helper.go:198-206`). That is deliberate — the helper is outside the measured boundary, so
a helper that could decide anything could decide it wrongly with nobody able to tell. The control
socket is dialled per apply rather than held, because the sentry's control server starts long after
the helper does and a policy arrives a handful of times in a sandbox's life.

**`Policy.Narrow` is registered only when there is an adapter to narrow** (`controller.go:254-257`,
inside `if l.tunnel != nil`), and it is refused unless the loader has started (`policy.go:106-111`).
That is the inverse of `containerManager.SetNetworkArgs`, which *ignores* a call that arrives after
the sandbox started: a policy is about a running workload, and refusing is not ignoring — the
refusal reaches the peer that made the push.

**The swap is a replacement and not an edit.** `NarrowTunnel` builds a second `adapter` holding the
bindings that survive and stores the pointer, so every reader sees the whole of the old table or
the whole of the new one (`tunnel.go:172-186`, `:279-314`). Three properties fall out of that and
all three were measured:

- **A surviving name keeps the binding it had** — the same synthetic address, the same port, the
  same peer — so an address a workload resolved before a narrowing is the same destination after
  it. E1 saw `bulk.peer-a` at `100.64.1.0` before and after eleven narrowings in one run, ten of
  which removed a name from the middle of the sorted list (E1 §3). Addresses are **not**
  reallocated by sorted index.
- **The local-port counter is shared across adapters** (`tunnel.go:161-169`, `ports` carried over
  at `:299`), so it never rewinds and two live sockets never agree on both ends.
- **Nothing already attached is touched.** See *What N, F and X enforce*, below: this is the
  revocation that does not exist.

**The resolver rebinds by not holding anything.** `serveTunnelResolver` takes the installed adapter
per query rather than capturing it at bind time (`tunnel_dns.go:109`, `:125`), which is the half of
`N` the connect hook cannot enforce: a name that still resolves is a name the workload has an
address for, and an address is a destination it can ask for without ever consulting a name again.

**What E1 measured of all this.** Two runs, thirteen pushes each, twelve accepted, so 24 narrowings
(`docs/snp/evidence/ticket26/spikes/E1/`, `output-01-narrowing-under-traffic.txt`):

| what is measured | n | min | median | p95 | max |
|---|---:|---:|---:|---:|---:|
| the table swap inside the sentry | 24 | 0.057 ms | **0.184 ms** | 0.382 ms | 1.292 ms |
| the whole of `Policy.Narrow` in the sentry (parse, subset check, swap, record) | 24 | 0.229 ms | **0.676 ms** | 1.720 ms | 2.559 ms |
| `Host.Apply` wall time, call to return | 24 | 2.349 ms | **3.506 ms** | 6.425 ms | 42.656 ms |

The first two are the sentry's own lines (`policy.go:230`, `tunnel narrow: applied in …, of which
the table swap was …`); the third is the stand-in's and is everything — the contract's socket, the
helper's callback goroutine, a fresh `ConnectTo` on the control socket, urpc, the sentry and the
same path back. **The gap between 0.7 ms and 3.5 ms is the boundary, not the enforcement.** The one
42.7 ms sample is a run's *first* push, where the control socket has never been dialled; the
adapter check saw the same shape once more, 25.2 ms for P0 against 4.2 ms for P1.

**The stream under it survives, by design.** E1's second run removed `bulk.peer-a` — the name the
open stream was **on** — four seconds into a thirteen-second transfer, and the transfer delivered
all 16,777,216 bytes (E1 §1). A new `connect` to the removed name was refused in both places at
once: `NXDOMAIN` by name and `ENETUNREACH` at its old synthetic address, with one
`egress_refused protocol=dns … reason=unknown-name` per query type and one
`egress_refused protocol=tcp … reason=not-in-table` for the address (E1 §2). The workload observed
nothing else: no signal, no EOF on the open stream, no error, no message of any kind.

## The subset check

An **atom** is a capability spelled as `kind:value`, sorted and deduplicated, and the three
components render to atoms the same way in every implementation in this tree:

```
n  {host, ports}   -> net:<host>:<port>, or net:<host> for every port
f  {path, modes}   -> read:<path>, write:<path>
x  {path | sha256} -> run:<path>, run:sha256:<hex>
```

`cidr` is refused, and refused for a reason about the format rather than about any one sandbox:
every check this design raises on a destination is against the *name* that was asked for — the
connect hook and the DNS responder both see a name — and a name is in no CIDR
(`attest/sandbox/policy.go:186-197`, `runsc/boot/policy.go:316`). An entry that grants exactly the
destinations nobody names is not a grant.

**`P0` for `n` is the boot table.** The first push is checked against the names `--tunnel-table`
gave the sandbox, one atom per row on the one port that row permits (`policy.go:185`, `:476`
`bootTableAtoms`), so a push may not name a destination the operator did not write down. Since a
table row carries exactly one port and the format's bare host means every port, a bare host is
canonicalised to the table's port before the comparison (`:487` `canonicalNetAtoms`); a host the
table does not carry is left alone and refused a moment later by the comparison itself.

**The first push fixes `f` and `x`.** Nothing before a push says anything about files or binaries,
so `P0` for those two components is the push itself (`policy.go:180-186`), and every later push may
only shrink them. The adapter check is the demonstration: P2 is **byte-for-byte P0**, accepted as a
first push and refused as a third, because what it widens is not the boot table but the policy in
force (`adapter-check/notes.md` §1–3).

**The refusal names the component and the atoms that widened**, because "refused" without them is a
message nobody can act on:

```
policy refused: it widens n by [net:gone.peer-a:9001]
```

carried back through the helper and the contract word for word; `attest/sandbox` prefixes its own
`sandbox: policy refused: the sandbox refused it:` and adds nothing else (E1 §6).

**There are three widening checks in this tree and they share a grammar, not a function.**
`attest/sandbox` exports the shared form — `Atoms` (`policy.go:166`), `Widening` (`:292`) and
`CheckNarrows` (`:334`), whose refusal wraps `ErrPolicyRefused` so that a sandbox making the check
refuses a push the way every other refusal of a push is made. The Deno sandbox keeps its own
atomiser, because three of its rules are facts about Deno: it has an `e` letter the format has not,
it refuses a digest it has nowhere to put, and it refuses a host its flag parser would refuse after
the exec rather than before it. And **the sentry keeps a third**, `runsc/boot/policy.go`, for a
reason that is not about grammar at all: `attest/` has no BUILD files and nothing under `runsc/`
can import it, which is the same reason `runsc/cmd/tunnel_client.go` exists. The two spellings are
pinned against each other by a test and by nothing else —
`TestTheAtomGrammarIsTheOneTheDenoSandboxAlreadyJudgedBy`
(`attest/sandbox/policy_test.go:236`), which fixes the exact six atoms of a reference policy and
the four kinds the grammar admits, beside `TestWideningIsOverTheAtomsAndNotOverADocument` (`:204`),
which is what lets a sandbox whose `P0` is not a policy document at all — the sentry's boot table,
a list of names and ports — make the same check.

**The mirror is not a copy, and the differences are recorded rather than reconciled.** The enforcing
implementation is the sentry's; `sandbox.CheckNarrows` has no production caller in this tree. Four
places where the two read one document differently:

| document | `attest/sandbox` | `runsc/boot` |
|---|---|---|
| widens two components | names both: `it widens n by […], x by […]` (`policy.go:351` `widenedBy`) | names the first: `n` is checked before `f` before `x` and the refusal stops there (`policy.go:441-453`) |
| `{"host":"a","cidr":"10.0.0.0/8"}` | refused, because a `cidr` is present (`policy.go:196`) | accepted, the `cidr` ignored, because the host is non-empty (`policy.go:314-319`) |
| an uppercase digest, or a host with a trailing dot | refused / kept as written (`isSHA256Hex`, `policy.go:270`) | lowercased and normalised before the atom is made (`policy.go:323`, `:395`) |
| `{"path":"sha256:deadbeef…"}` in `x` | admitted as `run:sha256:deadbeef…`, colliding with a digest atom | refused: a path may not be spelled the way a digest is (`policy.go:413`) |

Every one of those is a document one implementation would compare differently from the other. None
of them is reachable through the path this ticket built, where the sentry is the only judge — they
are reachable the moment a second enforcer judges the same bytes.

## What N, F and X enforce, and what they do not

### N: two places, and no revocation

`n` is the only component with an address behind it, and it is enforced twice: at the **resolver**,
where a removed name stops resolving at all, and at the **connect hook**, where the address that
name used to have is not in the table any more. Both refusals are ticket 25's and unchanged — a
name is `NXDOMAIN` with `reason=unknown-name`, an address is `ENETUNREACH` with
`reason=not-in-table` — and both write a `sentry/egress_refused` event.

**A narrowing decides what may be opened next. It revokes nothing.** E1's `narrow-self` run is the
statement of it: the name the open stream was on was removed from the policy in force, from the
resolver and from the table, and all 16 MiB still arrived. The sentry keeps no registry of attached
endpoints per name, and `NarrowTunnel` replaces an adapter without touching one
(`tunnel.go:270-278`). **A policy pushed to stop an exfiltration in progress would not stop it.**
What it stops is the next connection. That is by design and it is a limit, and a record that did
not say it plainly would be describing a different system.

**Two DNS events per name and one TCP event**, because busybox asks `AAAA` and `A`; the TCP event
carries a task's context and the DNS ones do not, which is ticket 25's finding and is unchanged
here — the responder has no task.

### X: a sink, an errno, and an identity that is not what the seam map predicted

`X` is a seccheck sink and no syscall-path patch at all. `pkg/sentry/kernel/task_exec.go` fires
`PointExecve` before the new image is installed and, unlike every other seccheck site, propagates
the sink's error into the syscall, so a sink returning `EACCES` is an execve that fails `EACCES`
(`policyx.go:15-33`, `:230`). The decision is on the identity the point already carries: the
resolved path of the first executable the exec opened, and the SHA-256 of its contents, hashed once
per `(mount, inode, size, mtime)` by the LRU in `pkg/sentry/seccheck`. Either half matching is
enough (`policyx.go:117` `Permits`), and a nil allow list permits everything, which is what a
sandbox looks like before the first push that carries an `x`.

A refusal writes a `W` line and a `sentry/exec_refused` point with the path, the digest and
`reason=not-in-x` (`policyx.go:228`, `:236`), and the path is scrubbed to printable ASCII first so
that a path with a newline in it cannot forge a line of the log (`:260` `Printable`). The sink is
installed at the first push carrying an `x` and **never removed** (`runsc/boot/policy.go:137-141`,
`:211-221`): seccheck's only way of taking a sink back takes every sink back, including the remote
one the refusal events go to.

**Two findings about what identity the point reports, neither of them fixed here:**

- **A symlink is reported as the file it resolves to.** E2's workload ran `/bin/uname`,
  `/bin/echo`, `/bin/cat` and `/bin/sh`, all symlinks to `/bin/busybox`, and every one was reported
  as `path=/bin/busybox` with busybox's digest; the whole run had four distinct identities across
  616 execs of busybox (E2 §3a). **An `x` that names `/bin/busybox` by path covers every applet.**
- **A shebang script is reported as the script, not as its interpreter.** `/e2-script.sh` is
  `#!/bin/sh` plus an `echo`; executed directly it is reported with the *script's* own sha256 and is
  refused, while `/bin/sh -c '…'` — the same interpreter, named explicitly — runs, because that
  execve's first opened executable is `/bin/busybox` (E2 §3b). This is the **opposite** of the seam
  map's prediction. It is arguably the better answer, and it has a consequence a policy author must
  know: *an `x` that names an interpreter does not grant the scripts it runs.* A run with
  `x = [/bin/busybox]` that then executes `./setup.sh` gets `EACCES` on the script and no hint that
  the shell was permitted.

**What it costs**, from E2 §1–2 (three rounds of 200 `fork`+`execve`+`wait4` per configuration):

| | median of the three rounds | p95 |
|---|---|---|
| no sink, `PointExecve` off | 18.234 / 18.515 / 17.957 ms | 22.94 / 22.56 / 21.39 ms |
| the sink, refusing nothing | 18.491 / 18.599 / 19.145 ms | 22.51 / 22.15 / 22.35 ms |
| the sink plus an `execve` trace session | 18.101 / 18.966 / 19.036 ms | 22.00 / 22.63 / 22.58 ms |

| | value |
|---|---|
| the X decision itself, measured by the sink | **4.3–5.4 µs**, flat, cached (`exec sink: checked=600 refused=2 mean=4.342µs …`) |
| the decision as a share of one process start | 0.03 % of 18 ms |
| the `sentry/execve` point the decision needs | ≈ **+0.5 ms**, about **3 %** of a process start |
| hash-cache hit rate over 600 decisions | 596 hits, 4 misses — exactly the four distinct files executed |
| cache capacity | 512 entries; nothing measured came near it |

So the decision is free and the *point it needs* is not quite: copying argv and the environment,
`Stat`ing the binary and looking the hash up costs about three percent of a process start, at the
edge of what this benchmark can separate from noise — the three rounds within one configuration
spread by as much as the configurations differ, which is the honest bound on the number.

**The firehose.** `seccheck.State.SentToSinks` calls *every* registered sink, so the moment the X
sink turns `PointExecve` on, any remote sink a trace session already installed starts receiving one
`MESSAGE_SENTRY_EXEC` per exec — **argv and environment included**. E2's run (b) named only
`egress_refused` and `exec_refused` in its session and its receiver logged 621 `execve` lines
anyway (E2 §5). In this design the receiver is a local socket the same operator owns. It is not
nothing, and it is recorded and not fixed.

**An empty `x` forever.** `Allow` distinguishes nil from empty on purpose (`policyx.go:58-66`): nil
means no X is in force and everything runs, and the empty set means nothing runs. Since the sink,
once installed, is never removed and the subset rule only shrinks, a policy that narrows `x` to
nothing is a sandbox in which no further `execve` can succeed for the rest of its life — which is
the correct reading of the document and worth stating, because it is a state no later push can
leave.

### F: mounts only, and `f` is enforced by nothing

`F` is approximated by read-only, locked, noexec mounts and **only** by them. The adapter check
demonstrates all three halves of what that gives on a `["ro","noexec","rbind"]` bind mount:
`rc=126` on an exec, `rc=0` on a read of the same file, `Read-only file system` on a write
(`adapter-check/notes.md` §6). What refused the exec is `MountFlags.NoExec` in
`pkg/sentry/vfs/vfs.go`, not the policy.

The record must say this plainly: **`f`'s atoms are parsed, subset-checked and carried in the
digest, and enforced by nothing.** A policy naming `/noexec` read-only would have been honoured by
that run whatever it said, because the mount was already read-only before a byte of policy arrived.
There is no path × {r,w,x} allow-set anywhere in this tree; the seam map says the only place to add
one is `VirtualFilesystem.OpenAt`, and that was explicitly not this ticket.

And **`locked` is unreachable from a bundle**: it is not an option `ParseMountOptions` knows, and
`vfs.MountOptions.Locked` is set in exactly one place in this tree, for the namespace-root tmpfs.
That is a unit test rather than a paragraph — `TestFIsMountsOnly`, `runsc/boot:boot_test`
(`runsc/boot/policy_test.go:292`) — so that the claim breaks when the fact does.

## The liveness design, and E3's constants

An acknowledgement is a claim about the past, and ticket 23 measured how short a past: the ack left
`Apply` 1.856 ms after `exec.Start`, the workload was dead at 43 ms, and the tunnel was still up —
asserting something the sandbox no longer believed, with no verb in the contract for saying so.
Contract version 3 is that verb, and it is one message with no reply:

> A sandbox that has acknowledged a policy sends `alive` with that policy's digest every
> `sandbox.DefaultPulse`, until it closes. Liveness is lost when an attachment that acknowledged has
> sent none for `sandbox.DefaultMisses` consecutive intervals, sends one whose digest is not the one
> that was pushed, or closes its socket.

`{"id":0,"type":"alive","digest":"<64 hex>"}`, id 0 because it numbers nothing: it goes nowhere near
either side's reply table, and a reply table that grew a slot per second would be the one part of
this socket that leaked.

| piece | where |
|---|---|
| the constants, `DefaultPulse = 1s` and `DefaultMisses = 3` | `attest/sandbox/live.go:51`, `:59` |
| the optional interface, one method | `attest/sandbox/live.go:78` `Live.Watch(ctx, digest) <-chan error` |
| the sandbox sends | `attest/sandbox/client.go:202` `applied` (the acknowledged bytes' digest), `:228` `Alive`, `:239` `pulse` |
| the sentry's sandbox sends | `runsc/cmd/tunnel_helper.go:225` `live`, `:248` `pulse`, `tunneldPulse` at `:131` |
| the host records and judges | `attest/sandbox/host.go:351` `pulsed`, `:361` `acknowledged`, `:370` `lost` |
| the watch | `attest/sandbox/host.go:194` `Watch`, `:175` `watchInterval = DefaultPulse / 4` |
| tunneld starts it and closes the tunnel | `attest/tunneld/push.go:223` `watchPolicy`, `:244` `watchLiveness` |
| the reason | `attest/refusal.go:123` `ReasonPolicyNotLive`, `:140` *the policy pushed to the peer is no longer live* |

**Only a sandbox across a process boundary is watched.** `sandbox.Host` alone implements `Live`, so
a tunneld whose sandbox is in its own process carries its tunnels exactly as before; a sandbox in
this process *is* this process, and a caller wondering whether it is still running has been
answered by the fact that it asked. **Every attachment that acknowledged must be live**, for the
same reason `Host.Apply` returns the first refusal rather than the last: two sandboxes on one
socket are two things enforcing the policy, and one of them stopping is the policy no longer being
enforced. In a guest that pair is the agent and the exit — ticket 25's leftover 14, two
`SANDBOX attached` lines per guest, is exactly this — and `agent-probe` runs them as two clients on
one socket with a test that watches both acknowledge and both pulse.

**Nothing crosses the wire for it.** There is no message that says "your policy lapsed", and adding
one would be telling a peer about the inside of this guest. The refusal is the receiver's alone; the
peer sees what it sees for every refusal after admission, which is that its tunnel went.

### E3's numbers

`docs/snp/evidence/ticket26/spikes/E3/`, on a 64-core machine at load average 24 throughout, so
every figure is an upper bound.

| | value |
|---|---|
| send, 10 000 pulses through `Client.Alive` | mean 30.174 µs, p50 **17.015 µs**, p99 84.727 µs, max 14.8 ms |
| one pulse on the wire | a 99-byte JSON message, 103 bytes with the length prefix |
| send cost at 1 Hz | 0.003 % of one core |
| receive, marginal in a burst of 10 000 | 50.719 µs per message |
| receive, at 1 Hz including the wakeup | **255.3 µs per pulse** = 0.026 % of one core, 22 s of CPU per day |
| 60 ticks of a 1 s ticker | 1m0.000165439s — cumulative drift **165 µs**, worst single tick **2.865 ms** late |

| teardown, 10 trials each | min | median | max | mean |
|---|---:|---:|---:|---:|
| `kill` — the socket closes | 49.923943 ms | **150.597202 ms** | 251.193851 ms | 150.166507 ms |
| `wrong` — a digest that is not the pushed one | 50.007518 ms | **150.666453 ms** | 250.797411 ms | 150.349544 ms |
| `stop` — `SIGSTOP`, three misses | 2.100802209 s | **2.851786545 s** | 3.25096344 s | 2.775334297 s |

All thirty were refused as *the policy pushed to the peer is no longer live*. The failure instant
was swept — trial *i* fails at `2s + i·100ms` after the acknowledgement — so that the ten trials
cover the interval rather than landing on the beat ten times; without the sweep every trial reads
the same number and the spread the constants actually produce is invisible.

**The model the numbers fit.** A watch looks at what each attachment last said every
`watchInterval = DefaultPulse/4` = 250 ms. A close or a mismatch is known the moment it arrives and
is detected at the first tick after it, so it lands in `[0, 250 ms]` — the ten `kill` and ten
`wrong` trials fall on {50, 100, 150, 200, 250} ms, which is the 100 ms sweep taken modulo the
250 ms tick, and the two cases are indistinguishable from each other, as they should be. A miss is
lost when `now − last > M·P`, so the wall time from the failure is `M·P − A + G` with
`A ∈ [0, P)` the age of the last pulse and `G ∈ [0, P/4]` the tick: `[(M−1)·P, M·P + P/4]`, which
for M=3, P=1 s is **[2.000, 3.250] s** against a measured [2.101, 3.251] s.

**Why 1 s × 3, in the order it actually decided.** Cost decides nothing — 0.026 % of a core on the
receiving side — and must not be argued as though it did. Measured jitter would justify **two**
misses: the worst lateness over a minute was 2.865 ms and the worst single send 14.8 ms out of ten
thousand, and two misses already leave 2 s of margin, seven hundred times the worst thing measured.
The third miss is bought by what a 60-tick sample does not contain — a guest paused for live
migration, a sentry stalled, a second of scheduler starvation — and by what a false positive costs,
which `docs/policy-push.md` prices exactly: **a refusal is not cached**, so the tunnel goes, the
handshake is burned, and the delegator's caller is told it was refused. The alternatives, applying
the same model: 0.5 s × 3 gives [1.00, 1.625] s for twice the wakeups; 1 s × 2 gives [1.00, 2.25] s
for nothing and spends a third of the margin. And the exposure being bought down is unbounded
today — ticket 23 measured it as "the tunnel is still up", with no end at all — so [2.1, 3.3] s is
not a compromise against zero, it is a bound against infinity.

**The teardown is bimodal by design, and the case the ticket was written for is the fast one.** A
workload that exits ends its sandbox's client, which closes the attachment, which is a **≤250 ms**
loss. The 2.1–3.3 s path is a sandbox that goes quiet *without* going away. Anyone reading a single
teardown number off a console is reading one sample from a one-second-wide uniform distribution,
and this record quotes the interval for that reason.

### The ordering defect, found by the adapter check and fixed

The first run of the adapter check lost the watch on the *new* policy after 250 ms, naming the
digest of the policy that had just been **replaced**. The cause is an ordering one and it is not
subtle once seen: `Host.Apply` returns as soon as the acknowledgement arrives, tunneld starts
watching immediately (`push.go:207`, `:223`), and the last thing the host had heard from the
sandbox was the previous policy's digest — so a ticker whose first tick is a second away leaves a
one-second window in which every watch is a mismatch. **On a real tunneld that is every tunnel torn
down on every narrowing.**

The fix is in the helper (`runsc/cmd/tunnel_helper.go:213-235`, `policyApplier.live`): the first
`alive` for a new digest is sent **synchronously, before `apply` returns and so before the
acknowledgement it answers**, and the socket delivers them in that order. The transcript in
`adapter-check/output-01-adapter-check.txt` is the run after the fix, and the window is gone: the
watch on P1's digest lived 12.251 s and ended as a close, 0.2 s after the workload was killed.

### The multiplexing consequence

The rule tunneld enforces is sandbox-agnostic: after a successful `Apply` on a tunnel with digest
`D`, the tunneld that applied it watches its sandbox and closes *that tunnel* if the sandbox stops
pulsing `D`, pulses something else, or closes. It does not parse `n`, `f` or `x`, so it **cannot
tell a narrowing from a different policy** — it compares digests. `Host.Watch`'s own comment says
the same thing from the other end: two peers that pushed two different policies to one sandbox
produce two watches and at most one of them can match, which is the honest answer to a question the
contract never promised — one sandbox enforces one policy.

So a **second pusher's narrowing is a mismatch to the first pusher**, and its tunnel goes. That is
correct behaviour rather than a defect, and it is the reason the hardware scenario narrows **only
from B**: A's long fetch rides the tunnel A dialled, which B watches against B's sandbox's digest,
and B's sandbox is never narrowed — so narrowing A leaves A's stream alone, which is the property
under test, while narrowing B would have torn down the tunnel carrying A's fetch and the run would
have proved the opposite of what it set out to
(`docs/snp/evidence/ticket26/snp/config/README.md`, *Why only guest B narrows*). The mirror-image
files are shipped anyway, set to a value that starts nothing, so either side can be the narrowed
one by changing one number.

## The loopback transcript

**Four sandboxes, one after another, and the whole difference between them is a document a third
tunneld pushed.** `attest/cmd/agent-probe/governed_test.go:113` `TestGovernedLoopback`, run on the
workstation on 2026-09-18 and recorded in `docs/snp/evidence/ticket26/loopback/` — `notes.md`,
`rq5-loopback.md`, and the run these numbers are taken from, `20260918-160939/`. Everything around
the sandbox is ticket 25's loopback world unchanged: the rootfs, the bundle, the tunnelds `a` and
`b`, ticket 23's exit, the capture and the key handling. What is added is a third tunneld, `root`,
which dials `a` and whose whole purpose is the document it carries, so that the policy reaches the
sentry **over a tunnel and through the contract** and not through a flag:

```
root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry: Policy.Narrow
                     │
                     └──tunnel──▶ tunneld b ──▶ the exit ──▶ the real network
```

The workload is `agent-probe -network plain -task summarize -dir /tmp`, built `CGO_ENABLED=0`: no
contract, no dialer of its own, Go's own resolver, and **nothing in it knows a policy exists**. The
model is `claude-sonnet-5` and the task is ticket 23's and ticket 25's, byte-identical. The boot
table names `api.anthropic.com:443` and `www.rfc-editor.org:443` in all four runs, and the runsc is
this branch's own `-c opt` build, sha256 `6019cbf4…7819` — the binary E1, E2 and the adapter check
answered. The tunnelds are goroutines in the test's own process over the fake SNP platform, so
**nothing here is evidence about attestation** and the cold `Open` below is a QUIC handshake plus a
fixture's arithmetic.

Three documents, and which of them is pushed is the experiment:

| what | sha256 | bytes |
|---|---|---:|
| P0, the whole table | `db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7` | 199 |
| the control's, P0 without the model endpoint | `8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b` | 156 |
| P1, P0 without the document host | `36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d` | 155 |

```
P0 = {"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]},
      {"host":"www.rfc-editor.org","ports":[443]}],"f":[{"path":"./summary.txt","modes":["w"]}],
      "x":[{"path":"/agent-probe"}]}
```

| run | pushed | the harness's `TIMING`, from `runsc` starting | runsc | what the agent did | cost |
|---|---|---|---:|---|---:|
| on-policy | P0 | `tunnel_open=552ms first_connect=566ms first_byte=599ms task_end=9.813s` | 0 | fetched the RFC, wrote `summary.txt`, said `DONE`; three requests, `input_tokens=14954 output_tokens=527`, 9.296 s | **$0.035178** |
| off-policy | the control's | `tunnel_open=never first_connect=never first_byte=never task_end=500ms` | 1 | died on its first model request | **nothing** |
| narrowed | P0, then P1, then P0 again | `tunnel_open=1.519s first_connect=1.53s first_byte=1.574s task_end=17.97s` | 0 | four refused fetches, then a summary from its own knowledge and `DONE`; five requests, `input_tokens=5962 output_tokens=1064`, 16.46 s | **$0.022564** |
| killed | P0 | `tunnel_open=391ms first_connect=404ms first_byte=424ms task_end=515ms` | 137 | killed 393 ms in, with a model request in flight | none to report |

`tunnel_open` is the exit accepting the first stream, `first_connect` the exit answering `OK` to the
`CONNECT` on it, `first_byte` the destination's first byte back down it and `task_end` `runsc`
exiting (`attest/cmd/agent-probe/adapter_test.go:822`); three of the four are read at the exit,
because that is the only place in this arrangement where the harness and the bytes meet.

**(a) on-policy — the task completes under the policy.**

```
PUSH root-on sha256=db453844…fdd7 cold_open=114ms apply=56.883ms tries=2 err=<nil>
SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe…fdd7
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe…fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 740.203µs, of which the table swap was 87.861µs
```

Both destinations were reached over the tunnel — the exit dialled `api.anthropic.com:443 ->
160.79.104.10:443` and `www.rfc-editor.org:443 -> 104.18.21.81:443`, and saw host, port and
ciphertext and nothing else — and the seccheck receiver printed its connect and its disconnect with
nothing between them, because nothing was refused.

**(b) off-policy — the refusal is the push and not the table.** The table carries both names; the
document leaves the model's endpoint out.

```
tunnel narrow: api.anthropic.com:443 at 100.64.1.0 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: applied in 2.695648ms, of which the table swap was 511.873µs
tunnel dns: q="api.anthropic.com" type=A answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
```

and the agent, whose first act is a model request, said this on stderr and nothing else — verbatim:

```
agent-probe: request 1: Post "https://api.anthropic.com/v1/messages": dial tcp:
  lookup api.anthropic.com on 127.0.0.53:53: no such host
```

with two `egress_refused protocol=dns name=api.anthropic.com reason=unknown-name` events, at
`20:09:02.400578637Z` and `20:09:02.406124663Z`, because the resolver asks `A` and `AAAA`. No stream
reached the exit, nothing was sent to the model and **this run cost nothing**. The refusal landed at
the **resolver** — `NXDOMAIN`, which Go reports as `no such host` — and not at the connect, so no
`connect` failed and there is no `ENETUNREACH` anywhere in this run: the finding ticket 25 recorded
for the table, now true of a policy.

**(c) a narrowing while the task is running.**

```
1.519s   the exit accepts the stream of the first model request
2.188s   root  pushes P0     acknowledged, applied in 894.404µs, swap 106.309µs
2.254s   root2 pushes P1     acknowledged, applied in 589.709µs, swap 137.646µs
         tunnel narrow: www.rfc-editor.org:443 at 100.64.1.1 is gone
         tunnel narrow: 1 of 2 names kept
2.292s   root3 pushes P0 again    REFUSED
```

The narrowing landed **735 ms after the exit accepted the first stream**, and the document host had
not been dialled when it did. What the agent — which knows none of this is there — did with that:

```
request 1: fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt -> 127 bytes, is_error=true
request 2: fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt -> 127 bytes, is_error=true
request 3: fetch_url https://www.ietf.org/rfc/rfc8446.txt       -> 115 bytes, is_error=true
           fetch_url http://www.rfc-editor.org/rfc/rfc8446.txt  -> 126 bytes, is_error=true
request 4: write_file summary.txt -> 31 bytes, is_error=false
request 5: stop_reason=end_turn        final text: DONE
```

It retried the same URL, then tried a **different host**, then the same host over plain HTTP, and
when all four were refused it wrote a summary of RFC 8446 from its own knowledge and reported
`DONE`. From outside, the run looks like a task that succeeded: runsc exited 0 and the last word is
the one the prompt asked for. That is ticket 23's *a denied tool is not a failed task*, reproduced
with the enforcement below the runtime rather than inside it, and it is this ticket's strongest
argument for why a transcript is not evidence and the sentry's log is.

The sentry refused all four by name — six `egress_refused` for `www.rfc-editor.org` and two for
`www.ietf.org`, every one of them `reason=unknown-name`. **`www.ietf.org` was refused by the boot
table, which never carried it, and `www.rfc-editor.org` by the policy, which removed it. The event
does not say which, and nothing in it could**: both names are absent from the table in force, the
responder has one reason for that, and an operator who wants the distinction has to hold the boot
table and the document beside the log.

**The words the agent was given are a reconstruction, and the lengths pin them.** `agent-probe`
prints a tool result's length and not its bytes, so the three numbers above are all the transcript
holds. The result is `"fetch_url: " + err.Error()` (`attest/cmd/agent-probe/agent.go:403`), and

```
fetch_url: Get "https://www.rfc-editor.org/rfc/rfc8446.txt": dial tcp: lookup
  www.rfc-editor.org on 127.0.0.53:53: no such host
```

is exactly 127 bytes, the `https://www.ietf.org/…` form 115 and the `http://` form 126 — the three
lengths the transcript records, and the wording is the one run (b) printed verbatim for its own
name. It is a **reconstruction**, and the record says so: no file in this directory holds those
bytes.

**The first peer's tunnel goes, and the workload does not.** 185 ms after the narrowing was
acknowledged:

```
SANDBOX liveness lost: it pulsed 36cce26e…c37d, expected db453844…fdd7
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at
  127.0.0.1:41414 pushed a policy this sandbox no longer enforces: it pulsed 36cce26e…c37d,
  expected db453844…fdd7
```

That is the eleventh reason reached by a **digest mismatch** rather than by a silence, on a sandbox
that was alive and working throughout: runsc exited 0 after 17.97 s, having started one process and
finished the same one. 185 ms is inside the bound the design gives it, one quarter of a pulse.

**The widening is refused, and the sentence that names the component stays in the guest.** `a`'s own
log:

```
… pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it:
  policy refused: it widens n by [net:www.rfc-editor.org:443]
```

What the third peer is told is `attest: verification failed`, and its own refusal log reads `"a" at
127.0.0.1:49791 did not apply the policy pushed to it: the peer refused it: the sandbox beside this
tunneld did not apply it`. That last clause is one fixed sentence, `attest/tunneld/push.go:93`
`ackRefused`, and it is all that crosses the tunnel: which of its own reasons a guest refused for is
a fact about that guest. **So a peer cannot tell a widening from a sandbox that was not ready yet** —
which is the window, below, seen from the other side.

**(d) liveness, twice, both by the fast path.**

| how the workload ended | runsc exited | the loss | the tunnel | what the loss said |
|---|---|---:|---:|---|
| the task finished (run a) | 16:09:14.376 | **+50 ms** | **+50 ms** | `the sandbox closed its socket` |
| `runsc kill … KILL` mid-task | 16:09:37.226 | **+33 ms** | **+33 ms** | `the sandbox closed its socket` |

Both are the fast case the design names: the workload ends, the sentry goes, the helper's fd-3 link
ends, the helper closes its tunneld client, the attachment goes, and the next quarter-pulse reports
it. `runsc kill … KILL` was sent 393 ms into the killed run, 2 ms after the exit had accepted its
first stream (`tunnel_open=391ms`) and with the first model request in flight; runsc exited 137
after 515 ms and that request was never answered, so the run has no cost to report. With
(c)'s mismatch at 185 ms, the three bracket the 250 ms granularity from both ends. Nothing here
waited three seconds, because nothing here went quiet — that case is E3's.

### What a push cost, and the window before it

| run | handshakes | cold `Open` | `Apply` at `a` | `Policy.Narrow` | the table swap |
|---|---:|---:|---:|---:|---:|
| off-policy | 3 | 75 ms | 38.723 ms | 2.696 ms | 511.9 µs |
| on-policy | 2 | 114 ms | 56.883 ms | 740.2 µs | 87.9 µs |
| narrowed, P0 | 1 | 51 ms | 3.901 ms | 894.4 µs | 106.3 µs |
| narrowed, P1 | 1 | 66 ms | 3.285 ms | 589.7 µs | 137.6 µs |
| narrowed, P0 again | 1 | 38 ms | 2.014 ms | refused | — |
| killed | 3 | 70 ms | 41.824 ms | 2.314 ms | 142.4 µs |

**`Apply` is bimodal, and a table that quotes one number is quoting whichever mode it sampled.** The
nine pushes these two loopback directories made — six here and three in E4 — split cleanly and
without an intermediate value: **35.2–65.7 ms** for the six that took more than one handshake,
**2.0–3.9 ms** for the three that took a single one. `rq5-loopback.md` reads the split as the first
dial of the sentry's control socket, which the helper makes per apply and never at startup, and E1
saw the same shape — one 42.656 ms sample in twenty-four and it was a run's first — and the adapter
check a third time, 25.2 ms against 4.2 ms. The `narrowed` run is the case that does not fit that
reading: its *first* push cost 3.901 ms, after the helper had been attached for a second. So what
these two modes track is a push that raced the sandbox's first milliseconds against one that arrived
after it had settled, and **the cold mode is the one hardware will show**, because a guest there gets
one push. The sentry's own half is the small half either way: `Policy.Narrow` is 0.59–2.70 ms and the
swap inside it 88–512 µs, against 38 ms at the boundary. The price of installing `P` is the price of
the process boundary it crosses.

**The window.** A policy cannot be applied to a loader that has not started its workload
(`runsc/boot/policy.go:106`, *the sandbox is … and a policy is honoured only by a started one*), and
a push made before that is refused — and **takes its tunnel with it**, because a refusal after
admission ends the connection it arrived on, so a retry is a fresh handshake. A sandbox becomes
ready in **four** steps and a push can arrive between any two of them: the helper is not on the
contract socket yet; the sentry's control socket does not exist yet; it exists and nobody is serving
it yet; the loader has it and has not started the workload
(`attest/cmd/agent-probe/governed_test.go:876-887`). The harness therefore pushes back to back until
one lands, and records what it burned:

| run | the workload started | the policy landed | the window | the workload's first query |
|---|---|---|---:|---|
| off-policy | 16:09:02.281193 | 16:09:02.284043 | **3 ms** | 119 ms after it started, 116 ms after the policy |
| on-policy | 16:09:04.924477 | 16:09:04.925405 | **1 ms** | 129 ms after it started, 128 ms after the policy |
| narrowed | 16:09:17.721578 | 16:09:18.774680 | **1.053 s** | 365 ms after it started, 688 ms *before* the policy |
| killed | 16:09:37.003528 | 16:09:37.005876 | **2 ms** | 91 ms after it started, 89 ms after the policy |

**This is a finding and not a harness artefact.** Three of the four closed the window in one to
three milliseconds; the fourth took a second, on the same machine with the same code, because the
helper took a second to attach — and in that run the workload's first query was answered under the
boot table alone. There is no way to be in front of it: the workload starts when the sentry starts
it, and there is no verb in this design that says *start the workload under this policy*. What
governs until the push lands is `--tunnel-table`, the ceiling every push narrows, so the guarantee
this arrangement actually offers is **"no wider than the boot table from the first instruction, and
no wider than `P` from the moment `P` lands"** — and this record says that rather than "the workload
ran under `P`".

**`x` was enforced on nothing in these four runs.** `P0`'s `x` names `/agent-probe`, the workload's
own path; the sentry execs the first process itself, before any policy can land, and `agent-probe`
execs nothing afterwards — every run's strace digest lists one process and an empty `## every
execve`. The `x` was parsed, subset-checked and carried in the digest the peer watches, the sink it
installed was installed, and the sink never saw a call. X is exercised in the adapter check and
measured in E2; it is not exercised here and this section must not read as though it were. `f` is
what it is everywhere else: tracked, and enforced by the mounts the bundle already had.

## What Claude Code did under a policy (E4)

**This is the definition of done's governed run, and it is three runs.**
`attest/cmd/agent-probe/governed_test.go:502` `TestClaudeGoverned`, recorded in
`docs/snp/evidence/ticket26/spikes/E4/` (`notes.md`, `20260918-161409/`): three governed runs and
one unrestricted, in that order, on the same afternoon, against the same binary in the same rootfs
behind the same exit — there is no separate `claude-governed/` directory and these three are it. The
workload is Claude Code **2.1.276**, the ELF ticket 25's smoke ran, invoked
`claude -p "Reply with exactly the word OK." --output-format json --model claude-haiku-4-5-20251001`.
The table is ticket 25's E4 host list unchanged — `api.anthropic.com:443` **and**
`http-intake.logs.us5.datadoghq.com:443` — in all four runs, so **the push is the only difference**:

```
{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[],"x":[]}
```

94 bytes, sha256 `b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d`. What it takes
away is the log intake the CLI contacts on a fresh `HOME` with nobody opting in — a destination a
table built from `agent-probe` alone would never have known to name. `f` and `x` are empty, so exec
stays unconstrained; whether `{path | sha256}` can name what this runtime execs is E2's question and
not this one.

| run | policy | result | `is_error` | turns | cost | wall | of it API | runsc | streams at the exit | intake dialled |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| governed-1 | pushed | `OK` | false | 1 | $0.003206 | 8.973 s | 2210 ms | 0 | 8 | no |
| governed-2 | pushed | `OK` | false | 1 | $0.003286 | 9.014 s | 2653 ms | 0 | 8 | no |
| governed-3 | pushed | `OK` | false | 1 | $0.003201 | 8.359 s | 2302 ms | 0 | 8 | no |
| unrestricted | none | `OK` | false | 1 | $0.003236 | 8.767 s | 2462 ms | 0 | **9** | yes |

$0.012931 for the four as the CLI reported it. The model is the same one in all four — the result
JSON's `modelUsage` names `claude-haiku-4-5-20251001`, `canonicalModel` `claude-haiku-4-5` — and the
governed runs are *inside* the unrestricted run's wall time rather than beside it: 8.359–9.014 s
against 8.767 s. **The task completed four times out of four**, because the destination that was
taken away was not one the task needed. That is not enforcement being weak: it is *task outcome not
being a channel for policy*, and an operator who wants to know whether a policy bit has ever
mattered must read the sentry and not the agent.

**Every refusal, and there are exactly two per governed run.** Verbatim, from governed-1 — the
sentry's own line and the event it wrote:

```
16:13:34.427993  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
16:13:34.429911  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

```
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name
  time=2026-09-18T20:13:34.428068546Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name
  time=2026-09-18T20:13:34.429986404Z
```

governed-2 said the same two at `16:13:45.635470` and `16:13:45.636657`, governed-3 at
`16:13:56.215048` and `16:13:56.216281`, each with its own pair of events; the unrestricted run's
sink printed its connect and its disconnect and nothing between. Twice for one name because glibc's
resolver asks `A` and `AAAA`. The name tallies are the rest of it: `api.anthropic.com` asked **8**
times and answered `100.64.1.0` in all four runs, `http-intake.logs.us5.datadoghq.com` asked **2**
times and answered **`nxdomain`** in the three governed runs and `100.64.1.1` in the fourth. The CLI
made **one** attempt at the intake and did not retry it, logged nothing about it on stdout, and the
result JSON does not mention it.

**There is no errno.** The ticket asked for every refusal *with its errno*, and the honest answer is
that this refusal has none: a name the policy in force does not carry is answered `NXDOMAIN` by the
responder inside the sentry, and glibc turns that into `EAI_NONAME` out of `getaddrinfo` — **a
library result and not a failed system call**. No `connect` is attempted, so the `ENETUNREACH` this
design gives an off-policy *address* never happens; that errno appears only when a workload dials a
synthetic address it resolved before a narrowing (E1 §2, `reason=not-in-table`), and a program that
resolves at the moment it dials never sees one.

**Distinguishable from the outside?** In the notes' own terms: **not** from the task's result, its
`is_error`, its turn count, its cost, `runsc`'s exit status or its wall time. **Not at all from
inside the guest** by anything a syscall trace can see — the `## syscalls that failed` tallies of
governed-1 and the unrestricted run differ in six rows and all six are scheduler noise (futex
wakeups, two `openat`s, two non-blocking `recvfrom`s); not one network syscall differs; neither run
has a failed `sendto` or a failed `socket`; and the only failed `connect` in either is the same pair
of `connect errno=2 (no such file or directory)` on an `AF_UNIX` path that is not there, present
identically in both. **Weakly at the exit**: one stream fewer, 8 against 9, which an observer would
have to know to expect. **Exactly at the sentry**: two events that say which protocol, which name
and which reason. That cuts both ways and both halves belong here. It is a good property — a policy
that silently removes a destination hands the workload no fingerprint of what is being enforced on
it, which is the shape a workload that wanted to detect and adapt would need. And it is a warning —
nothing in the task's own output will ever tell an operator that a policy bit fired, so **the
seccheck sink is not a debugging convenience, it is the only channel**.

The three pushes cost what the loopback pushes cost in their cold mode: 3, 3 and 4 handshakes, cold
`Open` 99 / 123 / 78 ms, `Apply` at `a` 52.443 / 65.721 / 35.231 ms, `Policy.Narrow` 2.052 / 0.824 /
1.323 ms, the table swap 884.8 / 201.9 / 530.8 µs, landing 349, 384 and 403 ms into their runs —
about two seconds before each run's first stream reached the exit at 2.397–2.64 s, and longer before
the intake was ever asked for. The cold `Open` is a QUIC handshake against the fake platform with a
fixture verifier and **is not an attestation cost**.

**What runs inside it.** E2's `d-claude` run, which spent nothing and reached nothing, found that
the Claude Code build in use is a **single self-contained ELF**, and that one run exec'd exactly two
distinct identities — `/usr/local/bin/claude` five times (the CLI re-execs itself) and
`/usr/bin/git` three times — both stable across the re-execs. **There is no Node**, so an `x` for it
is two entries and not a list of interpreters. That run also produced four `egress_refused
protocol=dns name=api.anthropic.com reason=unknown-name` pairs, which is the adapter refusing the
one name a policy would have to grant. E4's governed-1, doing real work, shows the same two paths
and what the re-execs are for: four `execve`s of `/usr/bin/git` and three of `/usr/local/bin/claude`
with `argv[0]` set to `rg` — the ripgrep the CLI ships inside itself. Which is the identity rule and
the argument limit in one line: `rg --no-config --files --hidden /work` is `/usr/local/bin/claude`
to the sink, and an `x` that names that path grants every one of them.

## The SNP transcript

<!-- PLACEHOLDER: filled from docs/snp/evidence/ticket26/snp/ when the run lands; the bundle, the two config devices and the runbook are already committed -->

## The TDX transcripts

<!-- PLACEHOLDER: filled from docs/snp/evidence/ticket26/tdx/ when the two-guest run lands: the task agent to agent, the off-policy control, the narrowing mid-run, the liveness teardown, both consoles and both quotes -->

What is decided now is the reference value set the run needs. The sets this project authors for
Google Cloud TDX admit **two** RTMR0 values instead of one: `c2fc12a5…850a` for the two-disk shape
(ticket 19) and `8ee4fa36…b70a3f` for the **three-disk** shape this ticket's proof requires — a
boot disk, a config disk and a workload disk, all present at instance creation. Ticket 24 observed
that value twice and authored it nowhere; this ticket authors it, in
`docs/snp/cloud/tdx/build-tdx-image.sh` and `emit-tdx-documents.sh`, with the reasoning and the
counter-arguments in `docs/snp/evidence/ticket26/tdx/RTMR0-DECISION.md`. The third disk stays
because the workload bundle has to live on a mount that is read-only **and** exec-permitted and it
is the only such mount in the guest; putting the bundle in the initrd would put it inside the
measurement, which is the opposite of the claim this design rests on. Nothing about ADR-0004's rule
is bent: no script reads a measurement off a quote or a console into a reference value, and the
number was typed by an author who read two recorded transcripts and decided which guests this
project admits.

## What a hop costs, and the six RQ5 components

<!-- PLACEHOLDER: the hardware column is filled from the SNP and TDX runs; the loopback column is `docs/snp/evidence/ticket26/loopback/rq5-loopback.md`, and the method column is what this ticket already knows -->

The six components as `evaluation.tex:764-771` names them
(`.scratch/attested-secure-tunnel/paper-vs-design-27sec.md:212`), with the method for each:

| component | method | loopback | on hardware |
|---|---|---|---|
| guest execution overhead | the measured init's own clock, sandbox start to workload exit, beside E2's `fork`+`execve`+`wait4` benchmark for the per-exec share the X sink adds | **nothing, and it must stay nothing**: `runsc --platform=systrap` on the workstation with the tunnelds in the test's own process, so a number here would be this host's scheduler | — |
| attestation acquisition | the guest's own console line for evidence acquired from the platform, one per guest per boot | **nothing**: `fixture.SNPPlatform` over `internal/snpfake`, no report requested of any hardware | — |
| attestation verification | the verifier's judgement of the peer's quote, counted per verifier call so that cold and warm are separated by the count rather than by a clock | **nothing**: `fixture.VerifierTrusting`, no VCEK fetched, no chain walked, no collateral consulted | — |
| establishment of the attested channel | first `Attach`, cold, against a later `Attach` on a tunnel that already exists | a pusher's cold `Open` — dial, both verdicts, the push and its ack in one call — **38–123 ms, median 75 ms** over 9; the *shape* of establishment and **not its price**, to be replaced by the hardware number and not adjusted by it | — |
| installation and binding of `P` | the three clocks E1 already reads: the table swap, the whole of `Policy.Narrow` in the sentry, and `Host.Apply` end to end | the nine governed pushes: `Host.Apply` **2.014–65.721 ms**, median 38.7 ms (bimodal, see above); `Policy.Narrow` **589.7 µs–2.696 ms**, median 1.109 ms over 8; the swap alone **87.9–884.8 µs**, median 172.2 µs over 8 | — |
| capability release | E3's ten teardown trials per case, which is what release costs when it is not asked for; a narrowing that removes a name is the asked-for form and E1 times it | E3's bounds ≤250 ms (close or mismatch) and 2.10–3.25 s (three misses), met by the governed runs' own two closes at **33 and 50 ms** and one mismatch at **185 ms**; `rq5-loopback.md` also reads the row the other way round, as release when it *is* asked for — the helper's first attach 130 ms–2.138 s (median 165 ms over 7), the exit's accept→`OK` 11–14 ms, `OK`→first byte 17–44 ms | — |

**What is already separated and what is not.** Ticket 25 recorded two of the six and only as a lump
— nothing separated the QUIC handshake from the quote verification — and the distinction this
ticket adds is the fifth row, which was not measurable at all before a policy could be installed in
a running sandbox.

**What the hardware runs must add, and must not take from here.** Rows 1, 2 and 3 in full: loopback
leaves them empty on purpose, because there is no measured guest and no attestation in it and a
number taken here would be a number about the absence of the thing being measured. Row 4 is
**replaced** and not adjusted — a real `Open` acquires a real report and verifies it against real
collateral, and shares nothing with the loopback figure but the order of its steps. Rows 5 and 6 are
worth comparing against: the sentry-side halves should be within noise of these, because the same
code does the same work whether or not the guest is measured, and if they are not, that difference
*is* guest execution overhead and is row 1 arriving by the back door
(`docs/snp/evidence/ticket26/loopback/rq5-loopback.md`).

## The ceiling and the model

The compiled-in egress ceiling permits **no TCP at all** out of a measured guest: the output chain
drops by default, accepts loopback, and then rejects every TCP packet with a reset — hoisted above
everything else, because the only accepts after it are UDP on port 4433
(`attest/ceiling/ceiling.nft:131-136`, embedded at `attest/ceiling/ceiling.go:86`). That is not an oversight to be worked around; it is the statement
that the only way out of the guest is the attested tunnel. It has one consequence this record owes
the reader in plain words: **a task that needs the model endpoint cannot run inside a measured
guest**, because reaching `api.anthropic.com:443` is a TCP connection the ceiling refuses before the
adapter is even consulted. So the model-backed task — Claude Code under a pushed policy, doing real
work and being refused real destinations — is proven on **loopback**, where there is no ceiling, and
the hardware task on two guests is the page fetch: one guest's sandbox fetching the other's page
through the tunnel, under a policy the other pushed. Both are real; neither is the other; and a
reader who wants "an agent calling a model from inside a confidential VM" should know that this
tree proves the enforcement and the tunnel separately from the model call, and that closing that
gap needs an exit outside the measurement that is permitted to speak TCP.

## What this ticket did not do

No change to the `(N, F, X)` bytes: the provisional `{format:"policy",version:1,n,f,x}` ticket 22
left is what is parsed, and **nothing is sent to the policy track** — what this ticket owes the
policy track is the paragraph below and nothing else. No path × {r,w,x} allow-set, and so no real
`F`: mounts approximate it and the record says so four times because it is the easiest claim in
this document to overstate. No `E` letter: the sentry reads `n`, `f` and `x` and ignores anything
else in the document, which is a narrowing and never a widening (`runsc/boot/policy.go:236-243`).
No revocation of an established stream. No change to the wire, the framing, the once-per-tunnel push
rule or the ordering guarantee; the contract gained one message and tunneld gained one watch and one
reason. No change to the agent programs. No restore path: a narrowed sandbox that is checkpointed
and restored is not something this ticket has anything to say about.

## Leftovers

The first two are E1's own, the next four E2's, the next three E3's, the next nine this record's,
and the last two the loopback proof's.

1. **`--root` has 108 bytes to spend, and a policy push is where you find out.** `Policy.Narrow` is
   delivered over the sentry's control socket, whose path is `--root` plus
   `runsc-<container id>.sock`; `pkg/unet.Connect` hands that straight to `connect(2)` in a
   `sockaddr_un`, which holds 108 bytes, so a deep `--root` or a long container id is `EINVAL` — and
   `EINVAL` from a `connect` is what the peer that pushed the policy is told. Not new in this ticket
   (every `runsc state` on such a sandbox fails the same way) and not fixed here; the harnesses use
   a short root under `/dev/shm`. **A deployment that puts `--root` somewhere deep silently loses
   the ability to narrow.**
2. **`busybox nslookup` costs about seven seconds per name through the responder**, against
   milliseconds for the `wget` that follows it on the same name. The responder answers `A` and
   `AAAA`; the delay is in what busybox does afterwards, most likely a reverse lookup the responder
   answers `NXDOMAIN`. Nothing in the design depends on `nslookup`. Not investigated.
3. **Installing X makes every `execve` visible to whatever remote sink is already configured**,
   argv and environment included, whether or not that session asked for the point. E2 §5.
4. **An `x` that names an interpreter does not grant the scripts it runs.** Every directly-executed
   script needs its own entry, by path or by digest. E2 §3b.
5. **A digest entry matches contents and not names**, so a copy of a permitted binary at a new path
   is permitted, and a different binary at a permitted path is not. Both halves are deliberate and
   both surprise.
6. **The execve hash cache holds 512 entries**, so a workload with more than 512 distinct
   executables would start evicting and paying a hash per exec. Nothing measured came near it.
7. **The loss is found by polling, at a quarter of a pulse.** A closed socket and a mismatched
   digest are known the instant they arrive and are rounded up to the watch's 250 ms tick. Waking
   the watcher on each pulse would make both sub-millisecond; it is one loop against a fan-out from
   every attachment to every watch, and 250 ms is already an order of magnitude inside the miss
   path.
8. **Liveness is a heartbeat and not a proof.** An `alive` says what the sandbox says it is
   enforcing. It is trusted for arriving on a socket inside a measured guest, exactly as a pushed
   policy is trusted for arriving over an attested tunnel; a sandbox lying about its digest is a
   sandbox lying about its own enforcement, which the measurement and not the contract is what
   stands behind.
9. **Every number in E3 was taken at load average 24.** They are upper bounds, and the constants do
   not depend on a quiet host.
10. **`f` is enforced by nothing.** Parsed, subset-checked, carried in the digest, enforced by the
    mounts the bundle already had. The seam map says the only place to add a real allow-set is
    `VirtualFilesystem.OpenAt`.
11. **`locked` cannot be asked for from a bundle**: not an option `ParseMountOptions` knows, and
    `vfs.MountOptions.Locked` is set in one place in this tree, for the namespace-root tmpfs.
12. **There is no revocation.** A narrowing decides what may be opened next; a stream already open
    runs to its end, and a policy pushed to stop an exfiltration in progress would not stop it.
13. **The exec sink, once installed, is never removed**, because seccheck's only way of taking a
    sink back takes every sink back — including the remote one the refusal events go to. A policy
    that narrows `x` to the empty set is therefore a sandbox in which no further `execve` can ever
    succeed.
14. **The shared check in `attest/sandbox` has no production caller.** `Atoms`, `Widening` and
    `CheckNarrows` are exercised by tests; the enforcing implementations are the sentry's mirror and
    Deno's own atomiser. The four documents on which the two read differently are tabulated in *The
    subset check*, above, and none of them is reconciled.
15. **A second pusher's narrowing is a mismatch to the first pusher**, and closes that tunnel.
    Tunneld compares digests and cannot tell a narrowing from a different policy without parsing
    `n`, `f` and `x`, which is exactly what it is built not to do.
16. **`attest/sandbox/live.go:47-48` understates E3.** It says the send was measured at "well under
    ten microseconds"; E3 measured a p50 of 17.015 µs and a mean of 30.174 µs, and only the minimum
    was under ten. `docs/sandbox-contract.md` carries the right number. The comment, not the
    constant, is what is wrong.
17. **`--debug` is how every number in the spikes was read**, and it is not free. E1's and E2's
    sandboxes ran with it; a production sandbox would not, and the swap and decision costs would be
    the same or smaller.
18. **Nothing here is evidence about tunneld.** E1, E2 and the adapter check all run against a
    stand-in that speaks `attest/sandbox`'s socket and has no tunnel, no QUIC and no attestation in
    it. What is evidence about tunneld is the hardware transcripts.
19. **The helper's first attach varies by a factor of sixteen, and nothing explains it.** From
    `runsc` starting to the helper being on the contract socket was 130–201 ms in six of the seven
    loopback runs that measured it and **2.138 s** in the seventh, on the same machine with the same
    code. Nothing in the design depends on it being fast — a one-second pulse tolerates it and did —
    but it is what sets the width of the window below it, and the run that took a second is the run
    whose workload made its first query under the boot table alone.
20. **A policy cannot govern a workload's first instructions.** `Policy.Narrow` is refused until the
    loader has started the workload, a sandbox becomes ready for a policy in four steps, and a push
    that arrives between any two of them is refused *and takes its tunnel with it*, so a peer that
    wants to govern from the first instruction retries and burns a handshake each time — two to four
    of them in six of the nine governed pushes. The windows measured were 3 ms, 1 ms, 1.053 s
    and 2 ms. The honest statement of what the arrangement gives is **"no wider than the boot table
    from the first instruction, and no wider than `P` from the moment `P` lands"**, and closing it
    would need a verb this design does not have: *start the workload under this policy*.

## What the policy side must deliver

This is a paragraph in this record and it is **sent nowhere**. Ticket 23 found four places where
`(N, F, X)` as typed is not enough (`docs/agent-on-the-contract.md:511-569`); this sandbox now
enforces three of the letters, so each of the four can be restated as a requirement on the format
this enforcer expects. **`n` must carry a name and the port must be mandatory.** A CIDR is refused
here as unenforceable, and refused for a reason about the format rather than about any one
implementation: every check raised on a destination is against the name that was asked for, at the
resolver or at the connect hook, and a name is in no CIDR. A bare host means every port and this
sandbox can only ever grant the one port its table carries, so it canonicalises — which works only
because the table exists; a format whose unit is `host:port` needs no such rescue, and the record of
ticket 25's `wrong-port` refusal is that distinction being made. One thing this enforcer answers
that ticket 23 could not: **the resolver is now inside the enforcer**, so the name→address binding
is allocated by the thing that enforces it and DNS pinning is not a separate problem. **`f` needs a
runtime baseline notion, which mounts approximate and do not supply.** The trust store, the
resolver's configuration files and the loader's libraries are the price of a workload starting
rather than of anything the workload's task is about; nobody writes them down, and this sandbox
supplies them as a read-only, noexec mount and lets `f` say nothing at all. Either the enforcer
supplies the baseline and the policy may not name it, or `F` needs a named set a policy can refer
to and narrow, distinct from the paths the task is about — and until one of those exists, `f` in a
document sent here is a claim nothing checks. **`x` needs identity, and identity has three parts
this sandbox has now measured.** A path resolves to the file: `/bin/uname` and `/bin/sh` are one
identity, `/bin/busybox`, so a path entry covers every applet symlink. A script is itself, not its
interpreter: a `#!` script is reported with its own digest, so an interpreter grant does not cover
the scripts it runs and every directly-executed script needs its own entry. A digest matches
contents and not names. And **arguments are still not part of it**, which is where the reach of an
exec actually lives — one granted `/bin/sh` is every command on the machine, and this sandbox
enforces `x` exactly as far as `execve`'s first argument and no further. **An `e` letter is still
missing and this sandbox ignores it.** The environment is the one resource unambiguously the
delegator's to grant; the format has no letter for it, and `runsc/boot/policy.go:236-243` reads `n`,
`f` and `x` and silently ignores everything else, which is safe (ignoring a grant is a narrowing)
and is not the same as enforcing it. If an `e` letter arrives, it has to mean *constructed* and not
*read-gated*. Two more things the format should keep: **the widening rule over sorted deduplicated
atoms**, which is what makes two orderings one policy and makes a refusal able to name what widened,
and **the fact that liveness belongs to the contract and not to `P`** — whatever `P` becomes, an
acknowledgement of it is a statement with a lifetime.

## Evidence

| what | where |
|---|---|
| E1, narrowing under traffic: 24 narrowings, a 16 MiB transfer that outlives the one under it, a removed name refused by name and at its old address | `docs/snp/evidence/ticket26/spikes/E1/` (`notes.md`, `run-e1.sh`, `e1-workload.sh`, `faketunneld/`, `output-01-narrowing-under-traffic.txt`) |
| E2, the exec sink's cost and reach: four runs, the identity findings, the firehose | `.../spikes/E2/` (`notes.md`, `run-e2.sh`, `e2-workload.sh`, `e2-script.sh`, `execbench/`, `output-01-cost-and-reach.txt`) |
| E3, what one `alive` per second costs and how long a teardown takes: 30 trials, the drift, the two alternatives | `.../spikes/E3/` (`notes.md`, `run.sh`, `e3_spike_test.go`, `output-00`–`output-03`) |
| the adapter check: one sandbox, three pushes, the seven obligations, and the ordering defect it found | `.../adapter-check/` (`notes.md`, `run-adapter-check.sh`, `check-workload.sh`, `faketunneld/`, `output-01-adapter-check.txt`) |
| the loopback proof: four sandboxes, an unmodified agent completing its task under a policy that crossed a tunnel, a narrowing mid-run, the widening refused, two teardowns, the window and the six RQ5 rows loopback can and cannot speak to | `.../loopback/` (`notes.md`, `rq5-loopback.md`, `run.sh`, `20260918-160939/` — the harness's own `README.md`, the untrimmed transcript, and one directory per sandbox) |
| E4, Claude Code under a pushed policy, which is the definition of done's governed run: three governed runs and one unrestricted, the two refusals each, and the strace tallies that cannot tell them apart | `.../spikes/E4/` (`notes.md`, `run.sh`, `20260918-161409/`) |
| the receiver the `egress_refused` and `exec_refused` lines come from | `.../tools/seccheck-receiver/` |
| the SNP bundle, the scenario's two config devices and the twelve files that are the whole difference between the two guests | `.../snp/RUNBOOK.md`, `.../snp/make-bundle.sh`, `.../snp/policy-probe.sh`, `.../snp/config/README.md`, `.../snp/config/{a,b}/` |
| the TDX runbook, and why the three-disk RTMR0 is authored rather than harvested | `.../tdx/RUNBOOK.md`, `.../tdx/RTMR0-DECISION.md` |
| the sentry's half | `runsc/boot/policy.go`, `pkg/sentry/policyx/policyx.go`, `pkg/sentry/socket/netstack/tunnel.go:266-314`, `tunnel_dns.go:105-140`, `pkg/sentry/kernel/task_exec.go:223-230,516-527`, `pkg/sentry/seccheck/execve_hash_cache.go` |
| the boot and helper halves | `runsc/boot/controller.go:155-157,254-257`, `runsc/boot/tunnel.go:57-82`, `runsc/cmd/tunnel_helper.go:126-262` |
| the contract's half | `attest/sandbox/live.go`, `host.go:120-260,310-380`, `client.go:195-262`, `policy.go:160-367`, `attest/tunneld/push.go:196-270`, `attest/refusal.go:111-141` |
| the two records this one continues | `docs/sandbox-contract.md` (version 3, *Liveness*), `docs/policy-push.md` (*PolicyNotLive, the eleventh*), `docs/the-adapter.md`, `docs/agent-on-the-contract.md` |
| the hardware transcripts | <!-- PLACEHOLDER: loopback/, claude-smoke/, snp/run*/ and tdx/run*/ rows, added when those runs land --> |

The unit tests are twelve in `runsc/boot/policy_test.go` (the parser and its sorting, a table of
refusals, the bare host canonicalised to the table's port and the one the table does not carry, the
boot table's atoms, the first push against the table and the second against the first, the
component a refusal names, the sink's two lists, the net atom's host and port, and
`TestFIsMountsOnly`), eight in
`attest/sandbox/policy_test.go` (the atoms, the refusals, the narrowing, the two components a
widening names, the atoms-not-documents form, the empty grant, and the grammar pinned against
Deno's), and the liveness tests named in `docs/sandbox-contract.md` — `attest/sandbox/socket_test.go`
for a sandbox in another process that pulses, is killed, goes quiet or pulses something else;
`attest/tunneld/liveness_test.go` for the tunnel that is closed when it does; and
`attest/cmd/agent-probe/liveness_test.go` for the agent's sandbox and the exit's, two clients on one
socket, both acknowledging and both pulsing.

<!-- PLACEHOLDER: the `ripwire attest --quality-delta=6dfa00a1d..HEAD` block, its gating/acked/stale counts, and the reasons the acked rows carry -->
