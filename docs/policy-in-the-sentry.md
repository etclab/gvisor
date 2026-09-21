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
`attest/refusal.go:123`). (5) The six RQ5 remote-cost components, answered on the workstation and
on both kinds of measured guest. Three spikes stand under it,
under `docs/snp/evidence/ticket26/spikes/`: **E1** (narrowing under traffic), **E2** (the exec
sink's cost and reach), **E3** (heartbeat cost and teardown timing), beside an **adapter check**
(`docs/snp/evidence/ticket26/adapter-check/`) that asserts all seven obligations of one sandbox at
once. **Tunneld's push path is ticket 22's and ticket 23's** — what this ticket adds to it is the
watch and one reason, and nothing about the wire, the ordering or the once-per-tunnel rule
changed. Work done 2026-09-18, base `6dfa00a1d`, **43 commits and tip `0404d9421` at the time of
writing**; every binary the hardware numbers were taken against was built at `3acfe11b5`, which is
the state the workstation sections were measured at too. The runs that fill the rest of this record
are five SEV-SNP boot pairs on the bench and three Intel TDX boot pairs on Google Cloud, all of them
on 2026-09-18 — the last TDX pair ended at **2026-09-18T23:59Z**, and the check that its ledger left
nothing behind was made at **2026-09-19T00:01Z**, which is 20:01 the same working day in
America/New_York. Nothing merged, nothing pushed.

**In one sentence:** apply-without-restart is real and is the whole reason this sandbox is gVisor
— a policy pushed over the contract replaces the sentry's table in a median of **0.18 ms** of swap
and **3.5 ms** of end-to-end wall time on the workstation, in **67–173 µs** of swap inside a
measured SEV-SNP guest and **11–20 µs** inside a measured TDX one, with a 16 MiB transfer in flight
on the workstation and an 8 MiB one on SEV-SNP hardware each delivering every one of its bytes —
but what a narrowing decides is what may be **opened next** and nothing else: a
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

**Ticket 27 changed two of those sentences**, and the record for it is
`docs/the-ack-means-the-sandbox.md`. A push now reaches only the client that attached as
`enforcing`, so the enforcing attachment is the one thing that must be live and the exit attaches as
`network` and is pushed nothing; and the watch belongs to that attachment rather than to the tunnel
the policy arrived on, so it outlives a tunnel that idled out and closes a tunnel only if one is
still open. Everything cited in this section is the line it was on when ticket 26 was recorded.

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
after it had settled, and **the cold mode is the one a measured guest would show**, because a guest
there gets one push — a prediction the hardware runs leave standing rather than confirm, since
neither vendor's console timestamps the round trip a push makes (`rq5-snp.md`, `rq5-tdx.md`, row 5).
The sentry's own half is the small half either way: `Policy.Narrow` is 0.59–2.70 ms and the
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
execve`. The `x` was parsed, subset-checked and carried in the digest the peer watches, and the exec
sink it installed never saw a call. X is exercised in the adapter check and
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

**Five boot pairs on the bench, and the record is the fourth: `=== 73 passed, 0 failed ===`.**
`docs/snp/evidence/ticket26/snp/run-4/`, 2026-09-18 — one measured image, two SEV-SNP guests booted
from it, one workload disk attached to both, and twelve unmeasured files on the two config devices
that are the whole difference between the guests (`.../snp/config/README.md`). The other four pairs
are kept as they stand in `run/`, `run-2/`, `run-3/` and `run-5/`, and **nothing under `pkg/`,
`runsc/` or `attest/` was touched between any of them**: every change is in the harness, in the
unmeasured config, or in `/sbin/init`.

```
launch measurement    5d73c959b5356dc63bf1ea4dd39562dee6679713c6fe87168bb75817defea9fde1c213863ea2d3beed28d9da4feb6dbc
                      predicted offline twice before either guest existed, and reported by both
verity root hash      4fe103f12515250a74ee88a8675d25543bbbd58135531262732176979034658e (21,916 data blocks)
runsc                 6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819, 109,044,910 bytes
tunneld               241fb424f1f3db04dfbd8688c993b7f2d0cf63baa2c3bc31bc11802388a027c6, 17,597,809 bytes
agent-probe           fc100aad383a0023079f64d2272585fe871e6539a7f87cd075233577dd22af6a, 9,214,897 bytes
/sbin/init            d6111b514656a4273bc54d31edde1288fb22465b94d5bd5fd5c29a074411e1db, 29,767 bytes
ceiling digest        197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973 (unchanged since ticket 22)
author public key     3f27c388b8c18afb53cce0214c3a9c7650290073d23ceffe09042c8d017dec72
workload disk         524087392626984847b6f97d6cf98a211adae654cc7e87d7fb3e5b698d8cfdf3 (not measured)
  /bin/busybox        dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14
  /bin/probe          75dfb7becbff66f9083b1fa955bef2d0c6de178a8892bbfaff82fa26515d00b9   the exec control
```

`6019cbf4…7819` is the runsc E1, E2, the adapter check and the loopback proof all answered, so the
workstation sections above and the two guests below are measurements of one build (`run-4/manifest.txt`,
which records it as `bazel-bin/runsc/runsc_/runsc at 3acfe11b5`). Four files differ from ticket 25's
image and **contract v3 is in all four of them**: runsc (**+87,604 B**), tunneld (**+23,828 B**),
`agent-probe` (**+10,087 B**, the client side of the `alive` message an attached sandbox now sends)
and `/sbin/init` (**+9,061 B**, the scenario). The kernel, the firmware, `/etc/hosts`,
`/srv/index.html` and every busybox applet are byte for byte ticket 25's.

**Which document governs whom.** A tunneld pushes the document on its own config device at *every
peer it dials*, so `a/push-policy.json` governs **B** and `b/push-policy.json` governs **A**. Three
documents, and the digests are what the consoles below are read by:

```
a/push-policy.json         {"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}
                           110 bytes, sha256 b23887d0…81268   -> guest A pushes it, guest B's sandbox enforces it
b/push-policy.json         the same with web.peer-b
                           110 bytes, sha256 681331c6…b785d   -> guest B pushes it, guest A's sandbox enforces it
b/push-policy-narrow.json  {"format":"policy","version":1,"n":[],"f":[],"x":[{"path":"/bin/busybox"}]}
                           76 bytes, sha256 92fb0e17…7248e    -> B pushes it at A 40 s in, from a second tunneld
```

### The five pairs

| pair | what changed since the one above | measurement | result |
|---|---|---|---|
| `run/` | — | `f8b60b78…ef31` | 69 passed, 4 failed |
| `run-2/` | tunnel idle timeout 60 s → 420 s (harness); the exec control asks once before anything else (workload script) | `f8b60b78…ef31` | 72 passed, 1 failed |
| `run-3/` | `kill_later` reads the whole process table before it signals, and prints it (`/sbin/init`) | `5dad2470…c5fb` | 68 passed, 5 failed |
| **`run-4/`** | `kill_later` matches **argv[0] out of `/proc/PID/cmdline`** and not `comm` (`/sbin/init`) | `5d73c959…6dbc` | **73 passed, 0 failed** |
| `run-5/` | the sentry's `tunnel narrow:` lines are picked out of the debug log onto the console (`/sbin/init`) | `1bc0c930…a1f2` | 71 passed, 2 failed |

**Four measurements across the five pairs**, and which is which is the boundary of the measurement
itself: pairs 1 and 2 share `f8b60b78…ef31`, because what pair 2 changed — the tunnel idle timeout
and the workload's script — lives on the harness and on the unmeasured workload disk. Every change to
`/sbin/init` is a new image and a new number, and all four were predicted offline before the pair
that reported them booted.

### The definition of done, in the two guests' own words

`A` and `B` are `run-4/policy/console-a.txt` and `console-b.txt`, and the number after the colon is
the line.

**The policy in force is the peer's, by digest.**

```
A:581  SANDBOX applied format=policy version=1 bytes=110 sha256=681331c69aedad34d51e9e1f325889ff81863885d1067055bf005ca9e33b785d
B:583  SANDBOX applied format=policy version=1 bytes=110 sha256=b23887d06a044f0752371ed8899c752ce0023a2aeaec56424e0cc3b747381268
```

Each console carries the digest of the document the **other** guest pushed, because a push is applied
by the tunneld beside the sandbox it governs. Both lines appear twice, at `A:582` and `B:584` with
tunneld's prefix — one line written to two sinks, and not two applications.

**The task, both ways, through the peer's exit.**

```
A:583  EXIT accepted a stream from peer="guest-b" vendor=amd-sev-snp measurement=5d73c959…6dbc policy_digest=197d4aae…b973
A:584  EXIT dialed web.peer-a:80 -> 127.0.0.1:80
A:602  served-by: guest-b
A:603  workload: wget exit 0 for http://web.peer-b/
B:599  served-by: guest-a
B:603  workload: wget exit 0 for http://web.peer-a/
```

Each guest's sandbox fetched the *other* guest's page, and each guest's exit served the peer while
dialling the one destination its `exit-allow` permits. The sentry's own account of the same two
fetches, out of the debug log init dumps at the end (`A:655`, `A:657`, `B:683`):

```
A  tunnel dns: q="web.peer-b" type=A answer=100.64.1.0
A  tunnel attach: web.peer-b:80 -> peer "guest-b": ok in 96.482342ms, host fd 41, local 100.64.0.1:40001
B  tunnel attach: web.peer-a:80 -> peer "guest-a": ok in 159.689431ms, host fd 41, local 100.64.0.1:40001
```

**The `N` control: a name in nobody's policy.**

```
A:605  workload: --- GET http://not-in-the-table.example/ (attempt 1)
A:607  wget: bad address 'not-in-the-table.example'
A:608  workload: wget exit 1 …: the name did not resolve, so this sandbox's policy does not carry it; not retrying
A:661  init: sentry: … tunnel_dns.go:203] tunnel dns: q="not-in-the-table.example" type=A answer=nxdomain
A:662  init: sentry: … tunnel dns: q="not-in-the-table.example" type=AAAA answer=nxdomain
```

Two events for one name, because busybox asks `A` and `AAAA`; `B:604-606` and `B:687-688` are the
same four lines on the other guest. **The refusal is the responder's**, one hop before any connect —
which is the loopback finding, unchanged on hardware.

**The `X` control, and it is a transition and not a constant.** The same execve ran a moment earlier,
under the boot table and before any `x` existed:

```
A:579  workload: exec /bin/probe attempt 0: it ran (rc=127); no policy carrying an x is in force in this sandbox yet
A:581  SANDBOX applied … sha256=681331c6…b785d
A:609  workload: EXEC REFUSED /bin/probe on attempt 1: /policy-probe.sh: line 150: /bin/probe: Permission denied
A:666  init: sentry: W0918 20:20:00.116893  1 policyx.go:228] exec refused: path="/bin/probe" sha256=75dfb7becbff66f9083b1fa955bef2d0c6de178a8892bbfaff82fa26515d00b9 reason=not-in-x
```

All four lines on both guests (`B:579`, `B:583`, `B:607`, `B:689`). `rc=127` is busybox declining to
be a `probe` applet, which is what "it ran" looks like; what the pair proves is that the errno changed
from *it ran* to `EACCES` across one push, and that the sentry names the identity it refused and the
reason. The loopback runs never exercised `x` at all, so this pair and the two TDX pairs below are the
only places in this record where **the transition itself** is on a console.

**The policy replaced, under a stream that was already open.**

```
B:654  init: narrow-after: 40s elapsed; starting a second tunneld to push /config/push-policy-narrow.json at the peer
A:620  SANDBOX applied format=policy version=1 bytes=76 sha256=92fb0e17644f61d44d0fa7c8ed10d2c5af5b9ccf75911a4d106463ba2967248e
A:628  workload: NARROWED web.peer-b stopped resolving on attempt 14: wget: bad address 'web.peer-b'
A:633  workload: LONG COMPLETE bytes=8388608 (the whole body arrived, and the stream outlived whatever happened to the policy under it)
B:616  workload: LONG-B bytes=8388608 expected=8388608
```

Guest A's console carries **two** applied digests and guest B's one, which is the whole of *replaced,
not restarted*: one sandbox, one workload process, a second policy. The eight mebibytes were being
read a chunk a second when the second document landed, and all 8,388,608 of them arrived — the
revocation that does not exist, on hardware. `B:616` is the same body read in one go from the other
side, so the number is not the reader's arithmetic about itself.

**The policy watched, both branches.** The mismatch branch is produced by the narrowing itself, because
tunneld compares digests and cannot tell a narrowing from a different policy:

```
A:626  tunneld: SANDBOX liveness lost: it pulsed 92fb0e17…7248e, expected 681331c6…b785d
A:627  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live:
       a peer at 10.14.0.3:50351 pushed a policy this sandbox no longer enforces: it pulsed …
```

and the branch the ticket is about, on both guests, after a kill that gives nothing inside the sandbox
a chance to say goodbye:

```
A:635  init: kill-after: 150s elapsed; killing the sandbox, so that nothing inside it gets to say goodbye
A:637  init: kill-after: round 1, the sandbox in this table is unshare(181) /usr/bin/runsc(182) runsc-gofer(190) runsc-tunnel-helper(191) runsc-sandbox(192)
A:638  init: kill-after: round 1 killed 5 processes
A:653  tunneld: SANDBOX liveness lost: the sandbox closed its socket
A:654  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live:
       a peer at 10.14.0.3:59512 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

`B:674-677` and `B:722-723` are the same on the other guest after `kill-after: 210s elapsed`, and
`B:722` is where the loss line survives *interleaved with three other writers*. Neither guest ever
printed `nothing killed this workload`, the line the script prints when it runs out of work: what ended
these two sandboxes was a signal from outside.

### Timings, off init's own clock

| | A | B |
|---|---|---|
| `no writable path is executable` | 3.24 s | 3.25 s |
| tunneld started → sandbox socket up (evidence, chain, listener) | 3.75 → 4.25 s (**0.50 s**) | 3.73 → 4.24 s (**0.51 s**) |
| runsc launched | 4.52 s | 4.41 s |
| runsc spawn → the sandbox's first name lookup | **0.572 s** | **0.496 s** |
| first `tunnel attach` on a tunnel that did not exist yet | 96.5 ms | 159.7 ms |
| later attaches on the warm tunnel (median, n) | 21.0 ms (16) | 23.3 ms (3) |
| narrow-after fired | — | 44.40 s |
| kill-after fired | 154.52 s | 214.41 s |
| all five sandbox processes signalled | 155.29 s (**0.77 s**) | 215.09 s (**0.68 s**) |
| the table is clear | 156.88 s | 216.58 s |
| teardown reported, bounded by those two | **≤ 2.4 s** after the kill | **≤ 2.2 s** after the kill |

**The teardown bound is the console's and not the watch's.** `attest/sandbox`'s watch ticks at a quarter
of a pulse, 250 ms; what the 2.4 s brackets is init signalling five processes — **0.68–0.77 s of it** —
and printing its mount table in between. A reader who wants the watch's own number has E3's ten trials
and the adapter check's 244 ms, not this.

The sentry's own cost of taking a policy is `run-5/`'s, because that is the pair whose `/sbin/init`
puts the `tunnel narrow:` lines on the console (`run-5/policy/console-a.txt:656`, `console-b.txt:698`):

```
A  I0918 20:28:52.911367  policy.go:230  tunnel narrow: applied in 1.314092ms, of which the table swap was 172.759µs
B  I0918 20:28:53.071642  policy.go:230  tunnel narrow: applied in 965.309µs, of which the table swap was 66.609µs
```

**One to one and a third milliseconds inside a measured guest, of which 67–173 µs is the swap** — with
the workload running throughout, which is the property the ticket exists for.

### The segment

```
l2relay: RELAYED a_to_b_frames=8316 b_to_a_frames=8234 a_to_b_bytes=9010174 b_to_a_bytes=9015758 tampered=0
l2relay: MARKER not found hits=0 marker='served-by: guest-' in 16550 frames carrying 18025932 bytes
  ethertypes : IPv4=16536, ARP=14      ip protocols: UDP=16536      arp targets : 10.14.0.2, 10.14.0.3
```

Eighteen megabytes crossed the wire — two pages, two eight-mebibyte bodies and the handshakes — and the
machine copying every frame found neither page's text, only UDP between the two guests' own addresses.

### What did not hold

**Nothing in the record pair**: 73 of 73. What did not hold in the other four is four things — the
three below and the race after them — and two of the four are facts about this design rather than
about the harness.

1. **A liveness watch lives exactly as long as the tunnel the policy arrived on.** At the sixty-second
   idle timeout every earlier scenario used, both tunnels in pair 1 idled out about a minute after the
   last fetch and a hundred seconds before the first kill, so the kill that was supposed to end liveness
   had nobody watching — three of that pair's four failures. `watchLiveness` returns silently, with no
   line and no refusal, the moment `conn.Live()` is false (`attest/tunneld/push.go:263`). Nothing is
   wrong with a watch whose tunnel is gone having nothing left to tear down; what is wrong is that a
   scenario had to derive its idle timeout from its own hold (420 s = hold + 60), which is
   leftover 22. Ticket 27 closed it: the watch is the sandbox attachment's and outlives the tunnel,
   so the scenario is back on the 60 s every other one uses.
2. **`kill_later` could not see the sandbox.** It matched `comm`, and the sentry, the gofer and the
   tunnel helper are all re-execs of `/proc/self/exe` with `Args[0]` set afterwards, so every one of
   their `comm`s is `exe` (`runsc/container/container.go:1486`). Pair 3 printed the table it was matching
   against — `the sandbox in this table is unshare(183) runsc(184)`, two processes, and **not** the
   helper that holds the sandbox's end of tunneld's socket. Matching argv[0] out of `/proc/PID/cmdline`
   finds all five, and pair 4 is the first pair whose kill is the contract's teardown.
3. **The teardown line is lost to console contention on some boots.** Over the two pairs with a working
   kill, guest A reported the socket close twice and guest B once: in `run-5/` guest B's console carries
   neither the loss nor the refusal, and in `run-4/` both landed *garbled* at `console-b.txt:722`,
   interleaved with three writers. Ticket 25's run 1 recorded the same loss and drew the same lesson —
   print what must be proved away from a flood, and init's dump of the sentry's debug log is the flood.
   Leftover 23.

**The exec control is a race with the push, and pair 1 lost it.** `EXEC REFUSED /bin/probe on attempt 1`
is a true statement about a governed sandbox and no statement at all about the transition, because in
that pair the policy had landed before the workload's first execve. The workload now asks once, before
anything else, and prints whichever way it came out; in pairs 2, 4 and 5 it won the race on both guests.
The window is the two-tenths of a second between the sandbox starting and the peer dialling — the same
window the loopback runs measured at 1 ms to 1.053 s and leftover 20 states.

**Nothing measured the `f` list.** It is empty in both pushed documents on purpose, and what makes the
bundle's root read-only and the config device `noexec` is the mount table, which the console prints
after the workload: `/dev/vdc /workload ext4 ro,nosuid,nodev,relatime`. `F` is mounts and only mounts
here too.

Two things are true of the record pair and are not failures. `--debug --debug-log=/run/runsc-debug/` is
in the **measured** flag set and costs about half a second of sandbox start — it is the price of every
`tunnel dns:`, `tunnel attach:` and `tunnel narrow:` line quoted above existing at all. And
`tunneld: SANDBOX attached` appears twice per guest, because the exit and the runsc tunnel helper are
both clients of one socket: unchanged since ticket 25, benign here, and — as leftover 21 shows — the
thing that decides whether a push lands at all.

## The TDX transcripts

**Three boot pairs on Google Cloud, and the ticket's TDX item rests on the second.** Six
`c3-standard-4` Confidential VMs in `us-central1-a`, 2026-09-18, two at a time, every one deleted
inside the hour it was created (`docs/snp/evidence/ticket26/tdx/`, and
`docs/snp/cloud/tdx/RESOURCES.md` is the authority on what existed):

| pair | created → deleted | result | what it settled |
|---|---|---|---|
| `boot-1/` | 21:06Z → 21:17Z | `44 passed, 28 failed` | both guests attested and reported the three-disk RTMR0; **no sandbox started** and **no peer was admitted**. Two faults, both in the harness and both fixed below |
| `boot-2/` | 23:25Z → 23:37Z | `69 passed, 5 failed` | the pair the TDX item rests on: two sandboxes under pushed policies, the two hops, both controls, the narrowing, the teardown |
| `boot-3/` | 23:48Z → 23:59Z | `71 passed, 3 failed` | the same again with one assertion's wording corrected, and a second sample for RQ5 |

The twelve unmeasured files are the SEV-SNP run's, unchanged, and so are the two pushed documents and
their digests: this is the same scenario on another vendor and not another scenario.

**The headline is two answers read apart, as ticket 24 insisted.** RTMR2 was predicted from the image
bytes at **2026-09-18T20:45:30Z**, inside the build and before any instance of this run existed
(`predicted-rtmr2.txt`, 25 records, over a `disk.raw` whose own sha256 is recorded beside it):

```
predicted, before any instance existed:
    7f7c43153cab5dd6353922eec2fdd628d93f29aae4b6f862c025914e9671a513d76de26580e062a68a5a86d8af404aa1
reported by all six guests of all three pairs:
    7f7c43153cab5dd6353922eec2fdd628d93f29aae4b6f862c025914e9671a513d76de26580e062a68a5a86d8af404aa1
```

**And the register ticket 24 could only observe is now one this project authors.** Every guest of this
three-disk shape reported

```
RTMR0  8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f
```

which is the second value `RTMR0-DECISION.md` pins and the emitted sets name, so **this is the first
run of this project whose guests are admitted on the shape they actually are**. No script read it off
a machine: `build-tdx-image.sh` passes two values a human typed, and the only thing this run does with
a quote is judge it. The other three registers are the provider's constants and matched: MRTD
`c1ee9c16…70a5` and RTMR1 `02c7f19c…913b`, the first-boot value of the two the sets admit.
`measurements.txt` in each pair records all four registers for each guest.

**Four verdicts per good pair, from this workstation, all ACCEPTED** — `attest-tool verify -vendor
intel-tdx` against the signed sets and the provisioned Intel collateral, in `verify-evidence-{a,b}.txt`:
each guest's quote against its own set (the self-check remade here) and against the peer's set (the
check the peer makes of it). Each guest said the same of itself on its own console at line 630:
`tunneld: SELFCHECK VERDICT ADMITTED: this platform satisfies this sandbox's own reference value set`.

### The reference value set the run needed

The sets this project authors for Google Cloud TDX admit **two** RTMR0 values instead of one:
`c2fc12a5…850a` for the two-disk shape
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
project admits. All six guests of the three boot pairs reported `8ee4fa36…b70a3f`, and in no verdict
— guest self-check or workstation, boot pair 1's refusals included — was RTMR0 the register that
refused: pairs 2 and 3 were ACCEPTED outright, and pair 1 was refused on the policy digest and on
nothing else. That is the shape of a number **authored rather than harvested**, and then being right.

### The definition of done, on both good pairs

Quoting `boot-3/console-{a,b}.txt` by line; `boot-2/` says the same with different line numbers and
different pids, and both are named where they differ.

**The policy in force is the peer's**, the same two documents and the same two digests the SEV-SNP
guests applied:

```
A:808  SANDBOX applied format=policy version=1 bytes=110 sha256=681331c69aedad34…b785d      (boot-2 A:816)
B:784  SANDBOX applied format=policy version=1 bytes=110 sha256=b23887d06a044f07…81268      (boot-2 B:795)
```

**The two hops**, each guest's sandbox fetching the other's page through the other's exit, and the
`uname` that says what fetched it:

```
A:770  initrd: httpd says: served-by: guest-a          A:797  served-by: guest-b
B:770  initrd: httpd says: served-by: guest-b          B:810  served-by: guest-a
A:823  Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux
```

**The two controls**, on all four guests of the two good pairs:

```
A:802  wget: bad address 'not-in-the-table.example'                                          N
A:779  workload: exec /bin/probe attempt 0: it ran (rc=127); no policy carrying an x is in force in this sandbox yet
A:819  workload: EXEC REFUSED /bin/probe on attempt 2: /policy-probe.sh: line 150: /bin/probe: Permission denied
B:815  workload: EXEC REFUSED /bin/probe on attempt 1: …                                     X, as a transition
```

The sentry's own `exec refused: path="/bin/probe" … reason=not-in-x` is **not** asserted on here, for
the same reason as on SEV-SNP: there is no seccheck receiver inside a measured guest, and that string
is recorded on the workstation in `.../adapter-check/notes.md`.

**The policy replaced, under a workload that keeps running**, and the sentry's cost of doing it:

```
B:868  initrd: narrow-after: 40s elapsed; starting a second tunneld to push /config/push-policy-narrow.json at the peer
A:836  SANDBOX applied format=policy version=1 bytes=76 sha256=92fb0e17644f61d4…7248e
A:845  workload: NARROWED web.peer-b stopped resolving on attempt 14: wget: bad address 'web.peer-b'
A:890  initrd: sentry: … policy.go:230] tunnel narrow: applied in 169.519µs, of which the table swap was 11.407µs
B:933  initrd: sentry: … policy.go:230] tunnel narrow: applied in 195.162µs, of which the table swap was 20.141µs
```

**A fifth of a millisecond to take a pushed policy on this hardware, of which 11–20 µs is the swap of
the table the workload is using** — four guests, two pairs, 169.5, 176.7, 195.2 and 200.3 µs. Guest A's
console carries two applied digests and guest B's one, and the stream that was open across the
narrowing carried two more mebibytes after it (`A:849 LONG reading bytes=6291456`).

**The policy watched, both branches**, and the second one is the kill:

```
A:842  tunneld: SANDBOX liveness lost: it pulsed 92fb0e17…7248e, expected 681331c6…b785d
A:843  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live: …
A:868  initrd: kill-after: 150s elapsed; killing the sandbox, so that nothing inside it gets to say goodbye
A:870  initrd: kill-after: round 1, the sandbox in this table is unshare(379) /usr/bin/runsc(380) runsc-gofer(391) runsc-tunnel-helper(392) runsc-sandbox(400)
A:908  tunneld: SANDBOX liveness lost: the sandbox closed its socket        (interleaved with init's debug dump)
A:909  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at
       10.128.0.41:48103 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

`B:918-925` and `B:957-958` are the same after `kill-after: 210s elapsed`. The five processes the kill
names are why it works at all, and they are matched by argv[0] out of `/proc/PID/cmdline` — the fix the
SEV-SNP pairs paid for, arriving on this vendor already made.

**And the mount that makes a sandbox possible here at all** (`A:581`):

```
initrd: workload device /dev/nvme0n3 found by the ext4 label, mounted at /workload
        (ro,exec,nosuid,nodev; not measured)
```

the one mount in the guest that permits exec, and therefore the third disk, and therefore the third
RTMR0.

### Timings, off the initrd's own clock

| | boot-2 A | boot-2 B | boot-3 A | boot-3 B |
|---|---|---|---|---|
| sandbox socket up / workload launched | 2.68 / 2.74 s | — / 2.72 s | 2.46 / 2.51 s | — / 2.90 s |
| evidence acquired (`SELFCHECK acquired … in`) | 40 ms | 47 ms | 41 ms | 41 ms |
| establish (`LATENCY … kind=establish`) | — | 15.5 ms | — | 15.2 ms |
| the sentry taking a pushed policy | 176.7 µs | 200.3 µs | 169.5 µs | 195.2 µs |
| of which the table swap | 13.9 µs | 18.4 µs | 11.4 µs | 20.1 µs |
| narrow-after fired | — | 42.72 s | — | 42.91 s |
| kill-after fired | 152.75 s | 212.72 s | 152.51 s | 212.90 s |
| the sandbox's table is clear | 153.90 s | 213.86 s | 153.66 s | 214.05 s |
| teardown, bounded by those two | ≤ 1.15 s | ≤ 1.14 s | ≤ 1.15 s | ≤ 1.15 s |

This vendor prints the one number SEV-SNP does not: `tunneld -selfcheck` times its own evidence
acquisition, so **40–47 ms** here is a measurement rather than a bracket.

### Boot pair 1, and the two faults it found

1. **`open /config/tunnel-table.json: permission denied`.** The config device's inodes were not
   root-owned: `mkconfigdev-tdx.sh` did what `docs/snp/image/mkconfigdev.sh` used to do before ticket
   25 — `-E root_owner=0:0` sets the root directory and `-d` copies the builder's uid onto everything
   else. The tunnel table is read by `runsc run` inside the user namespace `unshare` makes, which maps
   one id, 0 to 0, and a capability over a file is only a capability when the file's owner is mapped
   (`capable_wrt_inode_uidgid`, `user_namespaces(7)`). So both guests booted, attested, and died at
   `console-a.txt:776`:

   ```
   running container: creating container: cannot create sandbox: cannot create sandbox process:
   starting the tunnel helper: opening the tunnel table "/config/tunnel-table.json":
   open /config/tunnel-table.json: permission denied
   ```

2. **The sets admitted a digest no guest presents.** `boot-1/set-a.json` pins
   `policy_digest 6385a230…237c` and `set-b.json` pins `08e453bb…a319` — the two guests' *emitted
   policy documents* — while every guest of this image presents `197d4aae…b973`, the sha256 over the
   egress ceiling compiled into its own tunneld. So every dial was refused in both directions,
   `tunnel-run.txt:464`:

   ```
   tunneld: REFUSED verification refused: guest policy or policy digest not permitted by the
            reference value: peer presents policy digest 197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973
   ```

   and each guest refused *itself* the same way at `console-a.txt:631`,
   `SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not permitted by the reference value`.
   No tunnel, so nothing the scenario is about could happen.

**This is a deviation from `tdx/RUNBOOK.md` §7 and it is the interesting one.** The runbook expected
both self-checks to be REFUSED on the policy digest, "which is what mutual pinning means". That
expectation is **pre-ticket-22**: since ticket 22 a guest presents the digest of its own compiled-in
ceiling and not the digest of any document on any disk, and both guests boot one image, so both present
`197d4aae…b973` and both must be admitted on it. What still makes the two guests two guests is the
measurement pinning and guest B's extra forward to a measurement nobody has built.

A third fault was found by reading rather than by booting: `write_side()` declared
`local g="$1" … d="$W/$g"` in one statement, and bash expands every word of a `local` before it assigns
any of them, so `$g` was the outer, unset one and `set -u` ended the run at the first config device.
That attempt created nothing and is kept as `boot-1/aborted-first-attempt.txt`; the dry run cannot catch
it, because the dry run does not write config devices.

### The ledger

Six instances in three pairs — 21:06Z–21:17Z, 23:25Z–23:37Z and 23:48Z–23:59Z — **each pair deleted
inside the hour it was created**, none living longer than about twelve minutes, about **68 TDX
instance-minutes** in all. Twelve custom images and twelve Cloud Storage buckets were created and
deleted inside the runs that made them; none was kept, because a ticket 26 image is a record of a run
and not something a later run boots from. No firewall rule, network, IAM or org policy was created or
changed, and none of the seven pre-existing TERMINATED instances was touched. Cleanliness was verified
after every pair by the four commands the runbook names, the last time at **2026-09-19T00:01Z** —
20:01 EDT on 2026-09-18, the same working day — and all four print nothing of this ticket
(`docs/snp/cloud/tdx/RESOURCES.md`, *State after boot pair 3*).

The collateral was not refetched: `docs/snp/evidence/tdx/collateral/` was fetched 2026-09-18T08:51:43Z
and is valid to 2026-10-18T07:56:25Z, `tcbEvaluationDataNumber` 20, and every boot of this run happened
on the same calendar day, which is what the ticket's "fresh collateral the same day as any TDX run"
asks for.

### What did not hold

1. **The long body arrives short on this vendor, twice.** `LONG SHORT bytes=8384705` (boot-2 `A:858`)
   and `bytes=8388563` (boot-3 `A:853`) against 8,388,608 — 3,903 bytes and 45. **It is not the stop
   condition the ticket names**, and the evidence for that is on the same consoles: the narrowing landed
   about twenty seconds and two mebibytes earlier and the stream went on carrying bytes across it, which
   is the property under test; the far end kept serving throughout; guest B read the same
   8,388,608-byte body in one go and got all of it (`B:821 LONG-B bytes=8388608`); and the same workload
   script on SEV-SNP completed three times out of three. What is short is the tail of a slow read —
   `head -c 131072` a second apart through a QUIC stream and an exit — and the candidates are the
   reader's last partial read and the serving side's timeout, not `Policy.Narrow`. Recorded, not fixed;
   leftover 24.
2. **`initrd: EXIT status=` is on no console, in any of the three pairs.** Compute Engine serves an
   empty body for a stopped instance; the watcher chases the tail for ninety seconds and then does one
   whole-buffer read, and the last lines are simply not retrievable. Tickets 19 and 24 record the same
   thing, and everything these runs assert on is above that line. Leftover 25.
3. **Boot pair 2 failed two assertions on a word**: the console says `SELFCHECK VERDICT ADMITTED` and
   the check looked for `ACCEPTED`. The verdicts themselves were right, the workstation's four
   `attest-tool verify` runs agreed, and boot pair 3 passes them.
4. **Serial-console interleaving is worse here than on the bench.** Several lines in each console are
   three writers deep, because init dumps the sentry's debug log while tunneld is still writing — the
   teardown lines at `boot-3/console-a.txt:908` and `boot-3/console-b.txt:957` are two of them. Every
   line these runs assert on survived in all three pairs, but it is the same hazard leftover 23 states.

**Everything that changed between pairs, on both vendors, was harness, config or `/sbin/init`.** The
list in one place, because a reader owed a defect list is also owed the boundary of it: the tunnel
idle timeout 60 s → 420 s, derived as `hold + 60` and printed before the boot, which ticket 27 put
back at 60 s; the exec control asking once before anything else; `kill_later` reading the whole
process table and then matching argv[0] out of `/proc/PID/cmdline`; the sentry's `tunnel narrow:`
lines picked onto the console for the pair that measures them; the TDX config device's inodes
chowned to root, with a check that refuses a device without it; the two reference value sets
authored to admit the ceiling digest a guest of this image presents; the `local g="$1" … d="$W/$g"`
expansion bug; and one assertion's wording, `ACCEPTED` → `ADMITTED`. **Nothing under `pkg/`,
`runsc/` or `attest/` was touched by any of them** — the enforcement path the first SEV-SNP pair ran
is the one the fifth ran and the one all three TDX pairs ran, and the sentry's own numbers agree
across every pair that printed them.

## What a hop costs, and the six RQ5 components

The six components as `evaluation.tex:764-771` names them
(`.scratch/attested-secure-tunnel/paper-vs-design-27sec.md:212`), with the method for each and with
three columns of answers: the workstation's, which is a shape and not a price; two measured SEV-SNP
guests on the bench (`docs/snp/evidence/ticket26/snp/rq5-snp.md`, from `run-4/` and `run-5/`); and two
measured Intel TDX guests on Google Cloud (`.../tdx/rq5-tdx.md`, from `boot-2/` and `boot-3/`).
**Nothing in the two hardware columns is an average over a benchmark**: each is what the run printed,
two or four times, and the spread is the range those files give.

| component | method | loopback | SEV-SNP, the bench | Intel TDX, Google Cloud |
|---|---|---|---|---|
| guest execution overhead | on hardware, runsc's own spawn timestamp — the debug log's filename — to the sandbox's first `tunnel dns:`, i.e. to the first syscall the workload made that left the sandbox; beside E2's `fork`+`execve`+`wait4` benchmark for the per-exec share the X sink adds | **nothing, and it must stay nothing**: `runsc --platform=systrap` on the workstation with the tunnelds in the test's own process, so a number here would be this host's scheduler | **0.496 – 0.622 s** (4), and ticket 24's bare workload launch-to-exit on this same host was 0.85 / 0.90 s and ticket 25's adapter run 1.23 / 1.14 s — so this ticket's policy work adds nothing measurable to sandbox start | **0.071 – 0.083 s** (4), the same two endpoints on a `c3-standard-4`: an order of magnitude smaller than the bench, same runsc, same bundle, same `--debug` |
| attestation acquisition | the guest's own console line for evidence acquired from the platform, one per guest per boot | **nothing**: `fixture.SNPPlatform` over `internal/snpfake`, no report requested of any hardware | **0.50 – 0.51 s**, *not separately timed*: `init: uptime` before `running /usr/bin/tunneld` to `init: uptime` after the sandbox socket is up — the link, the report interface, the evidence, the chain, the listener and the socket together, so an upper bound containing four other things | **40, 41, 41, 47 ms** (4), a measurement and not a bracket, because the guest times it itself: `SELFCHECK acquired 8000 bytes of intel-tdx evidence in 41ms, bound to a throwaway key and to policy digest 197d4aae…` |
| attestation verification | the verifier's judgement of the peer's quote, counted per verifier call so that cold and warm are separated by the count rather than by a clock | **nothing**: `fixture.VerifierTrusting`, no VCEK fetched, no chain walked, no collateral consulted | **1 verifier call per admission**, inside row 4 (`LATENCY … verifier_calls=1`); the guest prints no verdict duration, so the figure that exists is the one containing it | the same 1 call, plus **four workstation verdicts per pair, all ACCEPTED** — `attest-tool verify -vendor intel-tdx`, each quote against its own set and against the peer's, with the provisioned Intel collateral |
| establishment of the attested channel | first `Attach`, cold, against a later `Attach` on a tunnel that already exists | a pusher's cold `Open` — dial, both verdicts, the push and its ack in one call — **38–123 ms, median 75 ms** over 9; the *shape* of establishment and **not its price**, replaced by the two hardware numbers beside it and not adjusted by them | **109.2 and 124.7 ms** (2), `LATENCY pass=1 … kind=establish attempts=1 verifier_calls=1` — one `Open` on a peer no tunnel existed to, with a relay copying every frame in the middle. From inside the sandbox: first attach **61.8 – 159.7 ms** (4), warm **5.6 – 23.3 ms** (median of 30) | **15.2 and 15.5 ms** (2), same code, same handshake, two VMs in one zone — seven times the bench's speed. From inside the sandbox: first attach **17.0 – 28.9 ms**, warm **1.3 – 6.3 ms** (19) |
| installation and binding of `P` | the three clocks E1 already reads: the table swap, the whole of `Policy.Narrow` in the sentry, and `Host.Apply` end to end | the nine governed pushes: `Host.Apply` **2.014–65.721 ms**, median 38.7 ms (bimodal, see above); `Policy.Narrow` **589.7 µs–2.696 ms**, median 1.109 ms over 8; the swap alone **87.9–884.8 µs**, median 172.2 µs over 8 | **965 µs – 1.314 ms**, of which the table swap is **67 – 173 µs** (2, `run-5/`), with the workload running throughout and an 8 MiB stream in flight on one of them. The contract round trip carrying it is **not timestamped on hardware** — the measured one is the workstation's 25.2 ms first push and 4.2 ms after | **169.5 – 200.3 µs**, of which the swap is **11.4 – 20.1 µs** (4), same conditions. The round trip is untimestamped here too, and the same workstation numbers stand in |
| capability release | E3's ten teardown trials per case, which is what release costs when it is not asked for; a narrowing that removes a name is the asked-for form and E1 times it | E3's bounds ≤250 ms (close or mismatch) and 2.10–3.25 s (three misses), met by the governed runs' own two closes at **33 and 50 ms** and one mismatch at **185 ms**; `rq5-loopback.md` also reads the row the other way round, as release when it *is* asked for — the helper's first attach 130 ms–2.138 s (median 165 ms over 7), the exit's accept→`OK` 11–14 ms, `OK`→first byte 17–44 ms | **49.4 and 148.1 ms** (2), `tunnel narrow: applied` to the first `tunnel attach: … ok` after it; they differ threefold because one was a warm attach and the other had to establish. The teardown the paper does not name is bounded at **≤ 2.4 / 2.2 s**, of which **0.68 – 0.77 s** is init signalling five processes | **0.119, 0.286, 1.830, 2.016 s** (4) — and the two larger are the workload's own three-second poll cadence and not a cost, which is what this row measures rather than a fault in it. Teardown bounded at **≤ 1.15 s** on all four guests |

**What is already separated and what is not.** Ticket 25 recorded two of the six and only as a lump
— nothing separated the QUIC handshake from the quote verification — and the distinction this
ticket adds is the fifth row, which was not measurable at all before a policy could be installed in
a running sandbox.

**What the hardware runs added, and what they did not take from here.** Rows 1, 2 and 3 are theirs
alone: loopback leaves them empty on purpose, because there is no measured guest and no attestation in
it and a number taken there would be a number about the absence of the thing being measured. Row 4 is
**replaced** and not adjusted — a real `Open` acquires a real report and verifies it against real
collateral, and shares nothing with the loopback figure but the order of its steps, which is why
109–125 ms and 15.2–15.5 ms stand where a 75 ms median of fixture arithmetic used to
(`docs/snp/evidence/ticket26/loopback/rq5-loopback.md`). Rows 5 and 6 are the comparison worth making,
and the prediction held: the sentry's own half of installing a policy is **965 µs – 1.314 ms** on the
bench against the loopback's 589.7 µs – 2.696 ms, and **169.5 – 200.3 µs** on a current cloud part —
the same code doing the same work whether or not the guest is measured, faster or slower only by the
machine it runs on. **Being measured costs the installation of `P` nothing that can be seen**, and had
it cost something, that difference would have been row 1 arriving by the back door.

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
the next two the loopback proof's, and the last five the hardware runs'.

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
16. ~~**`attest/sandbox/live.go:47-48` understates E3.** It says the send was measured at "well under
    ten microseconds"; E3 measured a p50 of 17.015 µs and a mean of 30.174 µs, and only the minimum
    was under ten. `docs/sandbox-contract.md` carries the right number. The comment, not the
    constant, is what is wrong.~~ Closed by commit `23504fe75`, which put E3's 17 µs median and
    30 µs mean in the comment.
17. **`--debug` is how every number in the spikes was read**, and it is not free. E1's and E2's
    sandboxes ran with it; a production sandbox would not, and the swap and decision costs would be
    the same or smaller. On hardware it is worse than a cost: `--debug --debug-log=/run/runsc-debug/`
    is inside the **measured** flag set, so every `tunnel dns:`, `tunnel attach:` and `tunnel narrow:`
    line these transcripts quote exists only in an image a production deployment would not boot, and
    whose launch measurement is not the one it would present.
18. **Nothing in the spikes is evidence about tunneld.** E1, E2 and the adapter check all run against
    a stand-in that speaks `attest/sandbox`'s socket and has no tunnel, no QUIC and no attestation in
    it. What is evidence about tunneld is the hardware transcripts — *The SNP transcript* and *The TDX
    transcripts*, above.
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
21. ~~**`Host.Apply` pushes only to the attachments that exist at that instant, and a sandbox that
    attaches afterwards never receives the policy.** `h.conns` is copied under the lock and iterated
    (`attest/sandbox/host.go:128-144`); SEV-SNP pair 3 is what that looks like on a console, and the
    order of four lines is the whole of it. Guest A dialled and pushed before guest B's runsc helper
    had attached: `B:556` refuses a push with *no sandbox is attached*, `B:558` is one attachment
    arriving, `B:577` is a push **acknowledged** by whatever was attached at that instant, and
    `B:584` is the second attachment — the sandbox's — arriving after it and never receiving the
    document. For the next sixty seconds B's workload ran **thirty unrestricted execs**, each printing
    `no policy carrying an x is in force in this sandbox yet`, ending at `B:694`
    `EXEC NOT REFUSED after 30 attempts over about 60s`, beside a tunneld that had said a policy was
    in force (`.../snp/run-3/notes.md`). **Tunneld claims enforcement and the sentry beside it enforces
    none of it**, and on a vendor whose only diagnostic is the console that is the difference between
    a claim and a fact. This is ticket 25's leftover 14 — two clients on one socket — in its sharpest
    form, and it is **the first thing the next ticket must close**: an acknowledgement has to mean
    *this policy reached the sandbox that will enforce it*, which today it does not.~~ Closed by
    ticket 27: an attachment declares whether it is the enforcing one, `Host.Apply` pushes to that
    one and waits for it inside the push deadline, and an enforcing sandbox that attaches after a
    push is replayed the policy in force. The record is `docs/the-ack-means-the-sandbox.md`.
22. ~~**A liveness watch lives exactly as long as the tunnel the policy arrived on.**
    `watchLiveness` polls `conn.Live()` once a second and returns the moment it is false — silently,
    with no line and no refusal (`attest/tunneld/push.go:243-267`, the return at `:263`). An
    idle-closed tunnel therefore leaves nobody watching the sandbox it governed, which is not wrong —
    the tunnel it would have torn down is already gone — but it means a scenario must derive its idle
    timeout from its own hold. SEV-SNP pair 1 lost three assertions to a 60 s idle timeout a hundred
    seconds before its kill; the harness now uses `hold + 60` and prints it before the boot. **Worked
    around, not fixed.**~~ Closed by ticket 27: the watch is the sandbox attachment's rather than
    the pushing tunnel's, so it outlives a tunnel that idles out, and a miss drops the enforcing
    attachment and marks the policy not-live whether or not there was a tunnel to close. The record
    is `docs/the-ack-means-the-sandbox.md`, and the harness is back on the 60 s idle timeout.
23. **The teardown line is lost to console contention on some boots.** Over the SEV-SNP pairs with a
    working kill, guest A reported the socket close twice and guest B once; in `run-5/` B's console
    carries neither the loss nor the refusal, and in `run-4/` both survived *interleaved with three
    other writers* at `console-b.txt:722`. Every TDX console shows the same hazard. The lesson is
    ticket 25's and is still unpaid: print what must be proved away from init's dump of the sentry's
    debug log.
24. **On TDX the long body arrives short, twice** — `8384705` and `8388563` of 8,388,608, which is
    3,903 bytes on one pair and 45 on the other — and it is **not** the stop condition the ticket
    names: the narrowing landed two
    mebibytes earlier, the stream carried bytes across it, the far end kept serving, and the same body
    read in one go from the other side arrived whole. The candidates are the reader's last partial
    read and the serving side's timeout. Recorded, not fixed.
25. **`initrd: EXIT status=` is unretrievable on a Compute Engine serial console.** The provider
    serves an empty body for a stopped instance, so the last lines of a TDX run are simply not there;
    tickets 19 and 24 record the same. Everything these runs assert on is above that line, which is a
    constraint on where a run must print what it proves and not an accident of one boot.

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
| the SEV-SNP record pair: one image, two measured guests, 73 of 73 — both policies in force by digest, both hops, both controls, the narrowing under an open stream, both liveness branches | `.../snp/run-4/` (`notes.md`, `manifest.txt`, `tunnel-run.txt`, `predicted-measurement.txt`, `policy/console-{a,b}.txt`, `policy/relay.txt`, `policy/segment.pcap`, `egress/`) |
| the other four SEV-SNP pairs, and what each one changed and cost | `.../snp/run/`, `.../snp/run-2/`, `.../snp/run-3/` (the `Apply`-at-that-instant finding), `.../snp/run-5/` (the sentry's own `tunnel narrow:` lines) — `notes.md` each |
| the TDX pair the TDX item rests on, and the pair that confirms it and gives RQ5 its second sample | `.../tdx/boot-2/`, `.../tdx/boot-3/` (`console-{a,b}.txt`, `tunnel-run.txt`, `measurements.txt`, `quote-{a,b}.{bin,txt}`, `set-{a,b}.json`, `verify-evidence-{a,b}.txt`, `egress-{a,b}.txt`) |
| the TDX pair that found the two harness faults, and the two answers read apart | `.../tdx/boot-1/` (+ `aborted-first-attempt.txt`), `.../tdx/notes.md`, `.../tdx/predicted-rtmr2.txt`, `.../tdx/RTMR0-DECISION.md`, `.../tdx/manifest.txt` |
| the six RQ5 components on each vendor, with the method for every number | `.../snp/rq5-snp.md`, `.../tdx/rq5-tdx.md`, `.../loopback/rq5-loopback.md` |
| what the cloud run created, and when each of it was deleted | `docs/snp/cloud/tdx/RESOURCES.md`, *Ticket 26*: three pairs, six instances, ~68 instance-minutes, twelve images, twelve buckets, cleanliness confirmed 2026-09-19T00:01Z |

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
socket, both acknowledging and both pulsing — which ticket 27 rewrote for contract v4, where the
enforcing client is the one a push reaches and the one that pulses.

`ripwire attest --quality-delta=6dfa00a1d..HEAD`, run from this worktree against the two committed
trees:

```
<quality-delta baseline="ref-pair" regressions="41" minor="2" acked="23" stale="9"
preexisting-worse="2" new-symbol="39" gating="0" register-macro-excluded="0"
base_ref="6dfa00a1d976046f75b28dd6b2036b00c7909cb0"
target_ref="0404d9421332feb05a28f2c17d6da5c4a78bbbd3" churn="unavailable" renames="0"
rename_window_commits="0" acked_by_rename="0" acked_by_content="0">
```

**`gating="0"`.** The two `preexisting-worse` rows are the two `minor` ones and they are the same two
symbols, both in the loopback harness: `digest` in `attest/cmd/agent-probe/adapter_test.go` grew from
117 lines to 120 and `receiver` from 64 to 68. The other **39 are `origin="new-symbol"`** and every one
is this ticket's own: **26 `dead-code`** rows, of which twenty-two are Go tests — nothing calls a test —
one is a harness helper and three are `netAtoms`, `fileAtoms` and `execAtoms`, the builders under
`sandbox.Atoms` that leftover 14 already states has no production caller; **six `duplication`** groups,
five inside the new tests and one the `acknowledged | pulsed` pair of mutex-guarded recorders in
`attest/sandbox/host.go`; **two `complexity`** rows and **five `verbosity`** rows, four of them the two
governed harnesses (`TestGovernedLoopback` at 125 lines, `TestClaudeGoverned` at 82) and the fifth
`ReasonPolicyNotLive`, whose 92 lines are the taxonomy's const block being scored whole.

**`acked="23"`**, and all 23 were acked by this ticket, in three families with the reason each row
carries. Eleven `verbosity` rows are one shape: the taxonomy's single const block is scored on the
block's line count, so adding the **eleventh reason** re-scores all eleven constants — ticket 22 acked
the same shape for the tenth. Eleven `duplication` rows and one `new-clone-of-reused-helper` row split
between **the Deno atomiser deliberately left where it is** (three of them; the four documents the two
implementations read differently are tabulated in *The subset check*, and reconciling them is not a
refactor but a decision about whose rules win), the **idiom collisions** this module has acked since
ticket 21 — a mutex-guarded accessor against another, a two-step that may fail against another — the
**house `refuse` helper** every package here wraps its own sentinel in, and the two clones the last
commit of the range accepted after looking: a hex shortener in the frozen `tsm` against one in the
harness, and two one-line formatters that share a shape and nothing else.

**`stale="9"`**: nine rows in `attest/.ripwire_quality_acks` whose target no longer applies, every one
of them `why="finding-gone"` — five `duplication`, two `new-clone-of-reused-helper`, one `verbosity`
(`TestAPushTheSandboxRefusesClosesTheTunnel`) and one `dead-code:preexisting` (`WithAdmission`,
`attest/ratls/ratls.go:250`). They are earlier tickets' entries — ticket 22's two, and the TDX phase's
table-driven-test family — and `why="finding-gone"` means the target is still there and the kind no
longer fires on it, not that anything was deleted. **The ledger was not edited**: a stale row is
hygiene the tool reports and not a
regression, and nothing here was acked to make a number smaller.
