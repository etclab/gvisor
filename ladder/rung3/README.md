# Rung 3 — Two agents, confused deputy

Status: implemented
Deck: agent-sandbox/deck.html, slides 11–12
Tag: `rung-3`   Flags: `--ladder-attest` (+ `--ladder-peer-channels`, `--ladder-identity`, `--ladder-grants`), composes with `--ladder-taint`
Verified on: gVisor `0ef32ffa3` + this rung's patch, Linux 6.8.0-1010-intel, 2026-08-16

## Enforcement claim

1. **Every message leaving a sandbox on a mediated peer channel is stamped by the
   runtime** with the sender's identity, its current taint bit, and its declared
   grants — prepended below the syscall boundary, so the agent's own bytes are only
   ever the tail of what the peer receives. Exercised by ENFORCED
   (`LADDER STAMP channel=/peer/peer.sock sender=reader taint=1 grants=`).
2. **A stamp the agent writes itself does not override the runtime's.** Exercised by
   ENFORCED: the reader emits a byte-identical, fully padded forgery claiming
   `sender=ops taint=0 grants=read_wiki,write_config`; the delivered header is
   `sender=reader taint=1 grants=`. Both are printed side by side.
3. **A tainted message may not cause a privileged action at the receiver.**
   Exercised by ENFORCED: ops's `write_config` gets `EPERM`, the sentry logs
   `LADDER DENY sink=/broker/broker.sock`, and the broker's log shows the request
   never arrived. The acceptance policy is claim 4 plus rung 2's gate — there is no
   new denial mechanism in this rung.
4. **The receiver inherits an accepted tainted message's taint.** Exercised by
   ENFORCED (`LADDER INHERIT sender=reader`, then `LADDER TAINT set
   source=peer:reader via=recv`) and by ENFORCED-2, where ops's *own* `read_wiki` is
   refused afterwards. Monotonic, like rung 2's: there is no `Untaint` here either.
5. **The stamped path is the only path to a peer.** Exercised by ENFORCED's two
   off-channel attempts: the reader's route into ops's network (`ENETUNREACH`, a
   live listener with no route to it) and a path naming ops's mailbox (`ENOENT`).
   This claim is **not** enforced by rung 3 — it is rung 0's topology still holding,
   and it is what makes claims 1–4 worth anything. See "Where the argument rests".
6. **The identical chain over an unlabeled source is allowed.** Exercised by
   CONTROL: same two sandboxes, same channel, same `write_config`, same argument
   shape — the reader reads from `/scratch` instead of `/untrusted`, its stamp says
   `taint=0`, and ops acts.

## Problem

Rung 2's answer to the injected page was the read/act split, and rung 2's own demo
shows it working: a reader sandbox with the untrusted mount and no broker socket is
fully steered by the injection and can do nothing. What it can do is *talk*.

Ops authorizes by ops's identity: its own manifest, its own broker socket, its own
taint bit. It has never opened an untrusted file, so rung 2's bit is clear and rung
2's gate has nothing to say. Any caller that can reach ops's mailbox is therefore
spending ops's authority rather than its own — the classic confused deputy, now
across a sandbox boundary. The attacker's edit to the page changed one word: instead
of telling the reader to act, it tells the reader to forward.

The uncomfortable part is what this says about rung 2. The read/act split is not a
fix, it is a *relocation* — it moves the problem onto the channel between the halves,
and the split looked safe only because rung 2 never gave the reader a peer.

## Mechanism

Design the message path first; the security argument is entirely about where the
stamp is applied.

### The channel

Agent-to-agent messages go through `common/postbox/postbox.py`, a host process in the
same class as the broker. It listens on **one unix socket per sandbox** and each is
bind-mounted into its own sandbox at the same in-sandbox path, `/peer/peer.sock`. It
is a store-and-forward relay: `SEND to=<peer> <body>` queues, `RECV` collects.

It does **not** stamp, and could not: it has no way to learn a sandbox's taint bit.
Its two jobs are to be the only route, and to hold an identity source independent of
message content — which socket file a connection landed on. With `--require-stamp`
it uses that to drop an unstamped message, or one whose stamp disagrees with the
socket it arrived on.

**SOCK_SEQPACKET, not SOCK_STREAM.** The stamp is a fixed prefix on each message, so
"one send is one message" has to be a fact rather than a convention. On a stream an
agent could put a delimiter in its payload and hand the receiver a second, wholly
fabricated, stamped line; on SEQPACKET the kernel owns the message boundary and an
application cannot create one. SEQPACKET is also connection-oriented, so the
`connect(2)` that the labeling hooks is mandatory — an unconnected `SOCK_DGRAM`
`sendto` would have no connect to hook. Host-UDS SEQPACKET through the gofer was
verified to work before anything was built on it.

### Where the stamp is applied — in the sentry, on the send path

`pkg/sentry/socket/unix/`. A socket is labeled a peer channel when `connect(2)`
succeeds against a path under `--ladder-peer-channels`
(`pkg/sentry/socket/unix/ladder.go:134` `ladderMarkPeer`, called from
`unix.go:685`), resolved by the same `ladderSinkPathname` rung 2 uses — so a
relative path or a planted symlink cannot present the channel under a name the label
set misses. Every send on such a socket is stamped
(`pkg/sentry/socket/unix/io.go:52` `WriteFromBlocks`).

The stamp is **prepended to the iovec**, not copied into the payload:

```go
if stamp != nil {
    bufs = append([][]byte{stamp}, bufs...)
}
n, notify, err := w.Endpoint.SendMsg(w.Ctx, bufs, w.Control, w.To)
```

`transport.Endpoint.SendMsg` already takes a `[][]byte`, so this is a vector
prepend: the application's bytes are never touched or copied. It is the lowest point
in the sentry at which "the message" still exists as a unit, and it is below
anything the application can reach. The stamp's length is then subtracted from what
`write(2)` reports, and the stamp is cleared once the endpoint has accepted it, so
one `sendmsg(2)` carries exactly one stamp however many times `WriteFromBlocks` runs.

The taint bit is read at **send** time, not connect time. A sandbox that connects to
its peer, then reads the page, then sends, must send `taint=1`; a connect-time stamp
would say `taint=0` and be a lie the runtime told itself.

### Where it is consumed — in the receiver's sentry, on the read path

`pkg/sentry/socket/unix/io.go:157` `ReadToBlocks`, after `RecvMsg` fills the
destination buffers:

```go
if r.LadderPeer != "" && out.RecvLen > 0 {
    ladder.Ingest(bufs, out.RecvLen, r.LadderPeer)
}
```

**Observe, do not mutate.** The stamp stays in the bytes the application receives —
which is how the demo can print what the receiver was actually handed — and nothing
adjusts `RecvLen` or `MsgSize`, so `MSG_TRUNC` accounting is exactly what it was.
`ladder.Ingest` reads the first 128 bytes, and if the stamp says `taint=1` calls
`ladder.Taint("peer:"+sender, "recv")`. That happens before `recv()` returns, and
`Taint` is the same idempotent, monotonic, `CompareAndSwap`-guarded function rung 2
wrote, so a `MSG_PEEK` followed by a real read costs nothing.

Stripping the stamp was the other option and was rejected: it would mean receiving
into a scratch buffer, copying the payload out, and shadowing `r.MsgSize` by the
stamp length or every SEQPACKET receiver would spuriously see `MSG_TRUNC`. That is
real surgery inside `RecvMsg`'s blocking loop, for a cosmetic gain.

### The stamp

128 bytes, ASCII, space-padded:

```
LADDER-STAMP v=1 sender=reader taint=1 grants=
```

Fixed width rather than delimiter-terminated so both halves of the hook are
stateless — the sender prepends exactly this many bytes, the receiver reads exactly
this many. A delimiter would make the receiver buffer across a partial read, and a
partial read is precisely where a parser gets confused. Sender and taint come first,
so truncation can only lose grant names, which is the direction that under-claims.

### Where identity and grants come from

The runtime learns them from the container's OCI spec, as annotations:

```
--annotation=dev.gvisor.flag.ladder-identity=reader
--annotation=dev.gvisor.flag.ladder-grants=read_wiki,write_config
```

emitted by `gen_spec.py` from the manifest's `task_id` and `broker_tools` whenever
`mounts.peer: rw` — so they are the same manifest fields rung 1 already enforces,
and the launcher fixes them before the sandbox exists. Nothing inside a sandbox can
rewrite its own spec.

They are per-container by nature (two sandboxes under one runtime registration must
stamp different names), which is why they are annotations rather than daemon.json
flags, and they are added to `overrideAllowlist` (`runsc/config/flags.go:245`)
rather than requiring `--allow-flag-override`. They meet that list's bar — "should
not make the sandbox less secure" — because **neither is a privilege**: nothing in
the sandbox consults them to decide what it may do. The grant set that decides what
ops can actually call is still its broker's `--tools`. These are claims that travel
with a sandbox's messages, and a receiver can only ever refuse *more* on account of
them. `--ladder-attest` itself and `--ladder-peer-channels` are deliberately **not**
on that list: whether messages are labeled at all, and which sockets are channels,
stay administrator decisions a container spec cannot switch off.

### The acceptance policy

Two lines, and neither is new code:

1. An accepted message stamped tainted taints the receiver (claim 4).
2. Rung 2's gate then refuses its writes to the privileged sink (rung 2's claim 2).

That is the whole policy. It never wanted to become a language, and the reason is
structural rather than restraint: rung 3 has no vocabulary to write a language *in*.
The runtime holds one bit and one name. "A privileged tool call whose parameters
derive from a tainted message is denied" is approximated as "the receiver is
tainted", which the spec permits and which is exactly claim 4.

### The rest of the patch

| What | Where |
|---|---|
| the flags | `runsc/config/config.go:487`, registered `runsc/config/flags.go:187` |
| override allowlist (identity, grants only) | `runsc/config/flags.go:245` |
| config installed at boot, before any task exists | `runsc/boot/loader.go:595` |
| stamp construction, peer matching, ingest | `pkg/sentry/ladder/attest.go` |
| per-socket peer label | `pkg/sentry/socket/unix/unix.go:80`, set at `unix.go:685` |
| host-side observability | `runsc/boot/ladder.go`, CLI `runsc/cmd/ladder.go:156` |
| the channel | `ladder/common/postbox/postbox.py` |
| agent actions | `send-agent`, `recv-agent` in `common/fake_agent/fake_agent.py` |
| `mounts.peer` | `ladder/rung1/gen_spec.py:65` |

**Patch size:** 467 added lines, 11 removed, across 11 files, 1 of them new, under
`pkg/` and `runsc/` (`git diff --stat rung-2..rung-3 -- pkg/ runsc/`). Surgical where
it counts: the two enforcement hooks are 20 lines in `io.go`, and `attest.go` is 258
of those 467 -- the mechanism is small and the reasoning about it is not.

## Where the argument rests

The claim "the agent cannot forge or suppress the label" is not cryptographic.
Nothing is signed. It holds for three reasons, each of which belongs to a different
rung, and this is the first place the ladder's rungs visibly compose:

- **Rung 3** puts the stamp below the syscall boundary. The agent's bytes are the
  tail of the message; it cannot reach in front of them, because the prepend happens
  after `CopyInTo` has already mapped its memory.
- **Rung 0** makes the stamped path the only path. Each task is alone on its own
  `--internal` docker network with only its own proxy, shares no writable mount with
  any peer, and has exactly one mailbox in its filesystem. A label on one path means
  nothing if a second path exists — which is why claim 5 is demonstrated rather than
  assumed, against a live listener so that "blocked" cannot be confused with "no
  listener".
- **Rung 2** supplies the taint field and does the refusing. Rung 3 adds no denial of
  its own.

The receiver's sentry trusts that the bytes on its mailbox came from some sender's
sentry. That is true because only sandboxes and the postbox can write there, and the
postbox is trusted host infrastructure in the same class as the broker — it could
drop, reorder, or fabricate a message, and nothing here would notice. Stated plainly
because it is the load-bearing assumption.

**How the stamper learns the taint state**: it *is* the runtime. `ladder.Stamp` reads
the same package-global `ladder.Tainted()` that rung 2's gate reads, in the same
sentry process, at send time. No control API, no polling, no root. The spec's
recommended host-side proxy would have had to query `runsc ladder-status` per
message — which needs root, only answers while the sandbox is running, and would put
a second component in the trust path for the one field only the runtime knows.

## Threat model delta

Assumes everything rungs 0–2 assume, plus: the postbox is trusted, the launcher's
manifests are correct, and identity means "the runtime on this host says so".

Does not defend against:

- **A hostile receiver that never reads its mailbox.** Ops cannot avoid inheriting
  taint while still getting the message — the ingress hook fires on the read that
  delivers it — but an ops that already intends to call `write_config` needs no
  message and is bounded by rung 1's manifest, not by this rung.
- **A compromised postbox.** See above.
- **Traffic analysis, or the message's existence.** The stamp says who and how
  tainted; it does not hide that a message was sent.
- **Anything rungs 0, 1 and 2 already excluded**, including the checkpoint/restore
  hole: `policy.attest` and the taint bit are package globals outside saved state, so
  a save/restore cycle launders both. Rung 4 will need ladder state to be savable
  anyway; doing it once for rungs 1, 2 and 3 is the right move.

One thing worth naming rather than burying: **the peer channel is deliberately not a
privileged sink.** Marking `/peer` alongside `/broker` would block the tainted
reader's message and end the demo, and it would also break CONTROL — legitimate
cross-sandbox collaboration has to keep working when nothing untrusted entered. A
blanket block is rung 2 applied harder, not a new property.

## Explicitly NOT enforced (the crack → rung 4)

- **One hop only.** A→B is solved; A→B→C re-launders. Each hop sees only its
  immediate caller, so a label that is meaningful pairwise still loses the *chain*.
  Ops knows its sender was tainted. It does not know what the user originally
  authorized, nor that B's request to C exceeds what A could have asked for. Rung
  3 gets one accidental half-step here — an ops that inherits taint stamps `taint=1`
  on its own onward messages, so the bit does travel — but the *authority* does not:
  nothing carries "A was only ever allowed to read metrics" to C.
- **Identity is local.** "Sandbox identity" means the runtime on this host asserts
  it. Across hosts or clouds there is no attestation, no key, no verification — and
  the scenario explicitly places these agents in different cloud environments. Two
  hosts running this patch would believe each other's stamps for no reason at all.
  Cross-cloud attestation is a backlog item, not part of the ladder.
- **Coarse binary taint.** No notion of *which* parameter came from tainted data. The
  stamp carries a bit, not a provenance graph, and ENFORCED-2 is where that costs
  something visible.
- **Grants are carried, not checked.** The stamp has a `grants` field and rung 3's
  acceptance policy ignores it. It is there because claim 1 asks for it and because
  rung 4 needs it; a receiver that refused a request exceeding the sender's grants
  would be the beginning of chain attenuation, which is the next rung.

## Demo

```
./demo.sh                        # five blocks, 26 checks, no root
./demo.sh --with-control-query   # adds ENFORCED-3, 28 checks (needs `sudo -v` first)
./demo.sh --keep                 # leave the world up for poking at
```

Blocks: BASELINE (the hop succeeding under rung 2's settings), ENFORCED (the same
hop with `--ladder-attest`), CONTROL (the identical chain over an unlabeled source),
ENFORCED-2 (what ops loses and keeps), ENFORCED-3 (the host querying the runtime).

**Prerequisites.** docker group membership, python3, and a `runsc` built from this
tree registered as *both* `ladder-taint` (rung 2's flags — the baseline) and
`ladder-attest` (those plus rung 3's). Registering them needs sudo once; running the
demo does not.

```
make runsc && mkdir -p bin && make copy TARGETS=runsc DESTINATION=bin/
sudo cp ./bin/runsc /usr/local/bin/runsc
sudo mkdir -p /tmp/ladder-runsc && sudo chmod 0777 /tmp/ladder-runsc
sudo /usr/local/bin/runsc install --config_file=/etc/docker/daemon.json \
     --experimental=true --runtime=ladder-attest -- \
     --ladder-taint --ladder-untrusted-paths=/untrusted --ladder-privileged-sinks=/broker \
     --ladder-attest --ladder-peer-channels=/peer \
     --debug-log=/tmp/ladder-runsc/%ID%.%COMMAND%.log
sudo systemctl reload docker
```

Rung 2's `ladder-taint` runtime must still be registered; rung 3's BASELINE runs
against it. `--debug-log` is not decoration — the sentry's emitter is `io.Discard`
without it (`runsc/cli/cli.go:230`), so the `LADDER STAMP`/`INHERIT`/`DENY` lines
the demo greps for would not exist anywhere.

Note that identity and grants are **not** in the registration command: they are
per-container annotations, so one `ladder-attest` runtime serves every peer.

Transcripts of passing runs are in `expected/`.

**How the flag-off case was checked.** Rungs 0, 1 and 2's demos were re-run against
the patched binary with `--ladder-attest` off: `make demo-all` PASS (rung 0 23/23,
rung 1 15/15, rung 2 31/31, rung 3 26/26), plus rung 0's `--baseline-runtime=runc`
23/23, rung 1's `--with-runtime-patch` 18/18, and rung 2's `--with-control-query`
33/33. `gen_spec.py` grew one optional mount and two annotations, and every rung-1 and
rung-2 manifest was diffed through the old and new generator to confirm the emitted
spec and the `show` table are byte-identical. gVisor's own test suite was **not**
run; the only evidence that upstream behavior is unchanged is those demos and the
fact that every new branch is guarded by `ladder.AttestEnabled()` or a per-socket
field that is `""` when the flag is off.

## Spec corrections

Where the rung-3 spec or conventions §2 were wrong about this tree, and what is true:

1. **Claim 4 needs no new control method.** The spec says "There is no way to *set*
   the bit from the host … Claim 4 needs a new control method", and suggests a
   monotonic setter on the control API. It does not: taint inheritance happens
   inside the receiving sentry, on the read that delivers the message, using rung 2's
   existing `ladder.Taint`. No host round-trip, no root, no new urpc method, and the
   monotonicity argument the spec was preparing to make is not needed because
   nothing new can clear anything.
2. **The recommended host-side proxy was not taken, and the "highest cost" label on
   Sentry-side stamping was overstated** — as rung 2's open questions predicted. The
   two enforcement hooks are eight lines in `pkg/sentry/socket/unix/io.go`, because
   `transport.Endpoint.SendMsg` already takes an iovec and `RecvMsg` already leaves
   the received bytes in buffers the caller owns. The proxy would have been *more*
   work, needed root, and would have put a second component in the trust path.
3. **Rung 1's `ladderScope` holds no capability set.** The spec's "the sender's
   capability set (its rung-1 task grants)" implies the runtime already knows them.
   It does not: `boot.Network.ladderScope` is `[]*net.IPNet` — egress CIDRs and
   nothing else — and it is populated only by a `LadderNarrow` call, never at boot.
   The tools half of a rung-1 manifest never enters the runtime at all; it is
   enforced host-side by the broker. Grants therefore had to be introduced, as a
   per-container annotation.
4. **One gate flag is again not enough configuration**, exactly as rung 2's
   correction to conventions §2 predicted. Rung 3 ships four: the gate, plus which
   sockets are channels, plus identity, plus grants. Two of the three configuration
   flags are per-*container* rather than per-runtime, which is new — rung 2's were
   all per-runtime — and OCI annotations are how gVisor already expresses that.
5. **`SOCK_SEQPACKET` to a host UDS works through the gofer.** Not stated anywhere in
   the spec, and load-bearing: it is what makes "one send is one message" a kernel
   fact instead of a convention an agent could break. Verified end-to-end before the
   patch was written. The gate is `isSockTypeSupported` at
   `runsc/fsgofer/lisafs.go:809`, which admits STREAM, DGRAM and SEQPACKET.
6. **`pkg/sentry/fsimpl/gofer/socket.go:31` `isSocketTypeSupported` is dead code** —
   defined and referenced nowhere. A reader checking "which socket types can reach a
   host UDS" will find it first and it is not the answer; the gofer-side check is.

### Was this hard?

The mechanism was cheap for the same reason rung 2's was: the interception point
already existed, and rung 2 had already answered the hard question of where the
sandbox-global state lives. The two things that took real thought were both about
*framing* rather than enforcement — choosing SEQPACKET so the message boundary is
not an application's promise, and noticing that a receiver which strips the stamp
inherits a `MSG_TRUNC` accounting problem it does not need.

The uncomfortable finding is in the other direction. Rung 3 is where the ladder's
enforcement stops being self-contained: the stamp is unforgeable because of rung 0's
topology, and it is meaningful because of rung 2's bit, and it is *trusted* because
of a host process nothing verifies. Each rung individually is a runtime property; the
system is a deployment.

## Open questions

- **The postbox is unverified.** Every other trusted component in the ladder is
  trusted for something narrow (the broker holds credentials; the launcher writes
  manifests). The postbox is trusted to relay honestly, and nothing checks it. The
  cheapest fix is not cryptography — it is deleting it, by having the receiving
  sentry rather than a host process own the mailbox, which is a real design question
  about whether a sentry should ever listen.
- **Grants are carried and ignored.** See the crack. Wiring the receiver to compare a
  request against the sender's stamped grants is a few lines and is deliberately not
  done, because "compare against what?" is rung 4's question and answering it here
  would blur the boundary the ladder exists to show.
- **A tainted sender's onward stamps say `taint=1`**, so the bit is transitive across
  hops for free. The authority is not. Whether that half-step is a useful primitive
  for rung 4 or a distraction from proper chain attenuation is worth deciding before
  rung 4 starts.
- **Nothing is savable, still.** Rung 1's `ladderScope`, rung 2's taint bit and rung
  3's `policy.attest` are all package globals outside checkpoint state. This is now
  three rungs with the same note; it should be done once.
- **The denial is still `EPERM` from a tool call the agent believes is legitimate.**
  Rung 3 makes it worse than rung 2 did, because ops has no way to know *why* — it
  never read anything, and nothing tells it a message it accepted is the reason. An
  agent that could be told "this was refused because your context is tainted, by a
  message from reader" could at least report the fact to a human.
