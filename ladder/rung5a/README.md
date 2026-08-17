# Rung 5a — Federated runtimes, standing-service model

Status: implemented
Deck: agent-sandbox/deck.html, pending
Tag: `rung-5a`   Flags: `--ladder-fed` (on the federation proxy; **no runsc flag**, and
the demo runs against rung 4's `ladder-chain` runtime unchanged)
Verified on: gVisor `release-20260810.0-67-ge81dec090e2b` — **rung 4's binary, unrebuilt**,
because rung 5a adds no runsc flag — Linux 6.8.0-1010-intel, 2026-08-17

The first rung whose problem is not inside a machine. Rungs 3 and 4 made a message's
label unforgeable because one trusted relay was every sandbox's only path and the sender
and the receiver shared it — a statement about **one process boundary**. Rung 4's own
threat model says what happens when the second hop moves: *"Two hosts running this patch
would believe each other's stamps for no reason at all."*

---

## Enforcement claim

1. **Cross-host agent traffic flows only through runtime proxies.** A sandbox holds no
   transport key, no connection and no registry; its entire vocabulary for the network is
   `send-agent ops@hostb` on a unix socket its own kernel stamps. The tunnel terminates in
   the host-side proxy, never inside a sandbox. Exercised throughout, and resting on rung
   0's topology (per-task `--internal` networks) rather than on this rung.
2. **A runtime not in the enrolment registry is refused at the handshake.** Not
   "its messages are rejected" — refused, before any stream exists, so no envelope, no
   stamp and no capability claim is ever parsed. Exercised by `ENFORCED`:
   `handshake decision=deny reason=server: peer public key sha256:025b7bda32c36a0e is not
   in the enrollment registry (enrolled: [hosta])` — the fingerprint is per-run, the
   sentence is not — against `BASELINE`, where the identical impostor delivers a forged
   clean stamp and ops applies what it asks for.
3. **Eight per-message checks, each with its own code and its own evidence line.**
   Tampered stamp → `signature-invalid`; tampered body → `body-tampered`; replay on the
   same connection → `replayed`; replay on a fresh connection → `not-exporter-bound`;
   backdated expiry → `expired`; a binding from another channel → `not-exporter-bound`;
   a second message appended after the payload → `trailing-bytes`; a capability outside
   the receiving service's role → `outside-role-scope`. Exercised by `ENFORCED`, one at a
   time. **Read this claim with "Who the adversary is" below** — these are run by an
   *enrolled* sender, not by a network attacker.
4. **The runtime's facts cross the network intact, and the far side's runtime still acts
   on them.** The reader's sentry sets taint on a labeled read; the 256-byte stamp is
   carried verbatim inside the federation envelope; ops's sentry ingests it on another
   host and rung 2's gate refuses the broker write. Exercised by `ENFORCED-2`: the stamp
   ops was handed reads `taint=1 ... origin=/untrusted/incident-page.txt`, and host B's
   runsc log carries `LADDER DENY sink=/broker/broker.sock taint=set source=peer:reader`
   — for a path host B has no mount for and a read it could not observe.
5. **A tainted standing service is bounded by rebirth, not cleared in place.** The proxy
   *reads* the runtime's taint bit off an outbound stamp and asks the launcher to destroy
   and restart the sandbox. Nothing anywhere clears the bit. Exercised by `ENFORCED-3`:
   `recycle service=reader reason=taint`, generation 1 tainted → generation 2 clean, and
   the far host's stamp agrees (`taint=0`). **Partial, deliberately — see "The residual
   window".**
6. **One human step per host, ever, and none on the per-exchange path.** Exercised by
   `CONTROL`: two SPAKE2 ceremonies at start-up, then 32 concurrent exchanges completing
   unattended on one warm connection, plus the committed latency table.

---

## Problem

Rung 4 ends with a system whose labels are unforgeable *by the agents that carry them*.
That is the right claim and it is the wrong shape for the scenario the deck describes,
where the hops are in different cloud environments. Move the second hop to another
machine and three things that were free stop being free:

- **Nobody authenticates the other end.** Host B's relay knows which local socket a
  message arrived on. There is no socket when the sender is on another machine, and
  `from_host: "hosta"` in a message is a string the sender typed.
- **Nothing protects the stamp in transit.** The field rungs 3 and 4 worked hardest to
  make unforgeable travels in the clear, next to a capability delegation that is also in
  the clear. `BASELINE` reads both and rewrites both.
- **Nothing binds a message to a moment or a channel.** A captured privileged request is
  a reusable one.

And a fourth, which is the model's rather than the transport's: an agent that never exits
never clears its taint bit.

---

## Mechanism

### Where everything lives

**No gVisor patch.** Verified rather than assumed: there is no `ladder-fed` or
`LadderFed` symbol anywhere in `pkg/` or `runsc/`, `git diff rung-4..rung-5a -- pkg/
runsc/` is empty, and the demo runs against rung 4's `ladder-chain` runtime with no
rebuild. §2a of the spec is why — the inner stamp stays exactly where rung 3 put it.

```
ladder/common/fed/     the substrate, a separate Go module (5b reuses it verbatim)
ladder/rung5a/         the scenario, the demo, this file
```

Host-side changes to the existing harness are small and inert without their flags:

| What | Where | Lines |
|---|---|---|
| federated destinations (`to=ops@hostb`), the fed gateway and the ingest listener | `common/postbox/postbox.py` | +264 −3 |
| `import` — the one op that records a capability this authority did not derive | `common/chaind/chaind.py` | +113 −2 |
| `serve-agent` — an agent that stays up and handles exchanges | `common/fake_agent/fake_agent.py` | +92 |
| listen backlog for a 32-way burst | `common/broker/broker.py` | +5 |

**Patch size.** `git diff --stat rung-4..rung-5a -- pkg/ runsc/` is **empty**, which is
the rung's headline result and not a formatting accident. `-- ladder/common/fed/` is 13
Go files and 3,984 insertions, of which **1,155 are comment or blank** — this substrate
is where the rung's design argument lives, so it is written to be read. The changes
threaded through files that already existed come to 474 insertions across four files, and
`ladder/rung5a/` is 2,222 lines of which 992 are `demo.sh` and 403 are committed
transcript.

### The two-layer stamp (spec §2a)

| Layer | Written by | Carries | The proxy |
|---|---|---|---|
| inner, 256 bytes | the **sending sandbox's kernel** | identity, taint, grants, chain, origin | copies it verbatim, **never writes one** |
| outer, the envelope | host A's proxy | routing, expiry, sequence, channel binding, the attenuated capability | writes and signs it |

The proxy *reads* the taint bit — that is what a policy layer is for, and it is how the
recycle policy learns anything. It cannot *write* one: the only function in the package
that emits stamp bytes lives in `attack.go`, where it is a forgery tool. Had rung 3 put
stamping in a host-side proxy, this rung would have had to decide which host-side process
was allowed to invent a taint bit, and every claim above it would be circular.

### The transport

QUIC, TLS 1.3, **static-key pinning only** — "TLS used as if it were Noise KK", which is
what §2 asks for. Two planes, deliberately not collapsed:

| Plane | Lifetime | Cost (measured, loopback) |
|---|---|---|
| **Enroll** — SPAKE2 over a self-hosted mailbox | once per host, ever | ~0.3 s of machine time for two ceremonies, plus one 3-word code typed by a human |
| **Connect** — cached QUIC per host pair, 0-RTT off | lazy, re-dialled transparently | ~4 ms median cold handshake |
| **Converse** — one stream per exchange | per exchange | ~0.3 ms median stream-open; ~4 ms end to end including the receiving postbox and its capability authority |

0-RTT is off in both required places (`quic.Config.Allow0RTT` unset on the server; the
non-`Early` dial entry point on the client) because replay of a privileged request is the
threat this substrate exists to stop, and replay is 0-RTT's known weakness. The burst
measurement is what makes that affordable: **32 concurrent exchanges on one warm
connection, 32/32 completed, ~25 ms wall, under 1 ms each amortized.**

These are loopback floors on an unloaded box and they move by roughly a factor of two
between runs, so the table above is rounded on purpose; the exact figures from the
committed run are in [`expected/latency.txt`](expected/latency.txt). The result is the
*ratio*, not the absolute numbers: five orders of magnitude separate the step a human is
on from the step an exchange is on.

The ten receive-side checks, their order and their codes are in
[`common/fed/README.md`](../common/fed/README.md). The property acceptance criterion §7
asks for holds: in `ENFORCED`, one message reached the postbox and eight were refused in
the proxy — the capability authority was never asked and the ops sandbox saw no bytes.

### Road not taken — Noise / WireGuard

Recorded here because §2 asks for it. Our post-enrolment trust model — both sides already
know each other's static keys — is exactly Noise KK, and WireGuard is Noise IK. Rejected
for the transport because (i) under the two-plane split, handshakes are amortized per host
pair, so Noise's cheap-handshake advantage stops mattering, while the agent-pace path is
stream-open, where Noise offers nothing (no mux, no loss recovery, no flow control); and
(ii) the attestation machinery this ladder is committed to lives on TLS 1.3 — RATS
(RFC 9334), the SEAT drafts (in-handshake and RFC 9261 exported-authenticator
post-handshake), and deployed aTLS admission (Constellation's JoinService) — with no prior
art for attestation inside a Noise handshake. What we kept is Noise's *worldview*: strict
static-key pinning, no certificate hierarchy. `identity.go` implements that literally.

### Where cross-host trust enters, and where it is logged

`chaind`'s new `import` op, and it is the only operation in the ladder that records a
capability the authority did not derive itself. The sending host ran rung 4's attenuation
check against the delegator's own set; what crosses is that check's **result**, already
narrowed and never touched by an agent. The receiving proxy checked it against the
service's role scope before the postbox was contacted. Every import logs its own basis:

```
import hop=ops from=reader@hosta host=hosta chain=user@hosta>trigger@hosta>reader@hosta>ops
       taint=0 origin=- basis=enrollment-not-attestation
```

Taint is merged, never lowered: a claim asserting `taint=0` over a stamp saying `taint=1`
loses, because the stamp was written by a kernel below the syscall boundary and the claim
by a host-side daemon.

---

## Who the adversary is (read claim 3 with this)

Once the QUIC connection is up, **a network attacker cannot produce checks 3–7.** That is
the whole point of the transport: a MITM can drop packets and corrupt them into a
connection error, and nothing else. The party that *can* produce them is one holding an
**enrolled** key and choosing to misbehave — which is precisely the residual this rung
leaves open.

So `ladder-fed attack` **is** that adversary, used as the test harness, and the demo says
so out loud before running the cases. "Tampered stamp rejected" here does not mean the
network was defeated; it means an enrolled peer cannot get a message accepted under a
stamp it altered, a sequence it reused, an expiry it backdated, a binding it borrowed, or
with a second message glued to the end. Two cases genuinely *are* network-attacker cases
and are labelled as such: the **impostor** (unenrolled key, refused at the handshake) and
the **MITM** (reads and rewrites in `BASELINE`; relays the datagrams and reads 0 ladder
tokens in `ENFORCED`).

Overclaiming this is the easiest mistake available in this rung, so the demo prints the
distinction rather than letting the README carry it alone.

---

## The rung-3 forgery attack, re-tested on the wire

Rung 3 needed `SOCK_SEQPACKET` on the local peer channel because on a byte stream an
agent can put a second, fully-formed, "stamped" message inside its own payload and hand
the receiver two messages where the kernel saw one. **QUIC streams are byte streams**, so
that attack is available again the moment a receiver parses more than one message per
stream.

The design forces one exchange per stream, and this rung makes that load-bearing: the
sender frames exactly one Sentry-stamped message and `CloseWrite`s; the receiver reads to
EOF and rejects **any** trailing byte. `ladder-fed attack --case trailing` appends a
second, correctly-signed frame carrying `write_config auth_disabled true` and gets:

```
trailing-bytes: 767 byte(s) after the payload; one exchange per stream,
                trailing bytes are a second message
```

---

## What the standing model costs

These are structural, not bugs, and they are the reason rung 5b exists.

**Receiving-side authority is role-scoped, not task-scoped — the far side of rung 1 is
regressed.** `scenario/roles/ops-role.json` is fixed at deploy time and has no idea which
goal or which caller is on the other end. It is a real ceiling — a claim naming
`auth_disabled` is refused before delivery — and it is a much blunter one than the
per-task manifest rung 1 introduced. An enrolled host cannot exceed the role, and can do
anything inside it, for any goal it cares to name.

**The service is a warm, stateful target.** Every message ops accepts that carries
`taint=1` taints it permanently, and there is no per-message isolation anywhere in the
model: a caller that reaches this instance reaches every later caller's instance too.

**The residual window.** Measured, not asserted: with `--recycle-on-taint` the reader
served **1 exchange** after the read that tainted it and before the recycle request. One
is the minimum — the proxy learns the bit from the stamp on an *outbound* message, so at
least one message has already gone out by the time it can act. A count or age threshold
makes the window larger, never smaller.

And what recycling does **not** do: the poisoned page is still on the wiki and still in
the labeled mount. A reborn service that reads it again is tainted again immediately.
Recycling bounds how long a taint lasts; it does not touch why it happened.

---

## Threat model delta

**Assumes.** Two operators (or one with two machines) who complete an enrolment ceremony.
Both runtimes are trusted; the agents are not. Each host's broker, relay, capability
authority and federation proxy are trusted and reachable only from that host's user. The
federation key file is 0600 and is bind-mounted into nothing — an agent that could read
it could impersonate its own runtime, which is the one thing the whole substrate rests on.

**New in this rung.** A network attacker with a full MITM position, and impostor hosts
claiming to be ladder runtimes.

**Does not defend against.**

- **A hostile-but-enrolled host.** See "Explicitly NOT enforced". This is the crack.
- **Compromise of any host-side fixture.** Unchanged from rung 4, now doubled: there are
  two brokers, two relays and two capability authorities.
- **Traffic analysis.** The MITM cannot read the exchange and can count it, time it and
  drop it. Nothing here is a mix network.
- **Denial of service.** A MITM can black-hole the connection. The proxy re-dials; it
  does not route around a censor.
- **Registry theft or staleness.** Distribution and revocation are manual. A stolen key
  is impersonation until somebody edits a file.
- **Checkpoint/restore.** Still unfixed, now for five rungs. Ladder state is package
  globals, so a save/restore cycle launders the taint bit and the chain — and now the
  federation carries whatever the stamp says, so a laundered bit crosses hosts cleanly.
  This is the oldest open item in the ladder and rung 5a made it slightly worse.

---

## Explicitly NOT enforced (the crack → the attestation rung)

**Keys are trusted by ceremony, not by attestation.** A completed enrolment proves an
operator was present at both ends at one moment. It proves nothing about what the peer
*runs*. A hostile-but-enrolled host — or one compromised after enrolment — passes every
check in this rung and can assert anything inside the receiving service's role. The
demo's own per-message harness *is* that adversary, so the gap is not hypothetical; it is
the thing the tests are built on.

The substrate was chosen so both attestation slots exist, and this is where they go:

- **Admission-time**, the Constellation JoinService pattern: evidence presented once per
  host, checked before the registry entry is written. Today that slot holds
  `runtime_version` and `policy_epoch` — two fields the ceremony carries and **nothing
  enforces**. They are in `registry.go` as the shape of the answer, and the file says
  they are unenforced rather than letting two unused fields imply a check.
- **Per-connection**, SEAT-style: evidence over a dedicated ALPN or stream, bound to the
  exporter. `ALPN = "ladder-fed/1"` and `ExporterLabel` are already the two hooks.

Also out of scope here:

- **Revocation and distribution.** Manual, by hand, and named in `registry.go` as this
  rung's crack.
- **Task-scoped authority on the receiving side.** That is rung 5b's whole point.
- **Field-level provenance, intent → scope, cryptographic attenuation.** Rung 4's backlog,
  unchanged and now multiplied by the number of hosts: the root capability is still
  hand-written, and every host that imports one inherits that assumption.

---

## Demo

```
./demo.sh          # five blocks, 37 checks, no root
./demo.sh --keep   # leave the world up for poking at
```

Verify through `make demo RUNG=5a` and `make demo-all` rather than running `demo.sh`
directly — rung 5a is in `IMPLEMENTED_RUNGS`, so the regression sweep covers it.

**Blocks.** `BASELINE` runs `--ladder-fed` off: a MITM reads the sentry's stamp in the
clear, rewrites both the payload and the capability claim behind it, and ops applies
`auth_disabled=true`; then an unenrolled impostor delivers a forged clean stamp and ops
applies that too. `ENFORCED` turns the flag on: the impostor is refused at the handshake,
the MITM relays the exchange (`relayed=1 datagrams bytes=1280 readable-ladder-tokens=0`) and reads nothing out of it, and eight per-message
checks fire one at a time. `CONTROL` runs the legitimate cross-host chain and prints the
latency table and the 32-way burst. `ENFORCED-2` runs rung 4's chain across the network
through the labeled path. `ENFORCED-3` is the recycle policy and its residual window.

**Prerequisites.** docker group membership, python3, a Go toolchain (the module declares
`go 1.25.0`; the gVisor tree's own `go.mod` declares newer, so any checkout that builds
runsc has one — set `LADDER_GO` if the `go` on `PATH` is older), and rung 4's runtime:

```
sudo /usr/local/bin/runsc install --config_file=/etc/docker/daemon.json \
     --experimental=true --runtime=ladder-chain -- \
     --ladder-taint --ladder-untrusted-paths=/untrusted --ladder-privileged-sinks=/broker \
     --ladder-attest --ladder-peer-channels=/peer \
     --ladder-chain \
     --debug-log=/tmp/ladder-runsc/%ID%.%COMMAND%.log
sudo systemctl reload docker
```

That is rung 4's registration, unchanged and unextended. Rung 5a adds no runsc flag.
`--debug-log` is still not decoration: `ENFORCED-2` greps for `LADDER DENY` from host B's
sandbox, and the sentry's emitter is `io.Discard` without it.

**Two hosts on one box.** The spec allows this and asks the README to say which was used.
Two federation proxies on loopback aliases — `hosta=127.0.0.1:14801`,
`hostb=127.0.0.2:14802`, MITM at `127.0.0.3:14803` — each with its own registry, key,
capability authority, relay and brokers, sharing nothing but the wire. Not network
namespaces, because netns needs root and every claim here is about what crosses *between*
the two proxies rather than about which kernel they run on. The one thing this stand-in
cannot show is a genuinely partitioned network; a real second host would change no line of
`ladder-fed` and no line of the demo except the two addresses.

**Offline.** No internet, no public relay, no cloud account. The mailbox is self-hosted on
127.0.0.1, the Go build runs with `GOPROXY=off` from the module cache, and the sandboxed
agents reach only local containers.

A committed transcript of a passing run is in `expected/`; the latency table is in
`expected/latency.txt`.

---

## Spec corrections

Where the rung-5a spec and conventions §2 were wrong about this tree, and what is true:

1. **Go has no RFC 7250 raw public keys.** §2 asks for "TLS 1.3 with raw public keys
   (RFC 7250 — no X.509, no CA)". `crypto/tls` has no `client_certificate_type` or
   `server_certificate_type` extension at any Go version available here — checked in the
   standard library source, not remembered. The Ed25519 key is wrapped in a self-signed
   certificate that is *only* a serialization envelope: no chain is built (`VerifiedChains`
   is empty on both sides), no name or SAN is consulted, and the validity dates are set a
   century wide so nobody mistakes certificate expiry for a control. The spec's *intent* —
   "keep Noise's worldview: strict static-key pinning, no certificate hierarchy" — is met
   exactly; its *mechanism* is not available. Ed25519 itself did not fight back anywhere.
2. **`quic.Dial` returns a nil error for a client the server is about to reject.** In TLS
   1.3 the client's handshake completes once it has *sent* its Certificate/Finished; the
   server has not looked at the client's key yet, and the rejection arrives on the first
   stream operation as `CRYPTO_ERROR 0x12a`. Claim 2 is therefore false unless the dialer
   forces an application round trip before handing the connection back. Without
   `dialConfirmed`, the impostor "connects".
3. **A refused handshake never becomes a connection**, so the accept loop cannot report
   it. Host B's evidence line is written from inside the pin-check callback, which is the
   only place that knows why.
4. **§2's "expect little or no Sentry change" was right, and the answer is *none*.** Not
   one line of `pkg/` or `runsc/` changed. That is worth stating as a result rather than
   as an absence: it is the verdict in `ladder/README.md` holding under the sharpest test
   the ladder has applied to it. Everything rung 5a adds is a decision about an action or
   a property of a channel, and none of it is a fact about a sandbox — so none of it
   belongs in the runtime, and none of it went there.
5. **§4.4's role check had to be reimplemented in Go.** `chaind.subset` already exists in
   Python, but "before delivery to the agent" means the check has to run in the proxy, and
   routing every inbound message through a host-side daemon first would put the
   substrate's own admission decision downstream of a process it does not own. The
   duplication is real; `rolescope.go` names it as a cost rather than hiding it.
6. **The enrolment ceremony needed no rendezvous implementation.**
   `wormhole-william`'s own `rendezvous/rendezvousservertest` is not a `_test.go` file and
   is importable, so the self-hosted mailbox is upstream's server rather than 226 lines of
   ours. Two things bit: the rendezvous client **never consumes server error frames**, so
   every server-side rejection presents as a hang and a context deadline is mandatory; and
   the default code length is 2 words (16 bits), which is fine for sending a file and thin
   for minting a long-term trust anchor — this uses 3 (24 bits).
7. **The spec's sequence number is the *narrow* half of the replay defence, not the main
   one.** §2 lists "per-(sender, peer) monotonic sequence number" and the exporter binding
   as two items in a list. Measured, they stop different attacks: a captured envelope
   replayed onto a *fresh* connection dies on the binding before the sequence is ever
   examined, and the window only catches a replay onto the *same* connection. The demo
   runs both cases separately so the transcript cannot credit the counter with the
   exporter's work.
8. **§6's "packet capture shows ciphertext" is better served by the MITM than by
   tcpdump.** The MITM is already in the position the threat model names, needs no root,
   and can report both what it read and what it could not. It relays the datagrams and finds 0
   ladder tokens.
9. **§6.1's baseline attack has to rewrite the capability claim, not just the payload.**
   Rewriting the instruction alone leaves rung 4's key allowlist refusing it at the far
   broker — correctly, because that check is host-side logic that never depended on the
   transport. This was measured, not predicted: the first passing build had a BASELINE
   that *failed*, for the right reason. The claim is no more authenticated than the
   payload, so the MITM rewrites both, and the baseline is stated at full strength.

### Was this hard?

The substrate was the largest single artifact in the ladder — about 2,300 lines of Go —
and almost none of it was hard. The transport is 200 lines once the two gotchas above are
known; the envelope and its checks are 300; the ceremony is 200 because it does not
implement a PAKE. What took the time was deciding *what the adversary is* for each check,
and that is the part the README carries rather than the code.

The one genuinely delicate piece was resisting the easy simplification. Moving the stamp
into the proxy would have removed the base64 round trip, the opaque-bytes discipline and
an entire section of this document — and would have made every claim above rung 3
circular. §2a exists because the spec's author anticipated the temptation, and it was
right to.

---

## Open questions

1. **Is a role scope on the receiving side worth having, given 5b exists?** It is a real
   ceiling and it caught a widening in the demo. It is also strictly worse than the
   task scope rung 1 built, and 5b gets that back. If 5b lands, the honest question is
   whether anyone would deploy 5a for reasons other than ecosystem compatibility.
2. **Should the receiving host verify the sending host's chain arithmetic at all?** Today
   it imports the result and trusts the enrolment. It *could* re-derive — but only from
   facts host A also supplies, so it would be checking a host's claim against the same
   host's claim. The answer is probably attestation rather than re-derivation, which is
   the next rung, and it is worth saying that a second capability authority buys nothing
   here.
3. **What is the right recycle threshold?** `--recycle-on-taint` gives the smallest
   window this design can give and destroys a warm service on the first tainted read;
   a count or age threshold trades window for stability. Nobody has data on which is
   right, and the demo picks the aggressive one because it is the one whose residual is
   easiest to state honestly.
4. **Does the two-layer stamp survive a peer with a different `StampLen`?** No, and
   nothing detects it — the wire contract is now shared by four implementations across
   two languages and two machines. Rung 4 noted this for three; rung 5a makes a mismatch
   a cross-host failure that presents as garbled provenance rather than as an error.
5. **Checkpoint/restore, for the fifth rung running.** And now with a federation on top:
   a laundered taint bit crosses hosts and is imported as truth on the far side.
