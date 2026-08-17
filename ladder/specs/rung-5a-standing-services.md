# Rung 5a — Federated runtimes, standing-service model

Read `00-conventions.md` and rungs 0–4 first — **including their implementation notes**;
this spec is written against the fork as built, not the original briefs. Deck: pending.
Tag: `rung-5a`. Flag: `--ladder-fed` (on the new federation proxy; expect little or no
Sentry change — but see §2a, the stamp integration point, before assuming none).

**Sibling spec:** `rung-5b-task-templates.md`. Both variants share §2 (the federation
substrate) verbatim; they differ in what a cross-host stream *means*. 5a assumes agents
are standing services (A2A/MCP-style: long-lived, addressable, ready to serve). 5b
assumes agents are stood up from templates per task. Implement the substrate once;
the variants are alternative harness scenarios plus different receiving-side policy.

---

## 1. Problem (P5)

Rungs 3–4 are single-host: the stamp is unforgeable because one trusted proxy is every
sandbox's only network path, and sender and receiver share it. Across hosts — the
scenario's actual premise — the stamp crosses an untrusted network. Required: (a) transit
integrity/confidentiality, (b) proof of which *runtime* is on the other end, (c) binding
of stamps to that identity. Deferred but **must not be foreclosed**: (d) remote
attestation that the peer runs the expected patched runtime (next rung).

New workload requirement, stated as a design forcer: agent-to-agent exchanges are
**ephemeral, throwaway, short-lived, bursty, and at agent-pace** — no human ceremony may
sit on the per-exchange path. Human-pace steps are allowed only at per-host enrollment.

Threat model delta: network attacker (MITM/tamper/replay) + impostor hosts claiming to
be ladder runtimes. Agents remain honest-but-hijackable.

---

## 2. Federation substrate (shared with 5b)

Two planes with different lifetimes; do not collapse them into one layer.

**Enroll (human-pace, once per host).** A Magic-Wormhole-style PAKE ceremony
(`wormhole-william`, MIT; self-hosted mailbox server) between a new runtime proxy and
the registry holder: the SPAKE2-protected channel exchanges the runtime's long-term
Ed25519 public key + metadata (runtime version, policy epoch). This is the only human
touchpoint and the only place trust enters. Registry = the broker/policy layer's list of
enrolled runtime keys; distribution and revocation are manual (that is this rung's crack).

**Connect (machine-pace, lazy, cached).** Proxies maintain lazily-established QUIC
connections per host pair: TLS 1.3 with **raw public keys** (RFC 7250 — no X.509, no CA),
mutual auth, peer key checked against the registry, connection refused otherwise.
**0-RTT stays off** — replay of privileged requests is the core threat and 0-RTT's known
weakness is replay; the stream design below gets ~0 added latency without it. ≤ N²
cached connections at N hosts; idle timeout + transparent re-dial.

**Converse (agent-pace, ephemeral, bursty).** One QUIC stream per exchange. Stream-open
on a warm connection costs no round trip; streams have no cross-stream head-of-line
blocking — this is what absorbs burstiness. Every stream begins with a **stamped
envelope**: sender identity, rung-4 chain (accumulated taint + capability set), expiry
(minutes), per-(sender, peer) monotonic sequence number, all bound to the channel via
TLS keying-material export (RFC 5705/8446 exporter). Tampered, expired, replayed, or
unbound stamps are rejected before any payload is processed.

**§2a — stamp integration point (reconcile with the fork, do not assume).** The
original rung-3 brief recommended a host-side stamping proxy; the fork chose the
Sentry, because the taint bit is the one field only the runtime knows and per-message
`runsc ladder-status` polling was too costly — with `SOCK_SEQPACKET` load-bearing, since
on a byte stream an agent can forge a second stamped message inside its payload. Two
consequences bind rung 5:

1. The cross-host stamp is therefore **two-layer**: the Sentry-applied sandbox stamp
   (local, unforgeable, carries taint/chain) wrapped in a federation envelope the proxy
   signs with the enrolled transport key and binds to the channel. Do not move
   stamping out of the Sentry to simplify the proxy — that reopens the polling problem
   rung 3 already rejected and shrinks the runtime's provenance role (see the verdict in
   `specs/README.md`: the runtime holds *facts*; the proxy must not manufacture them).
2. **Message boundaries must survive the transport.** QUIC streams are byte streams;
   the SEQPACKET lesson recurs if the receiving side parses multiple messages out of one
   stream. The design already forces one exchange per stream — make that load-bearing:
   the proxy frames exactly one Sentry-stamped message per stream, and the receiver
   rejects trailing bytes. State this in the README as the rung-3 forgery attack
   re-tested across the network, and re-run that attack in the demo.

Invariants carried forward: the tunnel terminates in the runtime-owned proxy, never
inside a sandbox — agents hold no tunnel or signing keys; the proxy is the only licensed
off-host path (rung 0 egress denial extended: sandbox egress rules admit only the proxy).

**Road not taken — Noise/WireGuard.** Our post-enrollment trust model ("both sides
already know each other's static keys") is exactly Noise KK/IK; WireGuard is Noise IK.
Rejected for transport because: (i) under the two-plane split, handshakes are amortized
per host pair, so Noise's cheap-handshake advantage stops mattering, while the agent-pace
path is stream-open, where Noise offers nothing (no mux/loss recovery/flow control);
(ii) the attestation machinery this ladder is committed to lives on TLS 1.3 — RATS
(RFC 9334), the SEAT drafts (in-handshake and RFC 9261 exported-authenticator
post-handshake), and deployed aTLS admission (Constellation JoinService) — with no prior
art for attestation inside the Noise handshake. Keep Noise's worldview: strict static-key
pinning, no certificate hierarchy — TLS used as if it were Noise KK. Record this
paragraph in the README.

---

## 3. The 5a model: agents as standing services

Each host's runtime fronts one or more **long-lived agent services** (reader, ops, …),
each in its own sandbox with a stable service identity `(runtime key, service name)` and
a deploy-time role scope. Callers address an existing, waiting agent; a stream is a
request/conversation delivered to it. This matches the A2A/MCP ecosystem shape
(agent cards, standing MCP servers).

## 4. Enforcement claim

1. Cross-host agent traffic flows **only** through runtime proxies over the §2 substrate;
   a sandbox attempting direct off-host egress fails (rung 0 extension, demoed).
2. A connection from a runtime **not in the enrollment registry is refused at the
   handshake**; an impostor host cannot deliver a message at all.
3. Stream preambles are verified: tampered stamp → rejected; replayed sequence →
   rejected; expired stamp → rejected; stamp not exporter-bound to this channel →
   rejected. Each with its own evidence line.
4. The receiving proxy enforces rung-4 chain checks (accumulated taint, capability
   ⊆ checks) against the standing service's role scope **before** delivery to the agent.
5. **Taint hygiene for standing agents (partial, honest):** taint accumulates
   monotonically per rung 2, so a long-lived service trends toward permanently tainted.
   Mitigation implemented here: a **recycle policy** — after max conversation count/age,
   or on taint, the service sandbox is destroyed and restarted fresh from its image.
   This bounds taint lifetime; it does not eliminate the window. State the residual
   window in the README.

## 5. What to build

```
ladder/rung5a/
  README.md
  demo.sh
  enroll/            # wormhole ceremony wrapper + registry file format
  scenario/          # two hosts (or two proxies on one box simulating hosts),
                     # reader service on host A, ops service on host B
  expected/
ladder/common/fed/   # shared with 5b: QUIC-RPK transport, stamp preamble codec,
                     # registry, sequence/replay cache — build it here, 5b reuses it
```

Two real hosts are ideal; two proxy instances with separate network namespaces on one
box are an acceptable stand-in — say which in the README.

## 6. Demo (`ladder/rung5a/demo.sh`)

1. **BASELINE** — `--ladder-fed` off: cross-host proxy traffic over plain TCP. Show
   (i) a MITM position reading and altering a message (tampered privileged request is
   accepted), and (ii) an **impostor host** delivering a forged clean-stamp message that
   causes a privileged action at ops. Both succeed.
2. **ENFORCED** — flag on: impostor connection refused at handshake (not in registry);
   tampered stamp rejected; replayed stream rejected; packet capture shows ciphertext.
   Then the rung-4 chain case cross-host: tainted reader findings relayed to ops →
   privileged call denied at ops' proxy. Then the recycle policy: drive the reader
   service past its taint/age threshold, show destroy-and-restart, show taint cleared
   only via rebirth (never in place).
3. **CONTROL** — legitimate cross-host chain succeeds, and **print the burst numbers**:
   per-exchange added latency on a warm connection (target ≈ stream-open, no handshake)
   and K exchanges fired concurrently, all completing. The agent-pace requirement is a
   demo assertion here, not prose.

## 7. Acceptance criteria

- All §4 claims individually evidenced; substrate rejections happen in the proxy before
  any agent sees bytes.
- One enrollment ceremony per host total — demonstrate that *no* per-exchange or
  per-conversation human step exists (the burst in CONTROL runs unattended).
- Rungs 0–4 demos still pass single-host; flag off ⇒ rung-4 behavior.
- Latency table (handshake vs stream-open vs end-to-end) committed in `expected/`.

## 8. Explicitly NOT enforced (the crack → attestation rung)

- **Keys are trusted by ceremony, not by attestation.** Enrollment proves an operator
  vouched once; nothing proves the peer *runs the enforcement* (a hostile-but-enrolled
  host can stamp lies). Next rung: attestation evidence — admission-time (Constellation
  JoinService pattern) and/or per-connection (SEAT-style over a dedicated ALPN/stream,
  exporter-bound). The substrate was chosen so both slots exist; say so.
- Registry distribution/revocation is manual; key theft = impersonation until noticed.
- **Standing-model residuals** (structural, not fixable at this rung): receiving-side
  authority is role-scoped, not task-scoped — the far side of rung 1 is regressed;
  taint is bounded by recycle, not eliminated; the service is a warm, stateful target.
  These are the costs 5b avoids — cross-reference the comparison in `specs/README.md`.

## 9. Report back

Conventions §7, plus: measured handshake and stream-open latencies; whether RPK TLS in
Go (crypto/tls + quic-go or equivalent) was straightforward or fought back; how the
replay cache is bounded; the recycle policy's chosen thresholds and the taint window
they leave; whether anything here touched the gVisor tree after all.

---

## Outcome (written after implementation; the body above is left as it was)

**Implemented. Tag `rung-5a`, 37 checks, `make demo-all` green across rungs 0–5a
(23 + 15 + 31 + 26 + 43 + 37 = 175).** Full writeup in `ladder/rung5a/README.md`;
substrate notes in `ladder/common/fed/README.md`.

**§9's questions, answered.**

- *Whether anything here touched the gVisor tree after all* — **no.** `git diff
  rung-4..rung-5a -- pkg/ runsc/` is empty, and the demo runs against rung 4's
  `ladder-chain` runtime unrebuilt. §2a's instruction not to move stamping out of the
  Sentry is what made that possible, and it was the single most load-bearing sentence
  in this spec.
- *Was RPK TLS in Go straightforward, or did it fight back* — **it does not exist.**
  `crypto/tls` has no RFC 7250 support at any available Go version: no
  `client_certificate_type`, no `server_certificate_type`. The Ed25519 key is wrapped in
  a self-signed certificate used purely as a SPKI container, with no chain built, no name
  checked and validity dates a century wide. §2's *intent* ("TLS used as if it were Noise
  KK") is met exactly; its *mechanism* is unavailable. Ed25519 itself fought back nowhere.
  Two Go-specific traps, both costly if unknown: `quic.Dial` returns a nil error for a
  client the server is about to reject (the rejection lands on the first stream op as
  `CRYPTO_ERROR 0x12a`, so claim 2 is false without a forced post-handshake round trip);
  and a refused handshake never becomes a connection, so the accept loop cannot report it
  and the evidence line has to come from inside the pin-check callback.
- *How the replay cache is bounded* — sliding window of 1024 sequence numbers per
  (host, peer): a highest-seen value plus a 128-byte bitmap, so memory is O(peers) and
  not O(messages). Anything more than a window behind the highest is rejected outright,
  which is the fail-closed direction. **And a correction to §2's framing:** the sequence
  number is the *narrow* half of the replay defence. A captured envelope replayed onto a
  fresh connection dies on the exporter binding before the sequence is examined; the
  window only catches a replay onto the *same* connection. The demo runs both separately
  so the counter cannot be credited with the exporter's work.
- *The recycle policy's thresholds and the taint window they leave* —
  `--recycle-on-taint`, measured at **1 exchange**. That is the minimum this design can
  give: the proxy learns the bit from the stamp on an *outbound* message, so at least one
  message has already left by the time it can act. `--recycle-max-exchanges` and
  `--recycle-max-age` exist and make the window larger, never smaller. Recycling also
  does not touch the *source*: a reborn service that re-reads the poisoned page is tainted
  again immediately.
- *Measured latencies* — committed in `ladder/rung5a/expected/latency.txt`, and rounded
  here because loopback medians move by about a factor of two between runs. Floors:
  enrolment ~0.3 s of machine time for two ceremonies (plus a human typing a 3-word
  code); cold handshake ~4 ms; stream-open ~0.3 ms; end-to-end exchange ~4 ms including
  the receiving postbox and its capability authority; 32 concurrent exchanges on one warm
  connection, 32/32 in ~25 ms. The result is the ratio, not the absolutes: five orders of
  magnitude separate the plane a human is on from the plane an exchange is on.

**Where this spec was wrong or incomplete about the exercise.**

1. **§6's ENFORCED list cannot be staged as network attacks, and saying so is part of the
   result.** Once QUIC is up, a network attacker cannot produce a tampered stamp, a
   replay, a backdated expiry, an unbound envelope or trailing bytes — that is what the
   transport is *for*. The party that can is one holding an **enrolled** key, which is
   exactly the residual §8 names. The implementation therefore uses an
   enrolled-but-misbehaving sender as the harness and says so in the demo output, rather
   than letting the transcript imply the network was defeated. The two genuine
   network-attacker cases (impostor, MITM) are labelled as such.
2. **§6.1's baseline attack has to rewrite the capability claim, not just the message.**
   Discovered by measurement: the first complete build had a BASELINE that *failed*,
   because rewriting only the payload left rung 4's key allowlist refusing the write at
   the far broker — correctly, since that check is host-side logic that never depended on
   the transport. The claim is no more authenticated than the payload, so a MITM rewrites
   both. Worth carrying into 5b: rung 4's host-side checks survive an unauthenticated
   transport, and a baseline that does not account for them understates itself.
3. **§4.4's role check had to be reimplemented in Go.** "Before delivery to the agent"
   means in the proxy, and routing every arrival through a host-side daemon first would
   put the substrate's admission decision downstream of a process it does not own.
   `chaind.subset` now exists twice, in two languages. The cost is named rather than
   hidden.
4. **§2's enrolment needed no rendezvous implementation.** `wormhole-william` ships
   `rendezvous/rendezvousservertest`, which is not a `_test.go` file and is importable, so
   the self-hosted mailbox is upstream's own server. Two things bit: the rendezvous client
   never consumes server error frames, so every server-side rejection presents as a hang
   and a context deadline is mandatory; and the default code is 2 words (16 bits), which
   is thin for minting a long-term trust anchor — this uses 3.
5. **The registry's `runtime_version` and `policy_epoch` are carried and enforced by
   nothing.** §2 asks the ceremony to exchange them, and it does. They are the slot the
   attestation rung fills, and `registry.go` says they are unenforced rather than letting
   two unused fields imply a check.

**What 5b will need that now exists.** The whole substrate, unchanged:
`ladder/common/fed/` is a standalone Go module with the transport, the envelope codec,
the registry, the replay window and the enrolment ceremony. What 5b has to replace is the
receiving side — `Proxy.admit` and its role-scope check become a spawn path — plus
`chaind`'s `import` op, which for 5b mints a *task* rather than recording a role-scoped
capability. The comparison table in `specs/README.md` holds up: everything in the 5a
column that the implementation touched cost what the table said it would.
