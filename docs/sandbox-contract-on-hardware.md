# The sandbox contract on hardware

Ticket 22, the live half. `docs/sandbox-contract.md` says what a sandbox is told and
`docs/policy-push.md` says how a policy reaches one; both rest on offline tests over a fake
platform. This is the same thing on two SEV-SNP guests, on the ticket 14 harness, with an
on-path attacker between them: a policy pushed over a tunnel that exists only because both
sides judged the other's evidence, a second push refused, and the egress ceiling refusing
from inside each guest what the measurement says it must.

Everything below was produced on 2026-09-15 at
`aa8669a4a9c66de4d01d321ca5c229d9c40a8291`, against the image whose predicted launch
measurement is
`b02657728efac22dbdd72b0388186aaa6a2c59e6c43ab92e48d6060b1e37ee342c083c34463ebc2c3537c5998d8529cc`,
and both guests reported exactly that measurement in their evidence. The recorded run is
`docs/snp/evidence/ticket22/`, whose `README.txt` says what each file proves. The models for
this document are `docs/two-guests-on-hardware.md` (ticket 14) and `docs/two-guests-on-tdx.md`
(ticket 19).

## What ran

Four commands, in this order, and nothing else touched the guests.

```
export PATH=/usr/local/go/bin:$PATH
export STACK=.../.scratch/attested-secure-tunnel/host-stack
export AUTHOR_KEY=$STACK/image-ticket14-packaging/author.key
export OUT=$STACK/image-ticket22

cd attest && go run ./cmd/attest-tool ceiling -digest
#   197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973

docs/snp/image/package-tunneld.sh
#   guard test, then the static binary, then the image measured around it

IMAGE=$OUT docs/snp/relay-selftest.sh -out $STACK/ticket22-run/relay-selftest
#   5 passed, 0 failed

docs/snp/tunnel-on-two-guests.sh -image "$OUT" \
    -scenario live -scenario push-v1 -scenario push-v2 \
    -run-for 1000 -capture docs/snp/evidence/ticket22
#   85 passed, 0 failed
```

`AUTHOR_KEY` is ticket 14's key and has to be: its public half is inside the launch
measurement, so re-signing a set for a rebuilt image with a different key would be a different
image for a reason that has nothing to do with this ticket. Every privileged step went into
the root spool as a `.job` file that could be read before it ran; `boot.job` in each scenario's
directory is exactly what root executed.

## What had to be fixed before any of it would run

Five things, each its own commit, and four of them were in the way rather than in the ticket.

**The config device could not be built at all.** `mkconfigdev.sh` refuses a source directory
carrying `policy.json` — that is what ticket 22 did to it — and the harness copied one in.
The fix is the shape `run-tdx-scenario.sh` already had: the config *source* still gets the
policy, because that directory is what the record keeps and what the digests are read off, and
the *device* is built from a copy that leaves the two policy files behind.

**The manifest named the wrong digest.** `build-image.sh` recorded the emitted policy's digest
as `policy_digest`, which stopped being what a guest presents when the ceiling was compiled in.
It now asks `attest-tool ceiling -digest` for that number, keeps the emitted policy's own as
`emitted_policy_digest`, and — following `build-tdx-image.sh` — defaults the emitted reference
value's `policy_digest` to the ceiling rather than leaving it unconstrained. Two guests from
one image now admit each other on the policy as well as on the measurement, which the run
exercises: `neither guest's set admits a peer under any policy at all` passes in both push
scenarios.

**Loopback was never brought up.** The ceiling's output chain ends in rejects rather than in
its drop policy so that a socket learns at once that a rule refused it, and the kernel delivers
the refusal netfilter builds back to the local socket over `lo`. `init.tdx` brings `lo` up;
`init.rootfs` never did. Measured in a namespace addressed like these guests, with `lo` down:

```
tunneld: EGRESS TIMEOUT tcp/169.254.169.254:80: ... i/o timeout
tunneld: EGRESS TIMEOUT tcp/8.8.8.8:53: ... i/o timeout
tunneld: EGRESS REFUSED udp/8.8.8.8:53: ... write: operation not permitted
```

The two UDP attempts are refused either way, because EPERM comes back from `write()` on this
side; the two TCP attempts read as timeouts, and a timeout is what a black hole, a missing
route and a firewall all look like. With `lo` up all four read REFUSED.

**The two ticket 21 leftovers.** `selfcheck.go` told an operator to feed a self-check's evidence
to `attest/cmd/verify-evidence`, a program that stopped existing in ticket 21; it now says
`attest-tool verify`. And `readAuthorKey` was two byte-identical unexported copies, in the
measured binary and in the workstation tool; it is now `attest.ReadAuthorKey`, beside
`LoadReferenceValueSetFile`, which is the only thing either caller does with a key. Both were
named in `docs/shrink.md` as things a later ticket that rebuilt the image could change in the
same commit that re-measured it. This is that ticket.

**And one thing nothing offline could have told us.** The first rebuilt image booted, proved no
writable path was executable, brought loopback up, and stopped:

```
tunneld: refusing to continue: installing the ceiling: committing the rule set: socket: protocol not supported
tunneld: EXIT status=1
init: FATAL: the egress ceiling would not install; powering off without running tunneld
```

This guest kernel builds `nf_tables` as a module and the image shipped none, so there was no
ceiling to install and the guest powered off rather than run unconstrained — which is what
`init.rootfs` has always been written to do, and the first time it has had to do it. The fix is
six modules in dependency order (`nfnetlink`, `nf_tables`, `nf_reject_ipv4`, `nf_reject_ipv6`,
`nft_reject`, `nft_reject_inet`) installed into the measured root filesystem and `insmod`'d by
init, because a guest with no modprobe and no usermode helper cannot be asked to find them.

## What each criterion showed

### Two guests from a rebuilt image

`manifest.txt` predicts `b0265772…8529cc` offline, from the four measured files plus the vCPU
count and model, asking no platform anything. Both guests reported that measurement in their
evidence, and each wrote the other's down:

```
tunneld: PEER SEEN key=a7367e9e… chain=0957b4aa… measurement=b02657728efac22d…2c083c34463ebc2c3537c5998d8529cc times=2
```

The chains are equal because there is one chip under both guests and a chain is per chip and
per TCB; the keys differ, which is the only thing that tells the two apart.

### A pushes P to B, and B's null sandbox acks

One line on each console, and the same number on both:

```
guest A  tunneld: push policy /config/push-policy.json: format=policy version=1 bytes=53 sha256=c067e20134c6ba70a95ece8b2f877b11f34943dd72d0ceff5038036431903e6c
guest B  tunneld: SANDBOX applied format=policy version=1 bytes=53 sha256=c067e20134c6ba70a95ece8b2f877b11f34943dd72d0ceff5038036431903e6c
```

A said what it was about to push before it dialled anything; B said what it applied. Equality
of those two digests is what makes the pair a claim rather than two assertions, and
`push-v1/digests.txt` puts them beside the file the harness wrote.

The document is `{"format":"policy","version":1,"n":[],"f":[],"x":[]}`, 53 bytes — the envelope
`tunneld` reads and the three lists it does not. It reaches guest A the only way a guest gets
anything that is not measured: on its config device, as `/config/push-policy.json`, which init
passes to `tunneld` as `-push-policy`. Deliberately not `policy.json`: that name and its
signature are what ticket 22 took *off* the device, and a tunneld that finds either refuses to
start. The two documents are not the same kind of thing and they are not treated alike — one
was loaded and enforced locally, this one is handed to a peer and is as trustworthy as the
evidence the pushing guest presented.

### Exchanges run through the re-attestation age

The live scenario ran 1000 s against a 15-minute maximum age:

```
passes: 34, of which cost a verification: 2 (maximum age 15m, run 1000s)
```

Every pass asks for the peer again. Within the maximum age the cache answers and it costs no
handshake and no verification; the second verification is the tunnel reaching fifteen minutes
and being judged afresh, in the middle of a run that kept exchanging across it. The latency
table in `tunnel-run.txt` shows the shape: an establish that costs a verification is ~100 ms,
one that does not is ~0.06 ms, and warm exchanges sit at a few milliseconds throughout.

### A second push with an unknown version is refused as PolicyNotApplied

Same pair, same image, a version 2 document:

```
guest B  tunneld: REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 10.14.0.2:51743 pushed a policy this sandbox did not apply: sandbox: policy refused: version 2 is not 1
guest A  tunneld: REFUSED verification refused: the policy pushed to the peer was not applied: "guest-b" at 10.14.0.3:4433 did not apply the policy pushed to it: the peer refused it: this tunneld does not read a policy of that format and version
```

Both sides reach the tenth reason, from opposite ends of the same event. What crosses the wire
is a sentence about the document the peer itself wrote — `this tunneld does not read a policy
of that format and version` — and nothing about B's reference value set, its sandbox or its
machine.

Three things are absent from guest B's console, and the absences are the ordering guarantee:
no `SANDBOX applied` line, so no sandbox was ever woken; no `SANDBOX stream from peer=` line,
so no stream was ever opened on that tunnel; and no exchange answered. Guest A's exercise
failed rather than carrying on without its policy (`init: tunneld exited with status 2`), and
because a refusal is not cached it re-dialled and re-attested for the whole run — 84 attempts
over 90 s in the first pass alone, every one a fresh handshake that reached the same refusal
and carried nothing. That is the design's shape on purpose: two peers that disagree about a
policy burn a handshake per attempt, visibly, rather than settling into a quiet half-state.

### Unattested egress is still refused at the ceiling

Six captures in `docs/snp/evidence/ticket22/egress/`, one per guest per scenario, each carrying
the ceiling as the image carries it, the same rule set as the kernel handed it back, and the
verdict on every attempt. Twenty-four attempts, and all twenty-four:

```
tunneld: EGRESS REFUSED tcp/169.254.169.254:80: dial tcp 169.254.169.254:80: connect: connection refused (the provider's metadata server) — the netfilter rule refused it
tunneld: EGRESS REFUSED tcp/8.8.8.8:53: dial tcp 8.8.8.8:53: connect: connection refused (a public resolver, over TCP) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/8.8.8.8:53: write udp 10.14.0.2:52761->8.8.8.8:53: write: operation not permitted (a public resolver, over UDP) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/169.254.169.254:4433: write udp 10.14.0.2:53526->169.254.169.254:4433: write: operation not permitted (the metadata server, on the one port the ceiling grants) — the netfilter rule refused it
tunneld: EGRESS PROBE PASSED: every attempt was refused before it left
```

The fourth is the one that matters most and the one ticket 19 had no reason to make: the
ceiling's grant is the tunnel port *to any address*, and the metadata server is an address. It
is refused by the carve-out above the grant, which is a rule and not an accident.

Two honest notes about how that was reached. The probe runs **after** the exercise, not before
it, because on this image `tunneld` is what brings the link up out of the run configuration and
before it there is no address at all; the ceiling itself still goes in before the link, so the
window in which a guest is up and unconstrained has length zero. And the probe needs the
routing table to have something to say, or every attempt fails in the routing table without
reaching a rule — the probe says exactly that, `no route, so the rule was never reached; this
does not demonstrate the policy`. So init adds an on-link default route for the probe alone,
after the exercise is over, on a guest that powers off seconds later. Nothing leaves on it: the
output hook rejects those packets before the kernel resolves a neighbour, and the relay's
record of the segment is the check on that claim — `arp targets : 10.14.0.2, 10.14.0.3`, the
two guests and nothing else, in all three scenarios.

### The relay carried it and could not read it

```
l2relay: RELAYED a_to_b_frames=2594 b_to_a_frames=2569 a_to_b_bytes=287356 b_to_a_bytes=289408 tampered=0
l2relay: MARKER not found hits=0 marker='attested-tunnel-plaintext-marker' in 5163 frames carrying 576764 bytes
```

That means something only because of the two controls in `relay-selftest.txt`, run against this
image before the guests: two guests really do reach each other across the relay, and the relay
really does say `MARKER FOUND` when a marker is on the wire.

## What did not hold, and what is not claimed

- **The policy scenarios of tickets 18 and 19 were not run and no longer mean what they say.**
  `policy-pinned`, `policy-mismatch` and `mutual` turn on a policy document delivered on a
  config device and a guest printing *that* document's digest at start. Ticket 22 removed the
  document and changed the digest. The three functions still exist in the harness and their
  recorded evidence stands as history; re-authoring them around the ceiling is not this
  ticket's work, and running them today would produce failures that say nothing.
- **Nothing enforces a pushed policy.** The null sandbox records format, version, length and
  digest, and acknowledges. `n`, `f` and `x` are unparsed by every line of code in this tree.
  What is enforced is the ceiling — measured, compiled in, and in `egress/` — and the reference
  value set that admits a peer at all.
- **The pushed policy is not measured.** It is read off guest A's config device, which is the
  host's and outside the measurement. A host that rewrites that device changes what guest A
  pushes. That is the design as written: what makes the document trustworthy to guest B is
  guest A's *evidence*, and a verifier reading guest A's image learns its ceiling, not its
  delegation.
- **One push, one direction, one document.** `Config.PushPolicy` is one document and not a
  table keyed by peer, so this run says nothing about per-peer delegation. Guest B was given
  nothing to push and the run asserts that, so nothing here exercises two peers pushing at each
  other.
- **The sandbox in these runs is in-process.** `sandbox.Host` over a unix socket is tested
  offline (`TestAPushReachesASandboxInAnotherProcess`) and is what Milestone 4 will put a runsc
  sandbox behind; no guest here ran with `-sandbox-socket`.
- **A guest's own measurement was never read off a booted guest**, here or anywhere in this
  record. Every measurement is the offline prediction, and what the guests did was report the
  same number in evidence a peer judged.

## Running it again

```
export PATH=/usr/local/go/bin:$PATH
export STACK=.../.scratch/attested-secure-tunnel/host-stack
export AUTHOR_KEY=$STACK/image-ticket14-packaging/author.key
export OUT=$STACK/image-ticket22
docs/snp/image/package-tunneld.sh
unset OUT
docs/snp/tunnel-on-two-guests.sh -image "$STACK/image-ticket22" \
    -scenario live -scenario push-v1 -scenario push-v2 -run-for 1000
```

The root runner has to be up first — `docs/snp/root-runner.sh` in a tmux session, started by
the operator once, with the password typed by a human — and `unset OUT` matters, because the
harness reads `OUT` too and would otherwise write its run into the image directory.
