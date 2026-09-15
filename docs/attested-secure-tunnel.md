# Attested secure tunnels between sandboxed agents

**Status:** design memo. **Target:** a gVisor branch.

## Goal

Two autonomous agents, each in a gVisor sandbox on a separate confidential VM, must
exchange messages over a channel that **comes into existence only if both platforms prove
by hardware attestation that they are running the expected runtime**. No operator ceremony
per host, no pre-shared keys, no CA. If either side's proof fails there is no connection —
not a connection whose messages are later rejected.

> A tunnel exists only between platforms that have proven they booted the measured image
> containing the runtime, and that proof is one launch measurement.

## Threat model

**Assumes.** AMD SEV-SNP is trustworthy and its key hierarchy intact. The image builder is
honest. The party authoring reference values is trusted.

**Defends against.** A malicious or compromised hypervisor/host on either end. A network
attacker with a full MITM position. An impostor platform claiming to run the runtime. A
hijacked agent in either sandbox.

**Does not defend against.** A malicious *operator*, who chooses which image to launch and
how to configure it. Bugs in a correctly-measured image. Traffic analysis and denial of
service. Side channels against SEV-SNP.

## Architecture

```
 ┌─ CVM (SEV-SNP guest, measured image) ──┐    ┌─ CVM (SEV-SNP guest) ─┐
 │  agent  ──syscall──►  sentry           │    │        sentry         │
 │                          │ control     │    │           │           │
 │                    tunnel supervisor ◄─┼────┼─► tunnel supervisor   │
 │                    (per sandbox)       │    │                       │
 └────────────────────────────────────────┘    └───────────────────────┘
```

The tunnel lives in **runsc**, in a per-sandbox supervisor process outside the sentry's
syscall path. Two reasons, and they are independent: QUIC, TLS, X.509 parsing and report
verification is a large body of code handling attacker-supplied bytes, which does not
belong in the sentry; and evidence acquisition needs VM-level access to
`/sys/kernel/config/tsm/`, which the sentry deliberately does not have.

Invariants:

1. **There is no path off the VM except the tunnel.** The sentry is the sandbox's network
   stack, so this is structural rather than a matter of egress configuration — there is
   nothing to misconfigure.
2. **The agent holds no key and sees no trust decision.** It asks for a named peer and gets
   a channel or an error. An agent able to evaluate evidence could ignore it, and a
   hijacked one would.
3. **The supervisor accepts requests only from its own sentry**, over the runsc control
   channel. It is not otherwise addressable.

*Implementor note:* the exact process is a decision to verify against the tree. The
existing gofer is the precedent for a per-sandbox runsc helper with host access; a new
sibling helper is likely cleaner than extending it. The sentry needs a patch either way, to
intercept the agent's outbound connection attempt and hand it across.

## What is measured, and what is not

A SEV-SNP report attests the launch measurement — the initial guest memory — plus guest
policy, TCB versions, and 64 caller-supplied bytes. Nothing after boot. Attesting a stock
guest yields a perfect report from a machine running nothing of interest.

**Covered: hardware platform through runsc, and the egress ceiling.** A minimal guest image —
firmware, kernel, initrd, no general-purpose userspace. The root filesystem is read-only and
dm-verity protected, with the verity root hash in the initrd or kernel command line so the
launch measurement covers the rootfs transitively. That rootfs contains the patched runsc and
nothing that can execute from a writable path. It also contains the egress ceiling — the one
netfilter rule set a guest built from this image installs, as a compiled-in constant rather
than a document — and the init that installs it before the link is up and before a config
device is looked for, so a verifier who has read the image knows what the guest can reach at
all, and the window in which a measured guest is running and unconstrained has length zero.

**Not covered: the agent, or the policy a sandbox is pushed.** Deliberate. The agent is the
untrusted workload; measuring it would bind the reference value to every agent image and buy
nothing. The policy is per-delegation and deployment-specific, and baking it in means a new
measurement per policy change, which destroys the single-reference-value property — so it is
neither measured nor delivered on the config device, but pushed over the tunnel after the
receiving platform has been attested, and trusted to be honoured for that reason. That is sound
only because the ceiling *is* measured: a pushed policy has plenty it can narrow and nothing it
can widen (ADR-0008).

**So state precisely what a peer learns**, because it is one inference longer than "the
report says so." SNP cannot attest that a key belongs to a sandbox, or to a sandbox at all.
The chain is: the report proves the VM booted measurement M; M contains runsc; runsc, being
measured, is trusted to generate the key and bind it to one sandbox.

| The peer learns | The peer does **not** learn |
|---|---|
| the key was generated by measured runsc | which agent runs in that sandbox |
| inside a VM whose launch measurement is M | what image the agent runs |
| bound to a single sandbox on that VM | what that sandbox does with a policy pushed to it |
| the egress ceiling that VM installed before its link came up | which peers it will dial, which `forward_to` used to declare |

That last pair is where ticket 22 moved the boundary. Ticket 18 bound a digest of the sandbox's
own signed policy into the evidence and ticket 19 gave that policy a document of its own, so a
peer was admitted only under a policy the verifier's own set listed; ticket 22 takes the
document away and puts the egress ceiling's digest in the same slot (ADR-0008). The argument
about the far side is narrower and sturdier at once. It no longer reaches what the far sandbox
will *do* — that arrives over the tunnel afterwards and nothing attests it — and what it does
reach, the rule set the far guest is enforcing, is inside the launch measurement rather than on
a disk its host wrote. An entry naming no digest still admits any ceiling. See open question 2.

## Attestation and handshake

**Evidence acquisition.** In the supervisor, via `configfs-tsm`
(`/sys/kernel/config/tsm/report/`): write 64 bytes to `inblob` in a single write, read the
report from `outblob`. The interface is vendor-neutral — the same path yields a TDX quote
on Intel — so only the evidence blob and verifier are AMD-specific. Keep that seam clean;
it is the entire cost of a second vendor later.

**Identity, per sandbox.** The supervisor generates an Ed25519 key at sandbox start with
`report_data = SHA-512(pubkey ‖ ctx ‖ policy_digest)`, and **never persists it**. `ctx` is the
16-byte versioned binding context of ADR-0002, version 2 since ticket 18, and `policy_digest`
is SHA-256 over the egress ceiling compiled into this image — what the slot names since ticket
22, where the digest of a signed `policy.json` on the config device used to go. Both travel in
the certificate payload beside the evidence, at payload version 2, because a 16-byte context
has no room for a 32-byte digest and widening it would move a byte an older reader already
reads. A verifier checks the digest against its allow-list first and recomputes these bytes
second, so a peer whose ceiling nobody admits is refused before the question of whether it
really acquired evidence over that ceiling arises. A version-1 peer commits to nothing in the
slot and is refused as an unrecognised binding context rather than admitted on its measurement
alone; ADR-0002's amendments record why, and why the version stayed at 2 when the meaning
narrowed. Key theft then requires breaking SNP; key lifetime, and therefore report freshness,
is bounded by sandbox lifetime. Sandboxes do not share keys or connections, so a peer's
identity for a channel is unambiguous and there is no cross-sandbox confusion. The cost is a
report and a connection set per sandbox rather than per VM; report generation is milliseconds
at sandbox start.

**Gate 1 — RA-TLS at the handshake.** The key is wrapped in a self-signed certificate
carrying the report in a custom X.509 extension, verified in `VerifyPeerCertificate`: the
report signature chains to AMD's root via VCEK, measurement, TCB and guest policy satisfy the
reference values, the policy digest the peer presents is one a value for that measurement
lists, and `report_data` matches the presented public key and that digest. Mutual. A failure
aborts the handshake — this is what "only when" means.

The certificate is a serialization envelope, not a trust object: no chain is built, no name
or SAN consulted, validity dates are not a control. Authentication is the report and only
the report.

**Gate 2 — freshness challenge.** RA-TLS binds the report to a key, so its freshness is the
key's age. After the handshake each side requests a **fresh** report over
`H(nonce ‖ TLS-exporter)` and exchanges it before any application data flows, proving the
platform is in the attested state now and binding that proof to this channel. Ship Gate 1
first; Gate 2 is a bounded addition on the same evidence path.

**VCEK caching.** Verification needs the VCEK from AMD's KDS, a network fetch. It is per
chip and TCB, so cache it at VM scope, shared across sandboxes — otherwise every sandbox
refetches. The certificates are public; the cache needs no protection, only a location.

## Reference values

No list of enrolled keys. Each supervisor holds one signed document, the reference value set,
which is whom it admits. The set and the policy were one document at version 3 and two since
version 4; since ticket 22 the policy is not a document at all, and the format stays at version
4 so that every set tickets 18 and 19 authored still loads.

| Field | Meaning |
|---|---|
| `vendor` | whose evidence this value admits, and whose the fields below are: `amd-sev-snp` or `intel-tdx` |
| `measurement` | expected launch measurement |
| `min_tcb` | minimum acceptable TCB (bootloader, TEE, SNP, microcode) |
| `policy` | required guest policy bits (debug disabled, SMT, migration) |
| `policy_digest` | *(optional)* the egress ceiling a peer running this image must present |
| `id_key_digest` | *(optional)* image-signing key, if using SNP ID blocks |

A `policy_digest` is SHA-256 over the egress ceiling's canonical text, commentary included, so
it names a rule set that is inside the peer's launch measurement rather than a file its host
delivered. An entry carrying one admits that image only under that ceiling and refuses anything
else as a policy mismatch naming the digest presented; an entry carrying none admits any
ceiling, and the guest prints one line per such entry at start, because an unconstrained entry
should not be something an operator discovers by reading a file they did not write. Before
ticket 22 the number named the signed region of the peer's own `policy.json`; the field, its
width and the check are unchanged, and what moved is where the number comes from (ADR-0008).

## The policy

A policy is not a document on the config device and not something an operator signs. It is
opaque versioned JSON — `{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}`, provisional
— pushed to a peer over the tunnel, per delegation, after that peer's evidence has been judged.
The receiver acknowledges it before the delegator's `Open` returns a stream, so nothing flows
under terms the far side has not confirmed it holds. Tunneld reads the format and the version
and nothing else, at the boundary and before the sandbox beside it is woken; what is done with
the rest is the sandbox's business, and today's null sandbox records the push and acknowledges
it. A push that is refused, that carries a version tunneld does not know, or that is never
acknowledged is refused as `PolicyNotApplied` and closes the tunnel — a delegation whose terms
did not arrive is not one that proceeds on the older terms.

Why an unsigned push is enough: the delegator has already proven by hardware attestation that
it booted the measured image, and the channel the bytes arrived on exists only between
platforms that have. That is a stronger statement than a signature over a document, which says
only that somebody holding the author key wrote it down beforehand. What it is not strong
enough for is *loosening*, and everything below is that one reservation.

**The ceiling.** So nothing a policy can say loosens anything, because the egress bound is a
constant in the measured image rather than an input to it: `attest/ceiling` — interface `eth0`,
UDP 4433, default-drop, loopback in both directions, the link-local block refused and no TCP at
all — installed by init before the link is up and before a config device is looked for. SHA-256
over its text, commentary included, is
`197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973`; the guest prints it at
start, and `attest-tool ceiling -digest` prints it from the same source without needing a
guest. Changing either compiled-in value makes a different image with a different measurement,
which is the property wanted — a verifier can tell a guest built for `eth0`/4433 from one built
for anything else. Whom a sandbox may talk to and what it may do are two mechanisms and
deliberately disjoint: the per-verifier allow-list and the peer table decide whom, the pushed
policy decides what, and the ceiling sits under both and bounds what the guest can reach at
all. The cost of that, plainly: under the ceiling alone a compromised guest can send UDP/4433
to any address on its link — establishing nothing there without evidence the allow-list admits,
and reaching the provider's metadata block not at all.

**History: the signed policy, tickets 18 and 19.** Until ticket 22 the policy was a second
signed document on the config device, `policy.json`, under the same author key and its own
domain prefix. It carried an `egress` section — `{"version": 1, "unattested": false}`, both
fields required — from which tunneld generated the netfilter rule set at boot, and
`forward_to`, the launch measurements this sandbox would dial, enforced by the dialing side
after the peer's evidence had verified and its digest had been admitted. It became a document
of its own because it could not be the set: ticket 18 made a sandbox's policy its own signed
reference value set and the live run proved that cannot stand — A's set would have to contain
the digest of B's set while B's contained the digest of A's, each digest taken over a document
that would then already have to contain it, so mutual pinning was inexpressible and constrained
admission was one-directional. Ticket 19 split the two and mutual pinning became ordinary
(`docs/policy-binding.md`). What the split did not fix is that the document still came off a
disk the untrusted host supplies and still decided what the guest enforced, which is what
ticket 22 closes by compiling the ceiling in and dropping `forward_to` as a decision. The
document format is kept, so every policy those tickets recorded still loads and still hashes to
the digest their records name; ADR-0008 holds the reasoning.

Membership is therefore "runs the measured image", and "under a ceiling this set lists"
wherever an entry names one — otherwise anyone who launches it joins. That is correct if the
property you want is *runs this runtime*, and wrong if you need a narrower federation; narrow
it with an ID block. Adding a host requires no human step. Revocation is a TCB floor or a
measurement change, not a file edit. The trust root moved rather than disappeared: someone
authors reference values, and that is now the sensitive act.

## Transport

QUIC with TLS 1.3, static-key pinning only, no certificate hierarchy.

- **0-RTT off**, on both the server config and by using the non-early dial entry point.
  Replay of a privileged request is a core threat and replay is 0-RTT's known weakness.
- **Connections cached per peer, per sandbox**, dialed lazily, re-dialed transparently,
  with an idle timeout and a maximum age forcing re-attestation.
- **One exchange per stream.** QUIC's multiplexing has no cross-stream head-of-line
  blocking, which is what lets concurrent agent exchanges share a warm connection. Streams
  are byte streams, so an exchange carries **a four-byte payload length and then that many
  bytes**, and the receiver requires the stream to be over after them — otherwise a sender
  frames a second message inside one exchange's payload. (This memo first said to read to
  EOF and reject trailing bytes; with no declared length every byte on the stream is payload
  by definition, so there is nothing for that rule to reject. Corrected by ticket 11.)

*Caution:* a QUIC dial can return success for a client the server is about to reject,
because in TLS 1.3 the client's handshake completes before the server evaluates its
certificate; the rejection surfaces on the first stream operation. Force one application
round trip before treating a connection as established, or an impostor appears to connect.
Gate 2 supplies that round trip naturally.

## What to build

```
attest/
  tsm/        evidence acquisition via configfs-tsm (vendor-neutral seam)
  verify/     SNP report parsing, VCEK chain validation, reference-value checks
  ratls/      certificate extension carry + VerifyPeerCertificate wiring
  tunnel/     QUIC dial/listen, connection cache, freshness challenge
  refvals/    reference value file format and loader
runsc/        per-sandbox supervisor hosting the tunnel; sentry intercept and
              control-channel handoff
image/        measured guest image build (dm-verity rootfs, initrd, cmdline)
```

**Milestones.** (1) Evidence acquisition and verification offline — produce a report in a
guest, verify it outside, prove a mutated measurement fails. (2) The measured image,
demonstrating that changing any covered byte moves the measurement. (3) RA-TLS between two
supervisors on two guests, no sandbox involved. (4) Sentry intercept and control-channel
handoff, agent to agent end to end. (5) Freshness challenge.

Milestones 1–3 are independent of the gVisor work and are where the risk is; sequence
accordingly.

## Verification

Every property gets its own evidence, and a blocked attack alone is not evidence — pair
each with a control showing legitimate traffic still works.

- Two attested sandboxes on two guests connect; a legitimate exchange succeeds.
- A guest booted from a modified image is refused at the handshake, naming the measurement
  mismatch.
- A guest below `min_tcb` is refused.
- A guest presenting a policy digest no reference value for its measurement lists is refused,
  naming the digest.
- Two guests admit each other on measurement and ceiling digest and exchange in both
  directions, and a guest whose ceiling digest is not the one its peer's set names is refused.
  (Ticket 19 showed the refusing half with two signed policies beside one image; one image now
  carries one ceiling and therefore one digest, so that arrangement is an older-format record —
  ADR-0008.)
- A pushed policy is acknowledged by the receiver before the delegator's first stream carries a
  byte, and a push that is refused, that carries an unknown version, or that is never answered
  closes the tunnel as `PolicyNotApplied`.
- A non-confidential VM presenting no evidence is refused.
- An agent attempting to reach the network other than through the tunnel fails, and so does the
  guest itself: every probe at an address the compiled-in ceiling does not permit is refused
  before it leaves, paired with a control showing the tunnel port still passes.
- A MITM relays datagrams and reads nothing.
- A replayed exchange on a fresh connection fails the channel binding.
- Trailing bytes after a framed message are rejected.
- A latency table: cold handshake including verification, warm stream-open, concurrent
  exchanges on one connection.

## Open questions

1. **Reference value authorship and distribution.** The relocated trust root, unresolved
   here.
2. **Binding runsc's configuration to the evidence.** *Resolved by ticket 18, corrected by
   ticket 19, narrowed by ticket 22.* The slot ADR-0002 reserved is spent: measured runsc folds
   a 32-byte digest into `report_data` under binding context version 2, and a verifier checks
   it against the allow-list before recomputing the binding. What the digest names has moved
   twice — the sandbox's own signed reference value set (18), then its own signed policy
   document (19), then the egress ceiling compiled into the image (22, ADR-0008) — while the
   format has not moved at all, which is why a version-1 peer, committing to nothing in the
   slot, is still refused rather than admitted without one. Trustworthy throughout for the same
   reason: the component computing the digest is measured and needs nothing from the host. What
   is bound is now a property of the image rather than of a document the host delivered, and
   the configuration that is *not* bound — the policy pushed after attestation — is unbound on
   purpose, because it can only narrow.
3. **Image update without downtime.** A new measurement is a new reference value. Do peers
   accept a set during rollout, and for how long?
4. **Attested ≠ correct.** A genuinely measured image with a logic bug attests perfectly.
   Nothing here addresses that and it should not pretend to.
5. **Second vendor.** *Resolved by ticket 17, and exercised on hardware by ticket 19.* The seam
   held: `verify/tdx.go` sits behind it and nothing above it changed to admit a TDX peer, while
   the acquirer needed three vendor-conditional corrections and no new interface. Two Google
   Cloud TDX guests then admitted each other over it, and refused each other on a measurement and
   on a policy digest (`docs/two-guests-on-tdx.md`).
