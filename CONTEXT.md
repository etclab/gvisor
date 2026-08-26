# Attested Secure Tunnels

Vocabulary for the attested-tunnel work in this fork: two autonomous agents, each in a
gVisor sandbox on a separate confidential VM, exchanging messages over a channel that
exists only if both platforms prove by hardware attestation that they run the expected
runtime.

## Language

### Participants

**Agent**:
The autonomous, untrusted workload running inside a sandbox. Never measured, never trusted,
never shown a trust decision.
_Avoid_: workload, client, assistant, subagent — and never use "agent" for tooling, skills,
or the contributors of `AGENTS.md`.

**Tunneld**:
The per-sandbox runsc helper process that acquires evidence, holds the sandbox's key, and
owns the tunnel. A sibling of the gofer, outside the sentry's syscall path.
_Avoid_: tunnel supervisor (the binary), tunnel daemon, proxy.

**Supervisor**:
The role tunneld plays, not a binary name: the component that mediates between one sentry
and its peers.
_Avoid_: manager, broker.

**Peer**:
The tunneld on the far side of a tunnel, identified solely by its evidence.
_Avoid_: remote, server, endpoint.

**Peer Table**:
The map from peer names to addresses. Deliberately not security-critical: a wrong address
yields a failed handshake, never a compromised one, because attestation authenticates and
naming does not.
_Avoid_: registry, directory, roster.

**Operator**:
Whoever chooses which image to launch and how to configure it. Explicitly outside the
threat model.
_Avoid_: admin, deployer.

### Attestation

**Evidence**:
The vendor-specific attestation blob obtained from the platform, opaque above the vendor
seam.
_Avoid_: quote, proof, blob.

**Report**:
An SEV-SNP attestation report specifically — one concrete form of evidence.
_Avoid_: attestation (as a noun for the artifact), quote.

**Launch Measurement**:
The digest of initial guest memory that a report attests. Written **M** in prose.
_Avoid_: hash, digest, image hash, golden measurement.

**Reference Value**:
An expected measurement plus the TCB floor and policy bits a peer must satisfy.
_Avoid_: golden value, allowlist entry, enrolled key.

**Reference Value Set**:
The signed collection of reference values one tunneld will accept, admitting more than one so
an image can be rolled out without downtime. Delivered from outside the launch measurement.
_Avoid_: allowlist, roster, registry.

**Reference Value Author**:
The party whose signing key authorises a reference value set. Its public key is inside the
measured image, which makes it the trust root of the system.
_Avoid_: issuer, signer, CA.

**Attested**:
Said of a platform whose evidence satisfied the reference value set. A property of the
platform, never of an agent and never of a message.
_Avoid_: trusted, verified, authenticated.

**Gate**:
An admission check that must pass before traffic flows. There are two: the handshake-time
evidence check, and the post-handshake freshness challenge.
_Avoid_: stage, phase, check.

**Re-attestation**:
The Gate running again for a platform already admitted once. Two occasions, and they differ
in where the Evidence comes from: a Tunnel reaching its maximum age, where the same Evidence
is re-judged against the current Reference Value Set and nothing fresher is obtained; and a
change that invalidates the Evidence a deployment already holds (ADR-0002's binding
retrofit), where every platform must produce new Evidence before it can pass at all. Not a
third Gate — the same handshake-time Gate, run again.
_Avoid_: refresh, renewal, re-verification.

**Freshness Challenge**:
The post-handshake exchange of a newly generated report over a nonce and the channel's
exporter, proving the platform is in the attested state now.
_Avoid_: liveness check, heartbeat.

### Channel

**Tunnel**:
The attested connection between two tunnelds. Exists or does not; there is no unattested
tunnel.
_Avoid_: link, pipe, session.

**Channel**:
What an agent receives when it asks for a named peer: a means to exchange messages, with no
key and no trust decision attached.
_Avoid_: socket, connection (reserve that for the transport-level object).

**Exchange**:
One request/response over a tunnel, occupying exactly one stream and ending at EOF. Trailing
bytes are a protocol violation.
_Avoid_: message, call, transaction.
