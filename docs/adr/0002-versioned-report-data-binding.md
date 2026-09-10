# report_data reserves space for a policy digest it does not yet carry

`report_data` is `H(pubkey ‖ ctx)` where `ctx` is a fixed-width, versioned field that is
all-zero in v1, rather than the memo's `H(pubkey)`. Open question 2 asks whether runsc's
configuration should be bound into the evidence and defers it, while warning that
retrofitting means re-attesting every deployed platform. Reserving the field costs one
constant and a version byte now and turns that cliff into a version bump.

## Considered Options

`H(pubkey)` as the memo proposes leaves the retrofit cliff standing. Computing a real policy
digest now would drag Milestone 4's policy plumbing into Milestone 1, which the agreed scope
excludes.

The digest is SHA-512 rather than the SNP-native SHA-384, decided during ticket 02. Its output
is exactly the 64 bytes the platform copies verbatim, so no padding convention exists for two
implementations to disagree about. A shorter digest would need one, and a padding convention is
the kind of detail that is agreed once, written down nowhere, and discovered later by a peer that
cannot verify anybody.

## Consequences

A verifier must treat a non-zero `ctx` as a version it may not understand and reject rather
than ignore it, or the reservation buys nothing.

## Amendment, 2026-09-08 (ticket 18), as corrected 2026-09-10 (ticket 19)

The reservation is spent. `ctx` v2 is version byte `0x02` with every remaining byte zero, and
`report_data` under it is `SHA-512(pubkey ‖ ctx ‖ policy_digest)`. The policy digest is SHA-256
over the exact bytes the author's signature covers — a domain separation prefix and the document
— so it names the signed region rather than the file, and `sha256sum` of the file is a different
number.

What it names is the sandbox's own signed **policy**, `policy.json`: a document carrying an
`egress` section and `forward_to`, the measurements this sandbox will dial. Ticket 18 made it
name the reference value set instead, on the grounds that a set with an `egress` section was
already a statement about behaviour, and the live run showed why that cannot stand. An
allow-list entry names a peer's policy digest, so two peers pinning each other would need A's
set to contain the digest of B's set while B's contained the digest of A's — each digest taken
over a document that would then already have to contain it. Nobody can author that pair.
Constrained admission was one-directional, and the only fully constrained pair admitted nothing
in either direction.

Ticket 19 therefore splits the two documents. The policy carries no digests at all, so the two
digests in a pair are fixed independently and mutual pinning is expressible. The reference value
set is format version 4: measurement and `policy_digest` pairs, and no `egress` section — a set
that still carries one is refused with a sentence saying to move it into the policy and sign both
again. Nothing about the binding changed: `report_data`, `ctx` v2 and the payload's optional
sixth field are exactly what ticket 18 shipped, and the amendment is a correction about which
document the digest names, not about how it travels.

The digest travels beside the context in the certificate payload, which is version 2 for the same
reason the binding is: a 16-byte context has no room for a 32-byte digest, and widening the
context would move a byte a v1 reader already reads. A verifier does not take the digest on the
peer's word any more than it takes the public key — the peer's evidence has to have been acquired
over it — which is what makes an allow-list of measurement and policy pairs mean anything.

v1 peers are refused as an unrecognised context, and the consequence this ADR recorded now cuts
the other way. It was written about a version from the future, which may bind something a verifier
cannot see. A version from the past binds nothing, and admitting one would let any peer skip the
policy check by claiming the older context — the reservation would have bought a version bump and
nothing else. `ratls.Open` refuses a version 1 payload with the same reason before it reads a
field that payload never had, because a peer speaking it is running yesterday's tunneld rather
than presenting something corrupt, and the operator on the other end has a build to redo.

The digest is checked against the reference value's allow-list before the binding is recomputed.
Both orders refuse the same peers; this one refuses them in the order the questions get cheaper to
answer, and it keeps the two statements separate in the log. "Your policy is not one I admit" is a
sentence an operator acts on by editing a set; "your evidence was not acquired over the policy you
claim" is a sentence about a peer that is lying, and it should not be reachable by anyone who
merely presented an unlisted digest. An entry that lists no digest admits any policy, which is
what every set authored before this amendment says; that is the one place this design reads an
absent field the weaker way, and a tunneld prints one line per such entry at startup so that
nobody has to find out by reading a file they did not write.

One check does not live here at all, and the asymmetry is the point. `forward_to` is enforced by
the *dialing* side after the peer's evidence has verified and its digest has been admitted: it
asks whether this sandbox's own policy says it calls the image in front of it. That is a fact
about the dialer, so no allow-list entry of the peer's could carry it and no verifier could
decide it. It refuses with the same reason a policy digest mismatch does, and a detail saying
which of the two it was.
