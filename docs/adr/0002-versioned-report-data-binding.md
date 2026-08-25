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
