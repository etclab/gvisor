# SNP report verification uses google/go-sev-guest rather than a hand-rolled verifier

`verify/` wraps `github.com/google/go-sev-guest` for report parsing, VCEK retrieval from
AMD's KDS, chain validation to the AMD root, and TCB and policy predicates. Hand-rolling this
would mean owning ASN.1 and AMD's certificate semantics inside the security boundary the
whole design rests on, in a research prototype where that code is not the contribution.

## Consequences

The library's API shape leaks into `verify/`'s interface, so the vendor seam described in the
memo has to be drawn deliberately rather than emerging: keeping the AMD-specific surface one
package deep is what makes a second vendor (open question 5) answerable later.

**Addendum (ADR-0005).** VCEK retrieval from the KDS is no longer part of what the wrapper is used for: the chain is provisioned onto the config device and the verifier refuses to fetch.

**Amendment (ticket 17, 2026-09-08).** The same decision is taken for Intel TDX, and the same
reasoning carries it: `verify/tdx.go` wraps `github.com/google/go-tdx-guest` for quote parsing,
the walk from the embedded PCK certificate to Intel's root, and the signature, revocation and
expiry checks on Intel's TCB info and quoting-enclave identity. Hand-rolling those would mean
owning Intel's PCK extension ASN.1 and its provisioning-service semantics inside the security
boundary, which is the mistake this record exists to avoid.

The library is pinned to commit `1f7f7b9b42b9` (`v0.3.2-0.20240902060211-1f7f7b9b42b9`). It is
pre-1.0 and carries Google's "not an officially supported product" disclaimer, so the argument
that made this comfortable for AMD is weaker here — the study said so and it remains true. Two
behaviours of that commit shape the verifier and are recorded here so that a bump is reviewed
against them: it accepts only a TCB status of `UpToDate`, before any floor of ours is consulted,
which is stricter than the reference value's `SWHardeningNeeded` floor can express; and it flattens
every failure into one untyped error, so the verifier classifies by *where* it asked rather than by
what the library said. One thing the library does not do is left to us: it resolves the platform's
TCB level only to refuse, so the level a verifier reports in its claims and holds to a floor is
computed again in `verify/tdx.go` by the algorithm Intel documents, on the same TCB info the
library has just verified.
