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
