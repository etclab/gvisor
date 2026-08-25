# Reference values are signed, and the author's public key is in the measured image

The reference value set is delivered from outside the launch measurement and its signature is
checked at load against an author public key baked into the measured image. Placing the value
set itself inside the measurement makes updates cascade without termination — accepting a
peer's new image changes your own measurement, which forces every peer to update theirs, and
so on — while placing it outside unsigned hands it to the untrusted host, which then supplies
a permissive set and defeats the design. Signing breaks the cycle: updating values needs no
new measurement, and only rotating the author key does.

This is the concrete answer to the memo's open question 1. The trust root is now exactly one
public key, and its location — inside the measurement — is what makes it trustworthy.

## Considered Options

Identifying peers by `id_key_digest` (SNP ID blocks) instead of `measurement` also stops the
cascade, but weakens membership from *runs this exact runtime* to *runs something that key
signed*. It stays available as the answer when a narrower federation is wanted, layered on
rather than underneath. Accepting the cascade with coordinated flag-day updates fails against
open question 3, which requires image rollout without downtime.

## Consequences

Author key rotation is a new measurement and therefore a flag day — the one cascade that
remains. A reference value file that fails signature validation must fail closed; treating an
unverifiable set as absent, or falling back to an unsigned one, reintroduces exactly the
substitution attack this prevents.
