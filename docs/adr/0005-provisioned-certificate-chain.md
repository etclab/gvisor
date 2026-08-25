# The VCEK chain is provisioned onto the config device, not fetched at handshake time

The certificate chain needed to verify a peer's evidence is fetched from AMD's key distribution
service once at provisioning time and delivered on the same read-only block device that carries
the reference value set, rather than retrieved during tunnel establishment. Ticket 01 established
that the platform cannot supply it: `auxblob` is empty on this host and no operator action fills
it, because upstream KVM ships a stub that always returns an empty certificate table, the
configuration ioctl is absent from the host kernel's uapi, and neither a newer kernel nor a newer
hypervisor changes it. Without this decision the key distribution service becomes the only
retrieval path, which puts an outbound call to AMD on the critical path of establishing every
tunnel — an availability dependency on a third party for a channel whose entire purpose is to
exist without one — and lets AMD observe which chips are talking.

The chain has the same character as the reference value set: public, self-validating against the
AMD root, and worthless to forge. That is what makes provisioning it through an untrusted channel
sound, and it is the same argument ADR-0004 relies on.

## Consequences

The chain is per chip **and per TCB**, so a provisioned chain goes stale when the platform's TCB
is updated — and a stale chain means this platform's own evidence stops verifying *at its peers*,
not locally, which is the confusing direction for the failure to point. Re-provisioning is
therefore part of any TCB update, in the same family of operational concern as reference value
rollout. A tunneld that finds its provisioned chain missing or stale must fail closed rather than
silently falling back to a network fetch; a silent fallback would restore exactly the dependency
this decision removes, and would do it invisibly.

A stale chain surfaces as a malformed-evidence refusal rather than anything nameable as
staleness, because the verification library compares the reported TCB against the one the chain
was issued for and rejects the pair. Since the failure appears at the peer rather than locally,
the refusal detail names this ADR explicitly — an operator reading "malformed evidence" about a
platform they know is healthy needs to be pointed at re-provisioning, not at the evidence.

Because the chain becomes an ordinary local file, there is nothing left to cache, so the earlier
decision to carry no chain cache stands — and is now correct for a better reason than when it was
made.
