# Pair 1: `=== 69 passed, 4 failed ===`

The first SEV-SNP pair of ticket 26, 2026-09-18, image `f8b60b78…ef31` (predicted
offline before either guest existed and reported by both). The full account of
all five pairs is `../run-4/notes.md`; this file says what this one proved and
what it found.

**Proved, on the first attempt and never in doubt afterwards:** both sandboxes
took the policy the *other* guest pushed (`SANDBOX applied … 681331c6…b785d` on
A, `b23887d0…81268` on B), both were served the peer's page through the peer's
exit, the name in nobody's policy did not resolve, an exec outside `x` was
refused on both, guest A took a second policy without being restarted, the
dropped name stopped resolving and the 8,388,608-byte stream that was already
open when that happened arrived whole, and guest A's tunneld refused the tunnel
the first policy arrived on, naming liveness.

**The four that failed, and all four are about *when*, not *what*:**

1. `guest-a: and it was allowed before the policy landed` — the workload asked
   for the exec control after two fetches, by which time the push had landed, so
   the transcript recorded a governed sandbox and not the transition. The
   workload now asks once before anything else (`../policy-probe.sh`, attempt 0).
2, 3, 4. the three liveness-at-the-kill assertions — the tunnel each policy
   arrived on had idled out (60 s) a hundred seconds before the kill, and
   `attest/tunneld/push.go`'s `watchLiveness` ends silently when `conn.Live()` is
   false. The scenario's idle timeout now outlives its own hold.

Nothing here is a defect in the sentry, in tunneld or in the contract.
