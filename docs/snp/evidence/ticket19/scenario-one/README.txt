Ticket 19, scenario one: two guests from one image, each pinning the other.

Two Confidential VMs on Google Cloud TDX, both booted from the same custom
image, each holding a signed reference value set that names the OTHER guest's
policy digest and no other. Both directions admit, both exchange, and the run
is long enough that each tunnel reaches its maximum age while a caller is still
using it and is re-attested underneath them.

  instances   t19-one-a at 10.128.0.40, t19-one-b at 10.128.0.41
              c3-standard-4 TDX, us-central1-a, one 20GB boot disk from
              attested-tdx-d5ddcc423b1a and one 10GB config disk each
  created     2026-09-10T23:29Z          deleted 2026-09-10T23:42Z
  written by  docs/snp/cloud/tdx/run-tdx-scenario.sh one
  verdict     55 assertions, 55 passed, 0 failed (tunnel-run.txt)

## The documents

  D_A = d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b
  D_B = 444a4aa826ae40b5cc4332df842f0cea17e02a51f6d8f30f2385daf051561f28

  set-a.json admits measurement d5ddcc42…73e0d paired with D_B, and no other.
  set-b.json admits the same measurement paired with D_A, and no other.
  Neither guest reported an unconstrained value.

The two digests differ because the two policies do, and they differ in the only
way that is also true: policy-a forwards to the image both guests run;
policy-b forwards to that and also to d79409cc…39592, which is sha384 of the
ASCII string "a TDX image this sandbox would also dial, which nothing in this
project has built". It is a launch measurement of the right width naming no
image anybody has, so B's policy is a different document from A's while both
still say the true thing about this pair. policy-a.json is byte-identical to
the one the image build emitted, which is why D_A is the image's own policy
digest. Under ticket 18 this pair could not have been authored at all: each
digest would have been taken over a document that had to contain the other
(docs/policy-binding.md).

Each digest was read three times and agreed three times — printed by
emit-refvals when it wrote the document, read back off the delivered document
by `emit-refvals -digest-of`, and read a third time off the console of the
guest carrying it. See digests.txt.

## What the consoles say

Both guests admitted the other:

  A: tunneld: PEER key=155b1e1a93247f98… chain=none measurement=d5ddcc423b1aed53… vendor=intel-tdx mrtd=c1ee9c16e3afc506… rtmr2=d5ddcc423b1aed53… tcb=UpToDate,evaluation=20
  B: tunneld: PEER key=6127250f6ac2cab8… chain=none measurement=d5ddcc423b1aed53… vendor=intel-tdx mrtd=c1ee9c16e3afc506… rtmr2=d5ddcc423b1aed53… tcb=UpToDate,evaluation=20

Neither logged a single REFUSED. Each answered the other's exchanges —
answered_by="guest-b" on A's console, answered_by="guest-a" on B's — and
neither exercise reported a failure.

## The re-attestation

max_age was 3m and the exercise ran eleven passes over eight minutes, 45s
apart. A pass that reuses a live tunnel costs no verifier call and establishes
in single-digit microseconds; a pass that finds the tunnel expired re-dials,
re-attests and costs one. Guest A:

  LATENCY pass=1  kind=establish ms=84.901 attempts=1 verifier_calls=1
  LATENCY pass=2  kind=establish ms=0.007  attempts=1 verifier_calls=0
  LATENCY pass=3  kind=establish ms=0.007  attempts=1 verifier_calls=0
  LATENCY pass=4  kind=establish ms=0.007  attempts=1 verifier_calls=0
  LATENCY pass=5  kind=establish ms=10.795 attempts=1 verifier_calls=1   <- re-attested
  LATENCY pass=6..8                        ms=0.007..0.008 verifier_calls=0
  LATENCY pass=9  kind=establish ms=10.354 attempts=1 verifier_calls=2   <- re-attested
  LATENCY pass=10,11                       ms=0.007 verifier_calls=0

Guest B's console shows the same shape at the same passes. Three verifications
per guest over the run, two of them after the first: the ticket asks for one
re-attestation captured and there are two apiece, and the lines that prove it
are pass=5 and pass=9, where verifier_calls goes back above zero and the
establishment costs a real handshake instead of a cache lookup.

## The self-checks are refused, and that is what mutual pinning means

Both guests print

  tunneld: SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not
    permitted by the reference value: attest: verification failed

and this is not a failure of the run. A reference value set says whom a guest
ADMITS. In a mutual arrangement that is the peer's (measurement, policy digest)
pair and not the guest's own, so a guest judging its own evidence against its
own set is refused on the digest — the measurement matches, and the registers
printed beside the refusal out of the quote's own bytes are the predicted ones.

The check that matters is the one the PEER makes, and this workstation made it
too, from the same quotes:

  guest A's quote against set-a (its own)   REFUSED, policy digest  (exit 2)
  guest A's quote against set-b (B's)       ACCEPTED                (exit 0)
  guest B's quote against set-b (its own)   REFUSED, policy digest  (exit 2)
  guest B's quote against set-a (A's)       ACCEPTED                (exit 0)

Four verdicts, each matching the corresponding console. See verify-evidence-a.txt
and verify-evidence-b.txt.

## The registers

Every register on both guests is the value this shape was pinned for
(measurements.txt): MRTD c1ee9c16…70a5, RTMR0 c2fc12a5…850a, RTMR1
02c7f19c…913b — the first-boot value, which is the expected one here because
this guest never runs Ubuntu's initramfs and so nothing ever grows the root —
and RTMR2 d5ddcc42…73e0d, which is the number predicted from the image bytes
before either machine existed. Neither RTMR0 nor RTMR1 moved on any boot.

## Files

  tunnel-run.txt          the run: documents authored, devices built, images
                          published, consoles watched, quotes verified, 55
                          named assertions and the count
  console-a.txt           guest A's whole serial console
  console-b.txt           guest B's
  digests.txt             the measurements and the two policy digests, with the
                          three-way agreement on each
  measurements.txt        every register each boot reported, predicted beside
                          quoted beside console
  set-a.json(+.sig)       the four signed documents as delivered
  set-b.json(+.sig)
  policy-a.json(+.sig)
  policy-b.json(+.sig)
  author.pub              the public half of the key that signed them, which is
                          inside both measurements
  config-src/a, config-src/b
                          each guest's config device as built, minus collateral/
                          — that directory is byte for byte
                          docs/snp/evidence/tdx/collateral, and each console
                          lists all ten of its files with their sha256
  quote-a.bin, quote-b.bin      the quotes, off the consoles
  quote-a.txt, quote-b.txt      parsed by docs/snp/cloud/tdx/parse-tdx-quote.py
  public-key-a.der, public-key-b.der
                          the throwaway keys the quotes are bound to
  verify-evidence-a.txt   both verdicts on guest A's quote, made here
  verify-evidence-b.txt   both verdicts on guest B's
  egress-a.txt, egress-b.txt    the rule set and every refusal (see ../egress/)

## One thing the consoles do not carry

Each console ends a few lines early. tunneld prints its peer summary — PEERS
and PEER SEEN, with the count of times each peer was verified — then its EXIT
status, then the initrd prints its own and calls `poweroff -f`, and those last
lines are written milliseconds before the machine stops. Compute Engine serves
an empty body for an instance that has stopped: the watch loop kept fetching
incrementally for ninety seconds after the stop and then read the whole buffer
once more, and got 0 bytes both ways. The same truncation is visible on the
smoke boot's console. Nothing turns on it — what the exercise did is on the
console in its own lines, and the verification count is in the LATENCY lines
above — but a reader looking for `EXIT status=` at the end will not find it.
