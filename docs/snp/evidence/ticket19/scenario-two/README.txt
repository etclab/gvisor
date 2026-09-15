Ticket 19, scenario two: one image, two policies, and a digest one guest does
not list.

Both guests boot the same image and run the same binary. The only thing that
differs between them is the policy on the config device — and guest A's
reference value set names a policy digest that guest B does not present. A
refuses B. B admits A. One direction only.

  instances   t19-two-a at 10.128.0.40, t19-two-b at 10.128.0.41
              c3-standard-4 TDX, us-central1-a, one 20GB boot disk from
              attested-tdx-d5ddcc423b1a and one 10GB config disk each
  created     2026-09-10T23:18Z          deleted 2026-09-10T23:25Z
  written by  docs/snp/cloud/tdx/run-tdx-scenario.sh two
  verdict     48 assertions, 48 passed, 0 failed (tunnel-run.txt)

## The documents

  D_A = d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b
  D_B = 444a4aa826ae40b5cc4332df842f0cea17e02a51f6d8f30f2385daf051561f28

  set-a.json admits measurement d5ddcc42…73e0d paired with D_A — guest A's OWN
             policy digest, which is a digest of a real signed document that
             guest B does not carry.
  set-b.json admits the same measurement paired with D_A, so B admits A.

The digest A lists is A's own rather than the digest of an invented string, and
that is deliberate. It makes A's self-check a positive control: A's set and A's
platform agree at the same moment A's set refuses the peer, so the machinery is
demonstrably intact when the refusal happens. Ticket 18's policy-mismatch run
had to reach for the same control by other means (docs/policy-binding.md).

## What the consoles say

Guest A refused guest B, naming the digest B presented, 180 times over the run:

  tunneld: REFUSED verification refused: guest policy or policy digest not permitted by the reference value: peer presents policy digest 444a4aa826ae40b5cc4332df842f0cea17e02a51f6d8f30f2385daf051561f28; no reference value for the measurement it is running lists that policy

Guest B admitted guest A, and refused nothing at all:

  tunneld: PEER key=15576ede988e8b67… chain=none measurement=d5ddcc423b1aed53… vendor=intel-tdx mrtd=c1ee9c16e3afc506… rtmr2=d5ddcc423b1aed53… tcb=UpToDate,evaluation=20

No tunnel was established in either direction and nothing was exchanged either
way. A's dial failed on A's own verdict, B's on the one A sent it:

  tunneld: exercise: pass=1 peer=guest-b FAILED: after 91 attempt(s) over 1m30s: tunneld: tunnel not established: "guest-b" at 10.128.0.41:4433: tunnel: dialing 10.128.0.41:4433: CRYPTO_ERROR 0x12a (local): attest: verification failed
  tunneld: exercise: pass=1 peer=guest-a FAILED: after 89 attempt(s) over 1m30s: tunneld: tunnel not established: "guest-a" at 10.128.0.40:4433: tunnel: dialing 10.128.0.40:4433: CRYPTO_ERROR 0x12a (remote): tls: bad certificate

That asymmetry is TLS 1.3's certificate ordering, and it is the same finding
ticket 18 recorded with the roles the other way round. The server's certificate
goes first, so on B's dials B judges A before A is asked for anything — B
admits, then A judges B, refuses, and aborts, and B sees a remote "bad
certificate". On A's own dials A meets B's certificate first and refuses
locally. A is therefore the party that judges B in both directions, which is
why A's refusal count is the sum of the two dial counts (180 = 91 + 89) while
B logged no refusal at all.

## The self-checks

Guest A's is ADMITTED — its set names its own pair — and this workstation
reaches the same verdict from A's quote. Guest B's is REFUSED on the policy
digest, because set-b names D_A and B presents D_B. All four workstation
verdicts match their consoles:

  guest A's quote against set-a (its own)   ACCEPTED                (exit 0)
  guest A's quote against set-b (B's)       ACCEPTED                (exit 0)
  guest B's quote against set-b (its own)   REFUSED, policy digest  (exit 2)
  guest B's quote against set-a (A's)       REFUSED, policy digest  (exit 2)

The last of those is the scenario's refusal, remade here by a verifier that
trusts none of the guests' machinery.

## The registers

Both guests reported MRTD c1ee9c16…70a5, RTMR0 c2fc12a5…850a, RTMR1
02c7f19c…913b (the first-boot value) and RTMR2 d5ddcc42…73e0d, the predicted
one. Neither RTMR0 nor RTMR1 moved. Both guests really are running the same
image, which is what makes the refusal a statement about the policy alone.

## Files

Same layout as scenario-one/README.txt describes, and the same note applies
about the last few console lines not surviving the guest's poweroff.
