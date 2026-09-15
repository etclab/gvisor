Ticket 19, scenario three: the same pair, and one guest booted from a different
kernel.

Everything about this run is scenario one — the same two policies, the same two
reference value sets, the same addresses, the same author key — except that
guest B boots the image built on kernel 7.0.0-1011-gcp instead of
6.17.0-1022-gcp. One variable. Guest A's set was authored to admit guest B and
admits nothing else; B's register is not the one it predicts, and A refuses it
on that register by name.

  instances   t19-three-a at 10.128.0.40, boot image attested-tdx-d5ddcc423b1a
              t19-three-b at 10.128.0.41, boot image attested-tdx-640de950bbdd
              c3-standard-4 TDX, us-central1-a, one 20GB boot disk and one 10GB
              config disk each
  created     2026-09-10T23:07Z          deleted 2026-09-10T23:14Z
  written by  docs/snp/cloud/tdx/run-tdx-scenario.sh three
  verdict     49 assertions, 49 passed, 0 failed (tunnel-run.txt)

## The documents

  D_A = d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b
  D_B = 444a4aa826ae40b5cc4332df842f0cea17e02a51f6d8f30f2385daf051561f28

  set-a.json admits measurement d5ddcc42…73e0d — the 6.17 image — paired with
             D_B, which is guest B's policy digest. Every field of that value
             was authored to admit guest B. Only the image is wrong.
  set-b.json admits the same measurement paired with D_A, so B admits A.

## What the consoles say

Guest A refused guest B 151 times, and the refusal names the register that
disagreed and the value the reference value predicts:

  tunneld: REFUSED verification refused: launch measurement not in the reference value set: the TD's RTMR2 is 640de950bbdde9300d2092da28885ec6455acdc3b6df99ea847d02d5cf7c99d86724bb4dff41bb037c4f212f33414be7, and this reference value predicts d5ddcc423b1aed530237a6c43b3005d317464a94217dd9477f113007379dbf0fc7601cac8fa69bb48a4efd4322c73e0d

Guest B admitted guest A on the same handshake:

  tunneld: PEER key=6e4fad2c93a09b2a… chain=none measurement=d5ddcc423b1aed53… vendor=intel-tdx mrtd=c1ee9c16e3afc506… rtmr2=d5ddcc423b1aed53… tcb=UpToDate,evaluation=20

That is this scenario's local control. The wiring, the collateral, the binding
and the author key are all demonstrably working at the moment A refuses B, so
the refusal is about the image and nothing else. No tunnel in either direction,
nothing exchanged, both exercises reported a failure.

Guest B's own self-check is refused for the matching reason — its set names the
6.17 measurement and B is running the 7.0 one:

  tunneld: SELFCHECK VERDICT REFUSED reason=launch measurement not in the reference value set: attest: verification failed

and guest A's is refused on the policy digest, as in scenario one, because
set-a names B's digest rather than A's own.

## The workstation's verdicts

  guest A's quote against set-b (B's)       ACCEPTED                (exit 0)
  guest B's quote against set-a (A's)       REFUSED, measurement    (exit 2)

The second is the scenario, remade here from B's own quote against the set A
was carrying.

## An address in the peer table that no machine has

Guest A's peer table names a third peer, `outsider` at 10.128.0.42:4433, to ask
what tunneld's own dialer does with a peer the rules do not except. It turns
out the question cannot be put that way, and the reason is the finding:

  tunneld: exercise: pass=1 peer=outsider FAILED: after 11 attempt(s) over 1m0s: tunneld: tunnel not established: "outsider" at 10.128.0.42:4433: tunnel: dialing 10.128.0.42:4433: timeout: no recent network activity

A timeout, not a rule refusal. The rule set is generated from the peer table
and the listen port, not from the policy — a policy's forward_to names
measurements and a measurement is not an address — so every address in the peer
table is excepted by construction, this one included (`ip daddr 10.128.0.42 …
udp dport 4433 accept` is in A's installed rule set, in egress-a.txt). The
packets left and nothing answered. ../egress/README.txt works through what that
means for the two mechanisms and for Milestone 4.

## The registers

  guest A  RTMR2 d5ddcc42…73e0d  (predicted for the 6.17 image)
  guest B  RTMR2 640de950…14be7  (predicted for the 7.0 image)

Both predicted from the image bytes before either machine existed, and both are
exactly what the hardware reported. MRTD, RTMR0 and RTMR1 are identical on the
two guests and identical to every other boot in this ticket — c1ee9c16…70a5,
c2fc12a5…850a and the first-boot 02c7f19c…913b — which is the point: the two
images differ in the kernel and in nothing else, and RTMR2 is the only register
that noticed.

## Files

Same layout as scenario-one/README.txt describes, and the same note applies
about the last few console lines not surviving the guest's poweroff.
