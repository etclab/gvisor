# Where the two values in this set came from

`reference-values.json` here admits two launch measurements, one per peer of the mixed run, and
they were arrived at in two different ways. The spec forbids one of the ways as the means of
producing a reference value — "a measurement learned by asking the machine is not a prediction,
and a test built on one cannot fail" — so this file says which is which. The set is signed by the
author key inside the shs1 image (`image-cloud-packaging/author.key`; public half
`b3bb138d…7ef9`, baked into that image at `/etc/attested-tunnel/author.pub` and handed to the
cloud tunneld as `-author`). The TCB floors and policy bits are real and ours.

## Value 1: `0ecf8f32…98a5` — the measured image on shs1

**A prediction.** Ticket 07's `predict-measurement.sh`, from the build inputs of
`$STACK/image-cloud` (OVMF, kernel, initrd, command line, 4 vCPUs of EPYC-v4, policy 0x30000),
computed offline before any guest was launched. `docs/snp/evidence/cloud/packaging.txt` and
`manifest.txt` record it. Floor 9/0/23/72 is what this host's chain was provisioned at.

## Value 2: `2d24cf96…c773` — Google's firmware on an n2d-standard-2

**Not a prediction; two things short of one.**

1. It was **read off a booted VM** — two of them, in fact: `probes/probe-a` (Ubuntu 24.04) and
   `probes/probe-b` (Ubuntu 22.04) reported the same value, which is what established that the
   measurement is over the provider's firmware and not the boot disk.
2. It **matches Google's own signed launch endorsement** for that firmware,
   `probes/endorsement-2d24cf96….binarypb`, fetched from
   `https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/<M>.binarypb`. The
   endorsement's signature verifies to Google's published root
   (`https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt`, kept beside it) with
   `gcetcbendorsement verify`, exit status 0 — `probes/endorsement-2d24cf96….txt` is the record.
   It says: UEFI digest `759990ee…04bf`, SVN 2, signed 2026-03-12, and a table of SEV-SNP
   measurements keyed by vCPU count in which key **2** is exactly this value. An n2d-standard-2
   has two vCPUs. (The endorsement's expected policy is `0x70000`, which additionally allows a
   migration agent; the VMs actually reported `0x30000`, and the floor here is the stricter one.)

So the value is authorised by the provider's signature over their firmware rather than by our
prediction from inputs we control. That is the better of the two options the plan named and
it is still not ticket 07's: nobody here can rebuild that firmware and recompute the number,
Google's endorsement says what the firmware measures to and nothing about what boots after it,
and admitting this value admits *any* two-vCPU SEV-SNP VM Google boots from that firmware.
A mixed federation has the granularity of that member.
