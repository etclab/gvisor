Ticket 19, milestone 3b: two attested guests on Google Cloud TDX.

This directory holds what the runs produced, in the order the ticket did them.
Nothing here was edited by hand; the scripts that wrote each part are named
beside it. The record that reads all of it, and says which of ticket 14's
eleven criteria hold here and which do not, is docs/two-guests-on-tdx.md.

  step-zero/   Before any image work: does predict-rtmr2.py's initrd path
               survive a boot that actually loads an initrd? Two boots of one
               throwaway VM, the second with one `initrd` line added to the
               stock grub.cfg, both predicted from the disk bytes and both
               MATCH (88 records of 88 on the initrd boot).
               Written by docs/snp/cloud/tdx/probe-tdx-initrd.sh.

  images/      The two images this ticket builds, as everything about them
               except their ten gibibytes: the manifest, the packaging
               transcript, the exact grub.cfg installed, the predictor's full
               output, the initrd's contents list, and the two signed documents
               the build emitted.
               Written by docs/snp/cloud/tdx/build-tdx-image.sh.

                 image-a  the pinned image's own kernel, 6.17.0-1022-gcp
                          predicted RTMR2 d5ddcc42…73e0d
                 image-b  the same guest on 7.0.0-1011-gcp, unpacked from the
                          Ubuntu kernel package; the image scenario three needs,
                          which differs from image-a in the kernel and in
                          nothing else
                          predicted RTMR2 640de950…14be7

               Both were rebuilt at least twice and predicted the same RTMR2
               each time. The disk images themselves are NOT bit-reproducible —
               ext4 puts the rewritten files in different blocks from run to run
               — and that does not matter: what grub opens is identical, so the
               register is identical. The disk.raw of each is out of the tree
               (.gitignore) and published as a Compute Engine image instead
               (RESOURCES.md).

  rtmr0/       Why the first guest was refused by its own reference value, and
               what the answer means for authoring one. Every RTMR0 recorded
               before this ticket was c0b8b19c…896d, on VMs that all had exactly
               one disk; the first guest with a config device attached reported
               c2fc12a5…850a. This probe changed one thing on one instance —
               attached a second disk and rebooted — and watched RTMR0 move.
               RTMR0 is a function of the machine's SHAPE, not only of the
               provider's firmware, and a reference value has to pin the value
               the shape it is authored for reports.
               Written by docs/snp/cloud/tdx/probe-tdx-rtmr0.sh.

  smoke/       One guest of the real shape, booted from image-a with a config
               device, on TDX hardware. The console is the record: the initrd's
               module loads, the config device found and mounted read-only, the
               address and routes, the egress rule set as the signed policy
               implies it and as the kernel holds it, five attempts at forbidden
               egress all refused, tunneld's start, its self-check, and a tunnel
               it established to itself through the whole attestation path.
               The quote it printed on the console is here as quote.bin and was
               judged again on the workstation by attest/cmd/verify-evidence
               (verify-evidence.txt): ACCEPTED.
               Written by docs/snp/cloud/tdx/smoke-tdx-guest.sh.

                 run1-rtmr0-mismatch/  the first attempt, kept because it is the
                                       observation the rtmr0/ probe went and
                                       explained. Its console is partial: the
                                       loop that fetched it re-fetched the whole
                                       buffer each pass and Compute Engine
                                       returns an empty one for an instance that
                                       has stopped, so the transcript was erased
                                       at the moment the guest finished. The
                                       loop now appends by byte offset.

The one number that had to be predicted rather than observed is RTMR2, and it
was:

  predicted from the image, before the boot : d5ddcc423b1aed530237a6c43b3005d3
                                              17464a94217dd9477f113007379dbf0f
                                              c7601cac8fa69bb48a4efd4322c73e0d
  reported by the hardware, in the quote    : the same

The author key that signed both documents is a throwaway, as every run in this
project so far has used (spec, Out of Scope: key custody). It is NOT in the
tree; it is at

  .scratch/attested-secure-tunnel/host-stack/image-ticket19-tdx/author.key

and its public half — 665053d10032f5b9a46394a65b022c0bd7007392b8f445fe4ace5b0e5ed4c5a2 —
is inside both images at /etc/attested-tunnel/author.pub, which means it is
inside RTMR2. Signing the scenarios' documents with a different key would need
new images and new measurements.
