# Cloud resources created by the TDX feasibility study

Running note so nothing is orphaned, in the shape of `docs/snp/cloud/RESOURCES.md` on the
cross-network branch. Project `nsf-2348130-428843`, zone `us-central1-a` unless stated.
Update on every create, stop and delete.

Everything this study creates carries the label `purpose=tdx-feasibility-probe`, so the
inventory can be checked against the provider with one command:

```sh
gcloud compute instances list --filter="labels.purpose=tdx-feasibility-probe"
```

**Not ours, and not touched:** `eval-vm`, `trusted-vm`, `trusted-vm-smh`, `untrusted-vm`,
`untrusted-vm-smh` from unrelated work, and `listener`, `relay` and the firewall rule
`attested-tunnel-udp-4433` from the cross-network run. All were TERMINATED before this study
started and were left that way.

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-08-31T20:47Z | tdx-probe-a, tdx-probe-b | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced | probes 1 and 2: two images, one shape (~$0.21/h each) | **deleted 20:51Z** (~4 min) |
| 2026-08-31T20:47Z | tdx-probe-c | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced | probe 3, run 1: one disk, three boots (mutation stage was not controlled; see probes-run1) | **deleted 21:04Z** (~17 min) |
| 2026-08-31T21:06Z | tdx-mutate | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced | probe 3 redone with reboot barrier and controls, plus attest/tsm built and run on Intel | **deleted 21:31Z** (~25 min, four boots) |
| 2026-08-31T21:33Z | tdx-eventlog | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced | probe 4, run 1: CCEL present; replay used a wrong register mapping (kept as eventlog-wrongmap) | **deleted 21:39Z** (~6 min) |
| 2026-08-31T21:41Z | tdx-eventlog | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced | probe 4, run 2: same probe with the MrIndex mapping corrected; the log replayed | **deleted 21:45Z** (~4 min) |
| 2026-09-08T18:07Z | rtmr2-helper (+ disk rtmr2-src, read-only, from image `ubuntu-2404-noble-amd64-v20260826`) | e2-standard-2 **non-TDX**, us-central1-a, 10GB debian-12 boot + the Ubuntu image as a second disk in `mode=ro` | ticket 16: obtain the image's bytes without booting them (`dd` of the read-only disk to the workstation, sha256 `d0b2b2c2…5474f`) | **deleted 18:17Z** (~10 min), disk deleted with it |
| 2026-09-08T18:16Z | tdx-upgrade | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, pinned image `ubuntu-2404-noble-amd64-v20260826` | ticket 16: four boots — baseline, `update-grub`, recordfail=1 in grubenv, kernel upgrade — quote+CCEL each, disk state tarball before each reboot (the kernel step installed nothing: wrong package name) | **deleted 18:24Z** (~8 min, four boots) |
| 2026-09-08T18:27Z | tdx-upgrade | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, pinned image `ubuntu-2404-noble-amd64-v20260826` | ticket 16 rerun, `-kernel-only`: baseline, then `apt-get install linux-image-gcp` and one boot on the new kernel (7.0.0-1011-gcp) | **deleted 18:30Z** (~3 min, two boots) |
| 2026-09-10T20:02Z | tdx-initrd | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, pinned image `ubuntu-2404-noble-amd64-v20260826` | ticket 19 step zero, run 1: baseline boot captured (RTMR2 `ecc99358…11df9`), then the probe stopped itself because it read `grub.cfg` without root and found no fs-uuid; nothing else done | **deleted 20:04Z** (~2 min, one boot) |
| 2026-09-10T20:05Z | tdx-initrd | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, pinned image `ubuntu-2404-noble-amd64-v20260826` | ticket 19 step zero, run 2: baseline boot (RTMR2 `ecc99358…11df9`, 86/86 MATCH), then one boot with an `initrd` line in grub.cfg (RTMR2 `d8f247b4…b1aa5`, 88/88 MATCH); attest/tsm acquirer run on Intel with no chain directory; platform UpToDate at evaluation 20 | **deleted 20:10Z** (~5 min, two boots) |

## Ticket 19: the attested tunnel guests

Ticket 19's resources carry a different label, `purpose=attested-tunnel-t19`, so that
the feasibility study's inventory and this one can be checked apart:

```sh
gcloud compute instances list --filter="labels.purpose=attested-tunnel-t19"
gcloud compute images    list --filter="labels.purpose=attested-tunnel-t19" --no-standard-images
```

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-10T21:24Z | tdx-smoke-a | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-d5ddcc423b1a` + 10GB pd-balanced config disk, `--private-network-ip 10.128.0.40` | ticket 19 smoke run 1: the guest booted, found its config device, installed and proved its egress policy, and was REFUSED by its own reference value on RTMR0 (`docs/snp/evidence/ticket19/smoke/run1-rtmr0-mismatch/`) | **deleted 2026-09-10T21:29Z** (~5 min) |
| 2026-09-10T21:34Z | tdx-rtmr0 (+ disk `tdx-rtmr0-probe-config`, 10GB) | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, stock image `ubuntu-2404-noble-amd64-v20260826` | ticket 19: why did RTMR0 move? Two boots of one instance, one disk then two. It moved: `c0b8b19c…896d` -> `a5e39b27…2b79` (`docs/snp/evidence/ticket19/rtmr0/`) | **deleted 2026-09-10T21:38Z** (~4 min, disk deleted with it) |
| 2026-09-10T21:44Z | tdx-smoke-a | as run 1, with the reference value's RTMR0 corrected | ticket 19 smoke run 2: the guest ran and powered itself off between two polls of the serial console and the transcript was lost; the loop now appends by byte offset instead of re-fetching | **deleted 2026-09-10T21:46Z** (~2 min) |
| 2026-09-10T21:49Z | tdx-smoke-a | as run 1 | ticket 19 smoke run 3, the one that counts: predicted RTMR2 `d5ddcc42…73e0d` = the register the hardware reported; self-check ADMITTED; five forbidden egress attempts refused; a tunnel established to itself through the whole attestation path (`docs/snp/evidence/ticket19/smoke/`) | **deleted 2026-09-10T21:51Z** (~2 min) |
| 2026-09-10T21:19Z | attested-tdx-d5ddcc423b1a | custom image, 10GiB, `purpose=attested-tunnel-t19` | ticket 19: the attested tunnel guest image on the pinned kernel 6.17.0-1022-gcp, predicted RTMR2 `d5ddcc42…73e0d` | **kept: the scenario runs boot from it** |
| 2026-09-10T21:55Z | attested-tdx-640de950bbdd | custom image, 10GiB, `purpose=attested-tunnel-t19` | ticket 19: the same guest on kernel 7.0.0-1011-gcp, predicted RTMR2 `640de950…14be7` — the different image scenario three needs | **kept: scenario three boots from it** |
| 2026-09-10T21:49Z | attested-config-tdx-smoke-a-20260910214749 | custom image, 1GiB, `purpose=attested-tunnel-t19` | ticket 19: the config device the smoke run booted with (signed set and policy, peer table, run config, addressing, Intel collateral) | **kept as the worked example a scenario config device copies** |
| 2026-09-10T21:24Z, 21:44Z | attested-config-tdx-smoke-a-20260910211919, -20260910214213 | custom images, 1GiB each | ticket 19: config devices for smoke runs 1 and 2, each carrying a reference value set that is now wrong | **deleted 2026-09-10T21:53Z** |
| 2026-09-10T21:19Z … 21:55Z | `attested-tunnel-t19-2026091021{1926,2253,4220,4755,5519}` | Cloud Storage buckets, us-central1, soft delete off | ticket 19: staging for `gcloud compute images create --source-uri`, which cannot take bytes any other way. Each holds one tarball for the length of one image create | **each created and deleted inside the run that made it; none survives** |
| 2026-09-10T22:24Z | t19-one-a, t19-one-b | c3-standard-4 TDX each, us-central1-a, 20GB pd-balanced boot from `attested-tdx-d5ddcc423b1a` + 10GB pd-balanced config disk, `--private-network-ip 10.128.0.40` and `.41` | ticket 19 scenario one, run 1: the pair that pins each other. Both admitted, both exchanged, three verifications apiece over eleven passes. 51 of 55 assertions passed; the four that did not were the harness reading a refusal through `go run` (which exits 1 whatever the program exits with) and asserting on console lines the guest's poweroff takes with it | **deleted 2026-09-10T22:36Z** (~12 min) |
| 2026-09-10T22:41Z | t19-two-a, t19-two-b | as above, both from `attested-tdx-d5ddcc423b1a` | ticket 19 scenario two, run 1: A refused B on the policy digest 181 times, B admitted A and refused nothing. 46 of 50 assertions; the same four harness faults | **deleted 2026-09-10T22:49Z** (~8 min) |
| 2026-09-10T22:55Z | t19-three-a, t19-three-b | as above, A from `attested-tdx-d5ddcc423b1a`, B from `attested-tdx-640de950bbdd` | ticket 19 scenario three, run 1, **superseded**: A's set had been authored from the measurement its peer actually reports rather than the one it expects, so A admitted the 7.0 guest and the scenario tested nothing. The bug and the fix are in `run-tdx-scenario.sh` | **deleted 2026-09-10T23:01Z** (~6 min) |
| 2026-09-10T23:07Z | t19-three-a, t19-three-b | as above | ticket 19 scenario three, the run that counts: A refused B 151 times naming RTMR2 `640de950…14be7` against the `d5ddcc42…73e0d` its value predicts, B admitted A on the same handshake. 49 of 49 (`docs/snp/evidence/ticket19/scenario-three/`) | **deleted 2026-09-10T23:14Z** (~7 min) |
| 2026-09-10T23:18Z | t19-two-a, t19-two-b | as above, both from `attested-tdx-d5ddcc423b1a` | ticket 19 scenario two, the run that counts: A refused B 180 times on the policy digest, B admitted A, A's own self-check ADMITTED as the local control. 48 of 48 (`docs/snp/evidence/ticket19/scenario-two/`) | **deleted 2026-09-10T23:25Z** (~7 min) |
| 2026-09-10T23:29Z | t19-one-a, t19-one-b | as above, both from `attested-tdx-d5ddcc423b1a` | ticket 19 scenario one, the run that counts: both directions admitted, eleven passes over eight minutes with a maximum age of three, two re-attestations apiece captured in the LATENCY lines. 55 of 55 (`docs/snp/evidence/ticket19/scenario-one/`) | **deleted 2026-09-10T23:42Z** (~13 min) |
| 2026-09-10T22:20Z … 23:28Z | `attested-config-t19-{one,two,three}-{a,b}-<stamp>`, twelve in all | custom images, 1GiB each, `purpose=attested-tunnel-t19` | ticket 19: one config device per guest per run — a signed set and policy each, peer table, run config, addressing, Intel collateral. Never reused between runs, because the documents are what the scenarios vary | **each deleted at the end of the run that made it; none survives** |
| 2026-09-10T22:20Z … 23:28Z | `attested-tunnel-t19-<stamp>`, twelve in all | Cloud Storage buckets, us-central1, soft delete off | ticket 19: staging for the twelve config-device image creates | **each created and deleted inside the run that made it; none survives** |

Ticket 19 state after the image work, 2026-09-10T21:56Z: **no instance and no disk left, no bucket left.** Four
instances were created over about half an hour and all four were deleted, the longest-lived
at roughly five minutes. What survives on purpose is three custom images — two guest images
the scenario runs boot from and one config device to copy — and they survive because the
scenario runs would otherwise have to upload ten gibibytes again to get back to where this
ticket left off. `gcloud compute disks list` is empty of this ticket's names; the only
storage is the images.

Ticket 19 state after the three scenarios, 2026-09-10T23:44Z: **no instance, no
disk and no bucket left.** Twelve more instances were created over about eighty
minutes, in six pairs, and all twelve were deleted; the longest-lived was
scenario one's final pair at about thirteen minutes, because that is the one
scenario whose point is a run long enough to re-attest in the middle of itself.
Three of the six pairs were superseded and are kept in the ledger anyway: two by
harness faults that changed no evidence, and one — scenario three's first pair —
by a real authoring mistake that made the scenario vacuous and had to be redone.
Twelve config-device images and twelve staging buckets were created and deleted
inside the runs that made them.

What survives, on purpose, is the same three custom images the image work left:
`attested-tdx-d5ddcc423b1a`, `attested-tdx-640de950bbdd` and
`attested-config-tdx-smoke-a-20260910214749`. `gcloud compute instances list
--filter=labels.purpose=attested-tunnel-t19` is empty, `gcloud compute disks
list` holds none of this ticket's names, and the only storage is those three
images. Total machine time across the scenarios is about 106 instance-minutes of
`c3-standard-4` TDX, well under a dollar. No firewall rule, network, IAM policy
or org policy was created or changed: intra-VPC UDP 4433 is carried by the
pre-existing `default-allow-internal` rule (priority 65534, source 10.128.0.0/9),
and the port is 4433 because that is the one the project's existing
`attested-tunnel-udp-4433` rule opens.

Final state, 2026-08-31T21:45Z: **nothing left running, nothing orphaned.** Six instances were
created over about an hour and all six were deleted; the longest-lived was `tdx-mutate` at
roughly 25 minutes, because it had to cross four boots. No disks survived their instances
(every one was a boot disk with auto-delete). `gcloud compute instances list` afterwards shows
only the seven pre-existing TERMINATED instances this study never touched, and
`gcloud compute disks list --filter="name~tdx"` is empty.

Total machine time is about 62 instance-minutes of `c3-standard-4` (~$0.20/h on-demand in
us-central1), so the whole study cost well under a dollar of compute. No firewall rule, no
network, no IAM and no org policy was created or changed.
