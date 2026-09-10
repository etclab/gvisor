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

Ticket 19 state, 2026-09-10T21:56Z: **no instance and no disk left, no bucket left.** Four
instances were created over about half an hour and all four were deleted, the longest-lived
at roughly five minutes. What survives on purpose is three custom images — two guest images
the scenario runs boot from and one config device to copy — and they survive because the
scenario runs would otherwise have to upload ten gibibytes again to get back to where this
ticket left off. `gcloud compute disks list` is empty of this ticket's names; the only
storage is the images.

Final state, 2026-08-31T21:45Z: **nothing left running, nothing orphaned.** Six instances were
created over about an hour and all six were deleted; the longest-lived was `tdx-mutate` at
roughly 25 minutes, because it had to cross four boots. No disks survived their instances
(every one was a boot disk with auto-delete). `gcloud compute instances list` afterwards shows
only the seven pre-existing TERMINATED instances this study never touched, and
`gcloud compute disks list --filter="name~tdx"` is empty.

Total machine time is about 62 instance-minutes of `c3-standard-4` (~$0.20/h on-demand in
us-central1), so the whole study cost well under a dollar of compute. No firewall rule, no
network, no IAM and no org policy was created or changed.
