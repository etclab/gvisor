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
| 2026-09-08T18:27Z | tdx-upgrade | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced, pinned image `ubuntu-2404-noble-amd64-v20260826` | ticket 16 rerun, `-kernel-only`: baseline, then `apt-get install linux-image-gcp` and one boot on the new kernel (7.0.0-1011-gcp) | **deleted 18:36Z** (~9 min, two boots) |

Final state, 2026-08-31T21:45Z: **nothing left running, nothing orphaned.** Six instances were
created over about an hour and all six were deleted; the longest-lived was `tdx-mutate` at
roughly 25 minutes, because it had to cross four boots. No disks survived their instances
(every one was a boot disk with auto-delete). `gcloud compute instances list` afterwards shows
only the seven pre-existing TERMINATED instances this study never touched, and
`gcloud compute disks list --filter="name~tdx"` is empty.

Total machine time is about 62 instance-minutes of `c3-standard-4` (~$0.20/h on-demand in
us-central1), so the whole study cost well under a dollar of compute. No firewall rule, no
network, no IAM and no org policy was created or changed.
