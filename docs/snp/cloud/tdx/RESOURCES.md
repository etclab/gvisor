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

## Ticket 24: runsc inside the measured guest (experiment E4)

Ticket 24's TDX resources carry the label `purpose=attested-tunnel-t24`, so this run's
inventory can be checked apart from ticket 19's and from the feasibility study's:

```sh
gcloud compute instances list --zones us-central1-a --filter="labels.purpose=attested-tunnel-t24"
gcloud compute images    list --no-standard-images --filter="labels.purpose=attested-tunnel-t24"
```

The three images ticket 19 kept — `attested-tdx-d5ddcc423b1a`, `attested-tdx-640de950bbdd`
and `attested-config-tdx-smoke-a-20260910214749` — were not touched by this run, and neither
were the seven pre-existing instances. Everything below was created and deleted inside the
same hour. This is the first TDX guest in the project with **three** disks (boot, config and
workload), which is a machine shape whose RTMR0 nobody has measured
(`docs/snp/evidence/ticket19/rtmr0/`); the row says what it reported, and no value read off
this machine was written into any reference value or build parameter.

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-18T10:02Z | tdx-t24-a | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-cd68e874bbfb` + 10GB pd-balanced config disk from `attested-config-tdx-t24-a-20260918095609` + 10GB pd-balanced **workload** disk from `attested-workload-tdx-t24-a-20260918095609` (`device-name attested-workload`), `--private-network-ip 10.128.0.40` | ticket 24 E4, boot 1, **inconclusive and not the design's fault**: the run's new `LABEL` knob (the Compute Engine resource label) leaked into `mkconfigdev-tdx.sh`, whose `LABEL` is the ext4 volume label, so the config device was written `purpose=attested` and the guest halted after 30 seconds looking for `attested-config`. Nothing about runsc, the workload disk or the measurement was reached. `smoke-tdx-guest.sh` now unsets `LABEL` for that one call (`docs/snp/evidence/ticket24/spikes/E4/boot-1/`) | **deleted 2026-09-18T10:06Z** (~4 min) |
| 2026-09-18T10:11Z | tdx-t24-a | as above, with the config device's volume label written correctly; config and workload images `attested-{config,workload}-tdx-t24-a-20260918100827` | ticket 24 E4, boot 2, the run that counts. **RTMR2 predicted offline nine minutes earlier is the register the hardware reported**, `cd68e874…f6e25`, and MRTD and RTMR1 are the pinned provider constants. The guest and this workstation both REFUSED it, and both on RTMR0 alone: this is the project's first three-disk TDX guest and it reports `8ee4fa36…b70a3f`, which the set (authored for the two-disk shape) does not list. runsc did **not** run the bundle: it reached the sandbox and the sandbox died, exit 128 (`docs/snp/evidence/ticket24/spikes/E4/boot-2/`) | **deleted 2026-09-18T10:15Z** (~4 min) |
| 2026-09-18T09:56Z | attested-config-tdx-t24-a-20260918095609, attested-workload-tdx-t24-a-20260918095609 | custom images, 1GiB each, `purpose=attested-tunnel-t24` | ticket 24: boot 1's config and workload devices; the config one carries the wrong volume label | **deleted 2026-09-18T10:08Z** |
| 2026-09-18T09:59Z | attested-tdx-cd68e874bbfb | custom image, 10GiB, `purpose=attested-tunnel-t24` | ticket 24: the guest image with runsc in the initrd, predicted RTMR2 `cd68e874…f6e25`. Published once and reused by boot 2 rather than uploaded again | **deleted 2026-09-18T10:16Z** |
| 2026-09-18T10:08Z | attested-config-tdx-t24-a-20260918100827, attested-workload-tdx-t24-a-20260918100827 | custom images, 1GiB each, `purpose=attested-tunnel-t24` | ticket 24: boot 2's config and workload devices | **deleted 2026-09-18T10:16Z** |
| 2026-09-18T09:56Z … 10:10Z | `attested-tunnel-t19-20260918{095615,095930,100112,100833,101018}`, five in all | Cloud Storage buckets, us-central1, soft delete off | ticket 24: staging for the five image creates across the two boots. The *name* still carries t19 because it is `publish-tdx-image.sh`'s default and this ticket did not change that script; the *labels* are `purpose=attested-tunnel-t24` | **each created and deleted inside the run that made it; none survives** |

State after E4, 2026-09-18T10:16:31Z: **no instance, no disk, no image and no bucket of this
ticket's survives.** Two instances were created, at 10:02Z and 10:11Z, and both were deleted the
same hour, at 10:06Z and 10:15Z — about eight `c3-standard-4` TDX instance-minutes in all, the
longest-lived at roughly four minutes. All five images this ticket published were deleted; unlike
ticket 19, none was kept, because ticket 24's image is an experiment and not something a later
run boots from. The confirmations, as the commands printed them, are in
`docs/snp/evidence/ticket24/spikes/E4/teardown.txt`: `gcloud compute images list
--no-standard-images` shows only ticket 19's three kept images, `gcloud compute instances list
--zones us-central1-a` shows only the seven pre-existing TERMINATED instances, `gcloud compute
disks list --filter="name~t24"` is empty, and both `--filter=labels.purpose=attested-tunnel-t24`
listings are empty. No firewall rule, network, IAM or org policy was created or changed, and
nothing pre-existing was touched.

### Boot 3, after E5's fix (2026-09-18)

E5 found why boot 2's sandbox died — `pivot_root` cannot move a root mount with no parent,
and on TDX the root is the initramfs — and the fix went into `docs/snp/cloud/tdx/init.tdx`.
That is a new `/init` inside the measured initrd, so it is a new image with a new predicted
RTMR2, and one more instance was needed to ask the hardware about it. Created and deleted
inside the same hour, like everything above, and **this run observed the three-disk RTMR0 a
second time and authored it nowhere.**

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-18T10:59Z | tdx-t24-b | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-038e7905a285` + 10GB pd-balanced config disk from `attested-config-tdx-t24-b-20260918105245` + 10GB pd-balanced **workload** disk from `attested-workload-tdx-t24-b-20260918105245` (`device-name attested-workload`), `--private-network-ip 10.128.0.40` | ticket 24 E4, boot 3, the run with E5's fix in the measured `/init`. **RTMR2 predicted offline eight minutes earlier is the register the hardware reported**, `038e7905…a0b78`, 25 records, and **the workload ran**: `Linux workload 4.19.0-gvisor …`, exit 0, 0.08 s, then tunneld started and acquired 8000 bytes of Intel TDX evidence in 41 ms. The guest and this workstation both REFUSED it, and again on RTMR0 alone: the three-disk shape reports `8ee4fa36…b70a3f` and the set (authored for two disks) lists only `c2fc12a5…850a` (`docs/snp/evidence/ticket24/spikes/E4/boot-3/`) | **deleted 2026-09-18T11:02Z** (~3 min) |
| 2026-09-18T10:52Z | attested-tdx-038e7905a285 | custom image, 10GiB, `purpose=attested-tunnel-t24` | ticket 24: image-b, the guest image with E5's fix in `/init`, predicted RTMR2 `038e7905…a0b78`. One record of twenty-five moved against image-a and it is the initrd's own digest | **deleted 2026-09-18T11:03Z** |
| 2026-09-18T10:52Z | attested-config-tdx-t24-b-20260918105245, attested-workload-tdx-t24-b-20260918105245 | custom images, 1GiB each, `purpose=attested-tunnel-t24` | ticket 24: boot 3's config and workload devices. The workload device is boot 2's file byte for byte (`ae7e6208…8406`), so all three boots and both vendors ran the same bundle | **deleted 2026-09-18T11:03Z** |
| 2026-09-18T10:52Z … 10:57Z | `attested-tunnel-t19-20260918{105251,105554,105728}`, three in all | Cloud Storage buckets, us-central1, soft delete off | ticket 24: staging for boot 3's three image creates. The *name* still carries t19 because it is `publish-tdx-image.sh`'s default and this ticket did not change that script; the *labels* are `purpose=attested-tunnel-t24` | **each created and deleted inside the run that made it; none survives** |

State after boot 3, 2026-09-18T11:03:47Z: **no instance, no disk, no image and no bucket of
this ticket's survives.** Three instances in all were created by ticket 24 — 10:02Z, 10:11Z
and 10:59Z — and all three were deleted the same hour they were created, at 10:06Z, 10:15Z
and 11:02Z: about **eleven** `c3-standard-4` TDX instance-minutes, the longest-lived at
roughly four. All eight images this ticket published were deleted and none was kept,
because ticket 24's images are experiments and not something a later run boots from. The
confirmations, as the commands printed them, are appended to
`docs/snp/evidence/ticket24/spikes/E4/teardown.txt`: `gcloud compute images list
--no-standard-images` shows only ticket 19's three kept images
(`attested-tdx-d5ddcc423b1a`, `attested-tdx-640de950bbdd`,
`attested-config-tdx-smoke-a-20260910214749`), `gcloud compute instances list --zones
us-central1-a` shows only the seven pre-existing TERMINATED instances, `gcloud compute
disks list --filter="name~t24"` is empty, both `--filter=labels.purpose=attested-tunnel-t24`
listings are empty, and the only bucket is the unrelated pre-existing `bucket-sep-25`. No
firewall rule, network, IAM or org policy was created or changed, and nothing pre-existing
was touched.

E5 itself created nothing: it is eight boots of a local QEMU on the workstation
(`docs/snp/evidence/ticket24/spikes/E5/`), no cloud resource and no sudo.

## Ticket 26: the sandbox honours a pushed policy

Two guests, and for the first time on this branch a **three-disk** shape whose
RTMR0 the reference value set names: a 20 GB boot disk from the ticket 26 image,
a 10 GB config device and a 10 GB workload device carrying the OCI bundle. Ticket
24 observed `8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f`
twice and authored it nowhere, so every guest of that shape was refused; ticket
26 authors it deliberately in `build-tdx-image.sh` and `emit-tdx-documents.sh`,
and `docs/snp/evidence/ticket26/tdx/RTMR0-DECISION.md` is the decision and the
argument for it.

Everything this ticket creates carries `purpose=attested-tunnel-t26`, so the
inventory can be checked against the provider with one command:

```sh
gcloud compute instances list --filter="labels.purpose=attested-tunnel-t26"
```

`docs/snp/cloud/tdx/run-tdx-t26.sh` prints the rows below already filled in, at
the end of every run and in `-dry-run`. A person writes them here: on create with
the timestamp, and again on delete with the state in bold, because a script that
edited this file would be claiming an instance was gone before the delete
returned. `docs/snp/evidence/ticket26/tdx/RUNBOOK.md` §9 is the discipline.

**Not ours, and not touched:** `eval-vm`, `listener`, `relay`, `trusted-vm`,
`trusted-vm-smh`, `untrusted-vm` and `untrusted-vm-smh`, and the firewall rule
`attested-tunnel-udp-4433`, exactly as every ticket before this one left them.

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-18T21:06Z | t26-policy-a | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-7f7c43153cab` + 10GB pd-balanced config disk from `attested-config-t26-a-20260918205702` + 10GB pd-balanced **workload** disk from `attested-workload-t26-20260918205702` (`device-name attested-workload`), `--private-network-ip 10.128.0.40`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 1, guest A: the sandbox to be narrowed mid-fetch and killed at 150 s. **The guest booted, attested and reported the three-disk RTMR0 this ticket authored; its sandbox never started.** `runsc` died on `open /config/tunnel-table.json: permission denied` — `mkconfigdev-tdx.sh` did not chown the device's inodes to root, so the table belonged to an id the workload's user namespace does not map (`docs/snp/evidence/ticket26/tdx/run/console-a.txt:776`) | **deleted 2026-09-18T21:17Z** (~11 min) |
| 2026-09-18T21:06Z | t26-policy-b | the same three-disk shape, config disk `attested-config-t26-b-20260918205702`, `--private-network-ip 10.128.0.41`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 1, guest B: the second pusher (narrow-after 40 s), killed at 210 s. The same failure, and its second tunneld started and pushed as asked | **deleted 2026-09-18T21:17Z** (~11 min) |
| 2026-09-18T21:06Z | attested-tdx-7f7c43153cab | custom image, 10 GiB, `purpose=attested-tunnel-t26` | ticket 26 boot pair 1: the guest image, predicted RTMR2 `7f7c4315…04aa1`, which is what both guests reported | **deleted 2026-09-18T21:17Z, with the run** |
| 2026-09-18T21:06Z | attested-config-t26-{a,b}-20260918205702, attested-workload-t26-20260918205702 | custom images, 1 GiB each, `purpose=attested-tunnel-t26` | ticket 26 boot pair 1: the two config devices and the workload device (one bundle, attached to both guests) | **each deleted 2026-09-18T21:17Z, with the run** |
| 2026-09-18T20:57Z … 21:06Z | `attested-tunnel-t19-20260918{205702,205855,210124,210437}`, four in all | Cloud Storage buckets, us-central1 | ticket 26 boot pair 1: staging for the four image publishes. The *name* still carries t19 because it is `publish-tdx-image.sh`'s default and this ticket did not change that script; the *labels* are `purpose=attested-tunnel-t26` | **each created and deleted inside the publish that made it; none survives** |

**State after boot pair 1, 2026-09-18T21:17Z**, confirmed at 23:12Z by
`gcloud compute instances list --zones us-central1-a` (only the seven
pre-existing TERMINATED instances) and
`gcloud compute instances list --filter="labels.purpose=attested-tunnel-t26"`
(`Listed 0 items.`): **nothing of this pair survives.** Two `c3-standard-4` TDX
instances existed for about eleven minutes each — about **22 instance-minutes** —
and both were deleted the same hour they were created. Four custom images and
four buckets were created and deleted inside the same run.

### Boot pair 2, with boot pair 1's two faults fixed in the harness

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-18T23:25Z | t26-policy-a | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-7f7c43153cab` + 10GB pd-balanced config disk from `attested-config-t26-a-20260918231703` + 10GB pd-balanced **workload** disk from `attested-workload-t26-20260918231703` (`device-name attested-workload`), `--private-network-ip 10.128.0.40`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 2, guest A: the sandbox narrowed mid-fetch and killed at 150 s. Boot pair 1's two faults are fixed in the harness: the config device's inodes are root-owned, and both sets admit the ceiling digest a guest of this image actually presents. **This is the pair the ticket's TDX item rests on** — `=== 69 passed, 5 failed ===`, both quotes reporting the three-disk RTMR0, each admitted by the peer's set, both sandboxes under a pushed policy, both controls, the narrowing, and the liveness teardown | **deleted 2026-09-18T23:37Z** (~12 min) |
| 2026-09-18T23:25Z | t26-policy-b | the same three-disk shape, config disk `attested-config-t26-b-20260918231703`, `--private-network-ip 10.128.0.41`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 2, guest B: the second pusher (narrow-after 40 s), killed at 210 s | **deleted 2026-09-18T23:37Z** (~12 min) |
| 2026-09-18T23:17Z | attested-tdx-7f7c43153cab | custom image, 10 GiB, `purpose=attested-tunnel-t26` | ticket 26 boot pair 2: the same guest image as pair 1, republished after pair 1 deleted it; predicted RTMR2 `7f7c4315…04aa1`, which is what both guests reported | **deleted 2026-09-18T23:37Z, with the run** |
| 2026-09-18T23:17Z | attested-config-t26-{a,b}-20260918231703, attested-workload-t26-20260918231703 | custom images, 1 GiB each, `purpose=attested-tunnel-t26` | ticket 26 boot pair 2: the two config devices (now root-owned inside) and the workload device | **each deleted 2026-09-18T23:37Z, with the run** |
| 2026-09-18T23:17Z … 23:23Z | `attested-tunnel-t19-20260918{231728,232023,232159,232330}`, four in all | Cloud Storage buckets, us-central1 | ticket 26 boot pair 2: staging for the four image publishes; the name is `publish-tdx-image.sh`'s default and the labels are this ticket's | **each created and deleted inside the publish that made it; none survives** |


**State after boot pair 2, 2026-09-18T23:37Z**, confirmed at 23:38Z by the four
commands this ticket's discipline names: `gcloud compute instances list --zones
us-central1-a` shows only the seven pre-existing TERMINATED instances,
`gcloud compute instances list --filter="labels.purpose=attested-tunnel-t26"`
and `gcloud compute disks list --filter="name~t26"` both print `Listed 0 items.`,
and `gcloud compute images list --no-standard-images` shows only ticket 19's
three kept images (`attested-config-tdx-smoke-a-20260910214749`,
`attested-tdx-640de950bbdd`, `attested-tdx-d5ddcc423b1a`). **Nothing this ticket
created survives.**

Ticket 26 created **four** `c3-standard-4` TDX instances in all, in two pairs —
21:06Z–21:17Z and 23:25Z–23:37Z — and every one was deleted the same hour it was
created: about **46 TDX instance-minutes**, the longest-lived at roughly twelve.
Eight custom images and eight Cloud Storage buckets were created and deleted
inside the runs that made them; none was kept, because a ticket 26 image is a
record of a run and not something a later run boots from. No firewall rule,
network, IAM or org policy was created or changed, and none of the seven
pre-existing instances was touched.

### Boot pair 3, the confirming pair

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-09-18T23:48Z | t26-policy-a | c3-standard-4 TDX, us-central1-a, 20GB pd-balanced boot from custom image `attested-tdx-7f7c43153cab` + 10GB pd-balanced config disk from `attested-config-t26-a-20260918233949` + 10GB pd-balanced **workload** disk from `attested-workload-t26-20260918233949` (`device-name attested-workload`), `--private-network-ip 10.128.0.40`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 3, guest A: the same run as pair 2 with one assertion's wording corrected (`SELFCHECK VERDICT ADMITTED`), booted to confirm pair 2 and to give the RQ5 table a second sample. `=== 71 passed, 3 failed ===`: the two corrected assertions pass, and what remains is the console tail Compute Engine does not serve for a stopped instance and the long body arriving 45 bytes short | **deleted 2026-09-18T23:59Z** (~11 min) |
| 2026-09-18T23:48Z | t26-policy-b | the same three-disk shape, config disk `attested-config-t26-b-20260918233949`, `--private-network-ip 10.128.0.41`, `--labels purpose=attested-tunnel-t26` | ticket 26, boot pair 3, guest B: the second pusher (narrow-after 40 s), killed at 210 s | **deleted 2026-09-18T23:59Z** (~11 min) |
| 2026-09-18T23:40Z | attested-tdx-7f7c43153cab, attested-config-t26-{a,b}-20260918233949, attested-workload-t26-20260918233949 | custom images, 10 GiB + 1 GiB × 3, `purpose=attested-tunnel-t26` | ticket 26 boot pair 3: the guest image republished again, the two config devices and the workload device | **each deleted 2026-09-18T23:59Z, with the run** |
| 2026-09-18T23:40Z … 23:46Z | `attested-tunnel-t19-20260918{234014,234327,234456,234632}`, four in all | Cloud Storage buckets, us-central1 | ticket 26 boot pair 3: staging for the four image publishes | **each created and deleted inside the publish that made it; none survives** |

**State after boot pair 3, 2026-09-18T23:59Z**, confirmed at 2026-09-19T00:01Z
(20:01 EDT on 2026-09-18, the same working day) by the four commands: no instance
carries `purpose=attested-tunnel-t26`, no disk matches `name~t26`,
`gcloud compute instances list --zones us-central1-a` shows only the seven
pre-existing TERMINATED instances, and `gcloud compute images list
--no-standard-images` shows only ticket 19's three kept images. **Nothing this
ticket created survives.**

**Ticket 26's whole cloud bill**: six `c3-standard-4` TDX instances, in three
pairs — 21:06Z–21:17Z, 23:25Z–23:37Z and 23:48Z–23:59Z — each pair deleted inside
the hour it was created and none living longer than about twelve minutes: about
**68 TDX instance-minutes**. Twelve custom images and twelve Cloud Storage
buckets were created and deleted inside the runs that made them; none was kept.
No firewall rule, network, IAM or org policy was created or changed, and none of
the seven pre-existing instances was touched.
