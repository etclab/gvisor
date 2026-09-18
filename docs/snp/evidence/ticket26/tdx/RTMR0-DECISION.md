# Pinning the three-disk RTMR0, and why the third disk stays

**Decision, ticket 26.** The reference value sets this project authors for Google
Cloud TDX now admit two RTMR0 values instead of one:

```
c2fc12a52db868515eff7c657e42ce04b0b7363fa6ddf7c1cca87aa8e6a061a11f9981924a600ad6d2232f75182a850a   two disks   (ticket 19)
8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f   three disks (this ticket)
```

They are written as the comma-separated default of `RTMR0` in
`docs/snp/cloud/tdx/build-tdx-image.sh` and in
`docs/snp/cloud/tdx/emit-tdx-documents.sh`, expanded into repeated `-rtmr0`
flags for `emit-tdx-refvals`, and printed in every manifest under `provider
constants pinned:`. `docs/snp/cloud/tdx/SCENARIOS.md` says the same thing to an
operator.

## What the second value is, and where it came from

`8ee4fa36…b70a3f` is what a `c3-standard-4` TDX guest reports when it is created
with **three** disks: a 20 GB pd-balanced boot disk from a custom image, a 10 GB
pd-balanced config disk (`--device-name attested-config`) and a 10 GB
pd-balanced workload disk (`--device-name attested-workload`), all three present
at instance creation.

Ticket 24 observed it twice and authored it nowhere:

| boot | instance | image | record |
|---|---|---|---|
| E4 boot 2 | `tdx-t24-a`, 2026-09-18T10:11Z–10:15Z | `attested-tdx-…` image-a | `docs/snp/evidence/ticket24/spikes/E4/boot-2/` — `console.txt`, `quote.txt`, `measurements.txt`, `verify-evidence.txt` |
| E4 boot 3 | `tdx-t24-b`, 2026-09-18T10:59Z–11:02Z | `attested-tdx-038e7905a285` | `docs/snp/evidence/ticket24/spikes/E4/boot-3/` — the same four files |

On both boots MRTD and RTMR1 matched the pinned constants and RTMR2 matched a
prediction made offline from the image bytes eight or nine minutes earlier. The
only register that disagreed was RTMR0, and both the guest's own self-check and
this workstation judging the same quote against the same signed set refused on
it and on nothing else:

```
tunneld: SELFCHECK VERDICT REFUSED reason=launch measurement not in the reference value set
the TD's observed RTMR0 is 8ee4fa36…b70a3f, which is none of the 1 values this reference value lists
```

Ticket 24's record (`docs/runsc-in-the-guest.md`, "The RTMR2 match, and the
RTMR0 finding") states plainly that the value **was observed twice and authored
nowhere**, and its leftover 2 hands the choice here: *"Ticket 25 or 26 must
observe `8ee4fa36…b70a3f` for the three-disk shape and author it deliberately,
the way ticket 19 authored the two-disk value, or attach no third disk. Until
then every three-disk TDX guest is refused."*

## Why pin rather than drop the third disk

The alternative leftover 2 offers is to attach no third disk — to put the OCI
bundle somewhere else, on the config device or inside the initrd. Both are
refused, and for reasons that are not about RTMR0 at all:

1. **The workload bundle has to live on a mount that is read-only and
   exec-permitted, and it is the only such mount in the guest.** The gofer
   bind-mounts the bundle's rootfs and remounts it `MS_RDONLY|MS_NOSUID|MS_NODEV`
   *without* `MS_NOEXEC`; those flags are locked inside a user namespace, so a
   remount that omits one is asking to clear it and the kernel answers `EPERM`. A
   `noexec` source therefore cannot be served to a sandbox at all
   (`docs/snp/evidence/spike-s1-runsc-in-guest/E2/notes.md`). The config device
   is mounted `ro,noexec,nosuid,nodev` and must stay that way — nothing on it may
   run — so the bundle cannot go there. That is the 2026-09-18 decision recorded
   in the project's memory as *images on a separate ro+exec mount*, and this
   ticket does not reopen it.

2. **Putting the bundle in the initrd would put it inside the measurement.** On
   TDX the initramfs is the root and grub measures it whole, so every byte of a
   bundle carried there would be a byte of RTMR2. The claim this whole design
   rests on is the opposite one: *what the disk carried is not measured and is
   not claimed to be*, and what the measurement covers is the runsc in the
   initrd, the flag set `/init` launches it with and the options the workload
   device is mounted with. A bundle in the initrd would also mean a new image and
   a new measurement for every change of workload, which is exactly what the
   config-device/workload-device split exists to avoid.

3. **Ticket 26's proof needs the third disk on hardware.** The item is *the proof
   on two Google Cloud TDX guests: a task completing agent-to-agent over the
   tunnel under a pushed policy; an off-policy control; a narrowing mid-run; and
   a liveness teardown after the workload is killed*. There is no sandbox without
   a bundle and no bundle without the third disk, so "attach no third disk" is
   the same sentence as "do not run the proof".

So the shape is a fact about what this project builds, and a reference value has
to pin the value the shape it is authored for reports.

## Why this is authoring and not harvesting

The rule this project keeps is ADR-0004's and ticket 19's: **never read a
measurement off a booted machine into a reference value.** Nothing about that
rule is bent here, and the distinction is worth stating exactly.

- No script reads RTMR0 off a quote, a console or a running instance and writes
  it into a document. `emit-tdx-refvals` takes `-rtmr0` on its command line and
  `build-tdx-image.sh` passes the list a human typed into it. Nothing in the
  build path has ever parsed a quote.
- The number in this file and in the two scripts was typed by an author who read
  two recorded transcripts, checked that they agree, checked that the shape they
  were taken on is the shape this project will create, and decided that guests of
  that shape are guests this project admits. That is the same act ticket 19
  performed for `c2fc12a5…850a` after `probe-tdx-rtmr0.sh` changed one thing on
  one instance.
- The two answers are still read apart, as ticket 24 insisted: the prediction
  (RTMR2) is computed from the image and matched; the pinning (MRTD, RTMR0,
  RTMR1) is observed, and observed values are provider constants an author
  chooses to admit. A set is a statement about whom this guest will admit, not a
  report of what some machine reported.

## What a reader should check before trusting it

- **Both values are listed, and neither replaces the other.** A set naming only
  the three-disk value would refuse every two-disk guest tickets 19 and 22
  recorded; one naming only the two-disk value refuses every guest of ticket 26's.
- **A fourth disk is a shape nobody has observed.** Ticket 19 established that the
  disk *count* is not what names the value — two shapes with two disks each gave
  two different RTMR0s — so nothing here predicts what a four-disk guest would
  report, and a guest of that shape would be refused. If the shape changes,
  observe it again and author it again.
- **The three-disk value has been seen on two instances and two images and on
  one machine type in one zone.** It has not been seen after a reboot, on another
  machine type, in another zone or in another project. Each of those is a shape
  this file says nothing about.
- **If a guest of the pinned shape is still refused on RTMR0**, the value moved
  and this file is stale; record the new one, do not edit a set to match a
  machine.

## Where the change is

```
docs/snp/cloud/tdx/build-tdx-image.sh     the RTMR0 default and the provenance paragraph above it
docs/snp/cloud/tdx/emit-tdx-documents.sh  the same default, so the two authoring paths cannot drift
docs/snp/cloud/tdx/SCENARIOS.md           the constants block, and the operator's rule about disks
```

No reference value file already committed under `docs/snp/evidence/` is edited:
those are the records of runs that happened, and a record is not rewritten
because a later ticket authored a different set.
