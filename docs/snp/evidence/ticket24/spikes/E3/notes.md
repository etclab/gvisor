# E3 — PASS. runsc runs inside the measured SEV-SNP guest, and the rule is untouched

Ticket 24, experiment 3, on the SEV-SNP hardware harness. 2026-09-18, E2's image
unrebuilt and unmodified, booted twice: once with the `attested-workload` disk
attached and once without. `commands.txt` has the exact invocations.

**Both boots pass, the whole harness passes on each, and the
writable-must-be-noexec rule was neither changed, relaxed nor excepted.**

    with the disk:     === 29 passed, 0 failed ===
    without the disk:  === 29 passed, 0 failed ===

and on all four guests:

    init: no writable path is executable

## The workload ran, and this is the line it printed

Guest A, with the disk (guest B is identical but for the clock):

    init: the workload device carries a bundle at /workload/config.json
    init: running: unshare -Urmnpf sh -c 'mount -t proc -o nosuid,nodev,noexec proc /proc; exec /usr/bin/runsc --root=/run/runsc-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new run --bundle /workload workload'
    init: uptime 3.42s
    Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux
    init: uptime 4.27s
    init: workload exited with status 0

That output line is the evidence, not just the exit status. `4.19.0-gvisor` is the
sentry's compile-time constant — the guest kernel is
`6.16.0-snp-guest-038d61fd6422`, which init prints twenty lines earlier — so the
string cannot have come from the guest, and `workload` is the bundle's own
`hostname`, so it cannot have come from the guest's UTS namespace either. A real
sandbox started, served a read-only root off the workload disk, ran busybox in it
and put its stdout on the serial console.

Both guests, both clocks:

| | check verdict | workload start | workload exit | cost | tunneld |
|---|---|---|---|---|---|
| guest A | `uptime 2.99s` | `uptime 3.42s` | `uptime 4.27s` | **0.85 s** | `uptime 4.29s` |
| guest B | `uptime 3.17s` | `uptime 3.60s` | `uptime 4.50s` | **0.90 s** | `uptime 4.51s` |

Under a second, start to exit, for a sandbox that is a 108 MB binary paged out of
a dm-verity squashfs. The 0.02 s between the workload's exit and tunneld is init
printing the mount table again.

## The mount, and why `exec` is not in the table

The initrd said what it mounted, in the config device's own shape:

    initrd: workload device /dev/vdc mounted at /workload (ro,exec,nosuid,nodev; not measured)

and init's table shows it as:

    init: mount: /dev/vdc /workload ext4 ro,nosuid,nodev,relatime 0 0

The two are not in disagreement. `exec` is the *absence* of `MS_NOEXEC`, so there
is no option for `/proc/mounts` to print: the console line says the intent, the
table shows the three flags that were set, and the missing fourth is the point.
The mount is `ro`, so the guest's rule — which constrains writable mounts — has
nothing to say about it, and needed no exception to say nothing.

Against the config device, which is the same disk in every respect but this one:

    /dev/vdb /config   ext4 ro,nosuid,nodev,noexec,relatime
    /dev/vdc /workload ext4 ro,nosuid,nodev,relatime

One word apart, and that word is what S1's second finding said it would have to
be: the gofer's read-only remount omits `MS_NOEXEC`, a user namespace locks that
flag, so a noexec source cannot be remounted at all and the bundle cannot live on
one.

## Nothing runsc made is visible in init's namespace

The table printed after the workload exited, next to the one printed before it
ran, is **the same nine lines**:

    init: mount-after-workload: devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,size=936544k,nr_inodes=234136,mode=755,inode64 0 0
    init: mount-after-workload: /dev/dm-0 / squashfs ro,relatime,errors=continue,threads=single 0 0
    init: mount-after-workload: /dev/vdb /config ext4 ro,nosuid,nodev,noexec,relatime 0 0
    init: mount-after-workload: /dev/vdc /workload ext4 ro,nosuid,nodev,relatime 0 0
    init: mount-after-workload: proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
    init: mount-after-workload: sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
    init: mount-after-workload: tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755,inode64 0 0
    init: mount-after-workload: tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,inode64 0 0
    init: mount-after-workload: configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0

No `runsc-root`, no `runsc-proc`, no `nsfs`, no `null-netns`, nothing under
`/run/runsc-state`. Two things made that true and both are in the measurement:
`unshare -m`, which put every mount runsc makes in a namespace of its own and
which does not propagate out (E1/output-08), and
`--gofer-network-namespace=new`, without which `pinNullNetNS` bind-mounts an nsfs
`rw` into `--root` and this guest powers itself off (S1 E2). The check was **not**
re-run against this table and was not moved — it ran once, before anything else,
and its verdict is what decided the boot. This table answers a second question,
and a weaker one: not "is the rule satisfied" but "is there anything new to ask
about at all". There is not.

## The disk-absent path, on the same image

Without the disk, both guests:

    initrd: no workload device (virtio-blk serial attested-workload); the boot continues without a workload
    init: no writable path is executable
    init: uptime 2.62s
    init: no workload bundle at /workload/config.json; continuing to tunneld
    init: uptime 3.21s
    init: running /usr/bin/tunneld

Two lines, no failure, `runsc` never executed, and the same 29 assertions pass.
The empty `/workload` directory in the squashfs is what makes the absent case
quiet: there is a mount point with nothing on it rather than a missing path.

The cost of the workload is therefore readable off the two runs directly:

| | verdict -> tunneld, with the disk | without it |
|---|---|---|
| guest A | 2.99 -> 4.29 s (1.30 s) | 2.62 -> 3.21 s (0.59 s) |
| guest B | 3.17 -> 4.51 s (1.34 s) | 3.03 -> 3.47 s (0.44 s) |

About 0.8 s of boot, which is the sandbox, and it is spent before tunneld exists.

## What the tunnel did not notice

Both runs are the full `live` scenario and both pass it whole: attestation,
mutual admission, an established tunnel, warm and concurrent exchanges, the relay
carrying it and finding no plaintext, no address resolved off the segment. Each
guest presented the measurement predicted offline for this image,
`423b7bcf…84b3c`, and the ceiling digest is ticket 22's unchanged
`197d4aae…b973`. Running a sandbox before tunneld changed nothing about what a
peer sees, which is the property ticket 25 will need.

## The disk is not measured, and the record says so once per place it could not

`with-disk/workload-config.json` is the bundle's configuration read back out of
the ext4 image with `debugfs` — out of the disk the guests were actually given,
not out of the directory it was built from. The disk itself is not in this
directory: it is not measured, it is 64 MB of mostly nothing, and the one file
that says what ran is this one. `config.json` beside these notes is the same
bytes as they went in.

## Leftovers, named not fixed

- **The ext4 label is truncated.** `attested-workload` is 17 characters and ext4
  allows 16, so `mke2fs` warns and writes `attested-workloa`. Nothing reads it —
  the disk is found by its virtio-blk serial, which carries the whole name — and
  `mkworkloaddev.sh` says so in a comment. The warning is left visible rather
  than suppressed.
- **`-E root_owner=0:0` owns only the root directory.** Everything `mke2fs -d`
  copies keeps the uid of whoever ran the script, and that is not cosmetic here:
  runsc's user namespace maps one id, and a capability over a file is only a
  capability when the file's owner is mapped into the namespace, so a bundle
  owned by an unmapped uid is refused on modes the host would let root through.
  `mkworkloaddev.sh` sets every inode to 0:0 with `debugfs` afterwards and then
  checks that it did. Found by reading the image back before the first boot, not
  by a failure.
- **The sandbox tells the workload a lie about the kernel.** `4.19.0-gvisor` is a
  runsc constant; a workload that reads the kernel version learns nothing about
  the measured guest it is running in. Noted in E1 too; it matters for ticket 25
  if anything inside is ever meant to reason about where it is.
