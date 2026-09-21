# E2 — PASS. A 108 MB runsc costs the image 75 MB and the boot nothing measurable

Ticket 24, experiment 2, on the SEV-SNP hardware harness. 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t24` on `ticket-24-runsc-in-the-measured-guest`.
The image was rebuilt with `/usr/bin/runsc` in it, the `unshare` applet, an empty
`/workload`, and both init scripts' new text. Booted **with no workload disk
attached**, which is what this experiment is about: the ordinary case, and the
one every scenario recorded before this ticket is. `commands.txt` has the exact
invocations; nothing ran as root but the two QEMUs, through the job spool.

**The writable-must-be-noexec rule was not touched, and it passed.** Both guests:

    init: no writable path is executable

The rule is byte for byte what it was (`docs/snp/image/init.rootfs`, the loop the
new text moved but did not change; E1's `init-mount-check.sh` is S1's file and
still matches it).

## The mount table init printed, in full

Identical on both guests, and `/workload` is not in it — nothing was mounted
there, because no disk carried the serial:

    init: mount: devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,size=936544k,nr_inodes=234136,mode=755,inode64 0 0
    init: mount: /dev/dm-0 / squashfs ro,relatime,errors=continue,threads=single 0 0
    init: mount: /dev/vdb /config ext4 ro,nosuid,nodev,noexec,relatime 0 0
    init: mount: proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
    init: mount: sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
    init: mount: tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755,inode64 0 0
    init: mount: tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,inode64 0 0
    init: mount: configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0

Eight lines, the same eight ticket 22's image printed. Three are writable and all
three carry `noexec`; the root is `ro` and so has nothing to answer for.

## The disk-absent path, both halves of it

The initrd looked for the disk, did not find it, and said so:

    initrd: no workload device (virtio-blk serial attested-workload); the boot continues without a workload

and init, finding nothing mounted over the empty `/workload` in the squashfs,
said so again and went on:

    init: no workload bundle at /workload/config.json; continuing to tunneld

Two lines, no failure, and `runsc` was never executed. The image carries it
either way, which is the point: what is measured is the binary and the flag set,
not whether a disk was plugged in.

## Boot time

The new `init: uptime` lines, from `/proc/uptime` read by the shell:

| | at the verdict | at tunneld's first line | between |
|---|---|---|---|
| guest A | `init: uptime 3.16s` | `init: uptime 3.67s` | 0.51 s |
| guest B | `init: uptime 2.73s` | `init: uptime 3.16s` | 0.43 s |

The half second between them is loopback, the six netfilter modules, the ceiling
going into the kernel and the ceiling being printed back — not runsc, which did
not run.

The kernel's own printk timestamps agree and are the independent check. The last
printk before the verdict is the sev-guest driver initialising, and there is no
printk at all between the verdict and `init: running /usr/bin/tunneld` — the
kernel is quiet by then, so the uptime lines are the only clock in that window:

    [    3.134052] sev-guest sev-guest: Initialized SEV guest driver (using VMPCK0 communication key)
    init: no writable path is executable
    init: uptime 3.16s

Against ticket 22's image, same measure, same host, same two guests:

| | ticket 22 | ticket 24 |
|---|---|---|
| last printk before the verdict, guest A | `[ 2.792852]` | `[ 3.134052]` |
| last printk before the verdict, guest B | `[ 3.137863]` | `[ 2.690345]` |

The two ranges overlap: one guest got faster and the other slower, by more than
the difference between the images. **A 75 MB bigger root filesystem costs no
measurable boot time**, and the reason is structural rather than lucky — the
squashfs is mapped through dm-verity off a virtio-blk disk and paged in on
demand, so a byte nobody reads is never read. The initrd, which *is* copied into
memory whole, grew by 849 bytes, and none of that is runsc.

## Image size

    rootfs.img   9,977,856 -> 85,319,680    +75,341,824   (8.55x)
    initrd.img   1,507,232 ->  1,508,081         +849
    cmdline.txt        195 ->        197           +2
    vmlinuz, OVMF.fd                          unchanged

`sizes.txt` has the whole table and the arithmetic. The 108,668,311-byte binary
costs 75.34 MB of image because zstd squashfs compresses it; the verity tree over
it went from 2,416 to 20,665 data blocks.

## The prediction still holds

The launch measurement was predicted offline by the build, from the four measured
files and the vCPU count, before any boot:

    launch_measurement: 423b7bcfbf3922af7c7faa65607dff6d86f6c0508ac6aaf0a9aff684d39313318364fd3ba2e15fe491b7f32077c84b3c

and each guest presented exactly that number in its evidence, as the other guest
wrote it down:

    tunneld: PEER SEEN key=676c7ad4… chain=0957b4aa… measurement=423b7bcfbf3922af7c7faa65607dff6d86f6c0508ac6aaf0a9aff684d39313318364fd3ba2e15fe491b7f32077c84b3c times=1

    PASS  each guest reported the measurement predicted offline for the image both booted

Nothing was read off a booted guest into a reference value; the number in
`manifest.txt` came from `predict-measurement.sh` and the guests agreed with it
afterwards. There is no line in which a guest names its *own* measurement — the
match is always one guest's prediction against the other guest's report, which is
the claim worth making.

The ceiling digest is unchanged from ticket 22 at
`197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973`: runsc is not
in `attest/ceiling`, so what a guest presents as its policy did not move.

## The harness's own verdict

    === 29 passed, 0 failed ===

The live scenario in full, unchanged and unrelaxed: both guests booted, attested,
admitted each other, established a tunnel, exchanged over it warm and
concurrently, the relay carried it and found no plaintext, and no address off the
segment was resolved. `capture/tunnel-run.txt` is the untrimmed transcript and
`capture/live/console-{a,b}.txt` the untrimmed consoles.

## What this does not answer

Whether runsc runs in there. Nothing executed it in this boot — E3 is that
experiment. What E2 establishes is narrower and had to come first: that carrying
it costs the image nothing it cannot pay, and that the rule the image exists to
have is still satisfied with a 108 MB binary and an extra mount point inside the
measurement.
