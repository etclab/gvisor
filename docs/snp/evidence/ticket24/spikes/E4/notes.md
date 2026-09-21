# E4 — the prediction holds; runsc does not run in an initramfs-rooted guest

Ticket 24, experiment 4, on Google Cloud TDX hardware. 2026-09-18, one image built
offline, two instances, both deleted the same hour. `commands.txt` has the exact
invocations and their timestamps; `image/` is everything about the image except
its ten gibibytes; `boot-1/` and `boot-2/` are the two consoles.

**The headline, and it is two separate answers.**

    RTMR2 predicted from the image at 09:53:38Z, before any instance existed:
        cd68e874bbfb15b746ba0679fb4a0bc3fe967b5b616a635fbd47f48538135af0ab229810fb3d293273a8c4e1438f6e25
    RTMR2 the hardware reported in the quote at 10:15Z:
        cd68e874bbfb15b746ba0679fb4a0bc3fe967b5b616a635fbd47f48538135af0ab229810fb3d293273a8c4e1438f6e25

**MATCH.** A 108 MB runsc inside the measured initramfs is still predictable offline,
which is the question E4 was asked. 25 records of 25, the same 25 grub takes on ticket
19's image; exactly one of them moved, record 24, the initrd's own digest (checked by
diffing the two predictors' record lists — `image/predict-rtmr2-output.txt` against
`docs/snp/evidence/ticket19/images/image-a/predicted-measurement.txt`).

**And: the workload did not run.** runsc reached the sandbox and the sandbox died:

    initrd: running: unshare -Urmnpf sh -c 'mount -t proc -o nosuid,nodev,noexec proc /proc; exec /usr/bin/runsc --root=/run/runsc-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new run --bundle /workload workload'
    running container: creating container: cannot create sandbox: cannot read client sync file: waiting for sandbox to start: EOF
    initrd: workload exited with status 128

There is no `uname -a` line on this console. On SEV-SNP (E3) the same binary, the same
flag set and the same bundle printed
`Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux` and
exited 0. Recorded, not fixed: the ticket says stop here, and nothing under `pkg/` or
`runsc/` was touched. The section "What most likely killed the sandbox" below names a
cause and says exactly what would prove it.

## The registers

| register | what the set pins | what the hardware reported | |
|---|---|---|---|
| RTMR2 | `cd68e874…f6e25` (predicted offline) | `cd68e874…f6e25` | **equal** |
| MRTD | `c1ee9c16…70a5` | `c1ee9c16…70a5` | equal |
| RTMR1 | `02c7f19c…913b` (first boot) or `3a446943…d691` | `02c7f19c…913b` | equal, the first-boot value |
| RTMR0 | `c2fc12a5…850a` (the two-disk shape) | `8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f` | **different** |

Both checks refused the guest, and both refused it on RTMR0 and on nothing else. The
guest's own self-check:

    tunneld: SELFCHECK VERDICT REFUSED reason=launch measurement not in the reference value set
    tunneld: REFUSED verification refused: launch measurement not in the reference value set:
             the TD's observed RTMR0 is 8ee4fa36…b70a3f, which is none of the 1 values this
             reference value lists

and this workstation, judging the same quote against the same signed set
(`boot-2/verify-evidence.txt`), printed the same sentence and exited 2. The refusal
names the register in its operator log; the one-line `reason=` says only "launch
measurement", which is the same wording ticket 19's RTMR0 refusal produced
(`docs/snp/evidence/ticket19/smoke/run1-rtmr0-mismatch/console.txt`) and is worth
remembering: a reader who takes `reason=` at face value will look at RTMR2, which was
right.

**The RTMR0 finding.** `8ee4fa36…b70a3f` is what a **three**-disk `c3-standard-4` TDX
guest reports — boot disk, config device, workload device. Every value recorded before
it was a one-disk (`c0b8b19c…896d`) or a two-disk (`c2fc12a5…850a`) shape, and ticket 19
established by experiment that RTMR0 moves when the shape does
(`docs/snp/evidence/ticket19/rtmr0/`). So this was expected, it is a fact about the
provider's firmware configuration and not about this image, and it is why the set that
ships with this image refuses a guest of this shape.

That value is **read off a booted machine and is not a reference value.** It is not in
`build-tdx-image.sh`'s `RTMR0` default, not in `image/reference-values.json`, and not in
any build parameter this ticket touched. Ticket 24 changed no authored value; a ticket
that wants a three-disk guest admitted must observe this register for that shape and
author it deliberately, exactly as ticket 19 did for two disks.

## Size: the whole cost is the initrd, and it is all inside RTMR2

    initrd.img   ticket 19 image-a   10,446,197 bytes   (49 entries)
                 ticket 24            86,550,953 bytes   (52 entries)   +76,104,756, 8.29x
    disk.raw     10,737,418,240 bytes both, unchanged: two files rewritten on /boot
    vmlinuz      16,775,240 bytes both; grub.cfg 272 bytes both, byte for byte identical

`image/sizes.txt` has the table. gzip turns the 108,668,311-byte runsc into 76 MB of
initrd, 70% of the binary. On SEV-SNP the same binary cost the initrd 849 bytes and the
verity root 75 MB (`../E2/sizes.txt`), because there it lives in a squashfs the initrd
only maps. Here the initramfs *is* the root and grub measures it whole, so all 76 MB are
inside RTMR2 — which is the point, and also the reason the prediction question was worth
asking.

## Boot time

The initrd's own clock, from `/proc/uptime`:

    initrd: uptime 1.96s   after the egress proof
    initrd: uptime 1.96s   immediately before runsc
    initrd: uptime 1.99s   immediately after it exited 128
    initrd: uptime 2.00s   immediately before tunneld

so the workload cost **0.03 s**, which is a failure and not a measurement of anything.
E3's SNP guest spent 0.85–0.90 s there for a sandbox that actually ran.

Against ticket 19's smoke console, which is the only TDX baseline there is
(`docs/snp/evidence/ticket19/smoke/console.txt`), the printk anchors:

| | ticket 19 | ticket 24 | delta |
|---|---|---|---|
| `RAMDISK: [mem …]` | 10,448,896 bytes | 86,552,576 bytes | the initrd, page-rounded, in memory |
| `Trying to unpack rootfs image as initramfs` | 1.576365 | 1.963035 | |
| `Freeing initrd memory` | 1.698789 (10,204K) | 2.497169 (84,524K) | unpack **0.1224 s -> 0.5341 s** |
| `Run /init as init process` | 2.325758 | 2.708962 | **+0.3832 s** |

So an eight-fold initrd costs about 0.4 s of kernel boot, nearly all of it the
initramfs unpack. **Two caveats, both real:**

- Grub's own read and SHA-384 of the 86 MB initrd happens before the kernel's clock
  exists, so it does not appear in any timestamp here. Whatever it cost is not measured
  by these numbers.
- Ticket 19's console carries **no** clock after `Run /init` — there was no `uptime_say`
  then — so "time to tunneld" cannot be compared against it at all. Only the kernel-side
  anchors above are comparable.

And one oddity, recorded because it will confuse the next reader: on this guest
`/proc/uptime` reads about a second *behind* the printk timestamps. `initrd: uptime 1.96s`
is printed after `[ 3.035159] gve … Device link is up.` The two clocks disagree; deltas
within one clock are still deltas, and all the workload numbers above are uptime-to-uptime.

## The mount table, and the asymmetry this ticket records rather than changes

Printed after the workload and before tunneld, so it shows `/workload`:

    initrd: mount: rootfs / rootfs ro,size=7641612k,nr_inodes=1910403,inode64 0 0
    initrd: mount: devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,…
    initrd: mount: proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755,inode64 0 0
    initrd: mount: tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,inode64 0 0
    initrd: mount: configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: /dev/nvme0n2 /config   ext4 ro,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: /dev/nvme0n3 /workload ext4 ro,nosuid,nodev,relatime 0 0

The last two lines are one word apart and that word is the whole of it: the config
device is `noexec`, the workload device is not. `exec` is the *absence* of `MS_NOEXEC`,
so there is no option for `/proc/mounts` to print — the console line says the intent,

    initrd: workload device /dev/nvme0n3 found by the ext4 label, mounted at /workload
            (ro,exec,nosuid,nodev; not measured); it holds:
    initrd:   config.json  632 bytes  193382ad2dfce082…
    initrd:   rootfs/bin/busybox  2124608 bytes  dbac288c29ba5684…

and the table shows the three flags that were set. (Two entries, not four: the
listing is `find -type f`, copied from the config device's, and the bundle's
`rootfs/bin/sh` and `rootfs/bin/uname` are symlinks to that one busybox.) Identical to E3's SNP guest in every
respect but the device node.

**The asymmetry, recorded.** `/` here is `rootfs`, a tmpfs, and it was `rw` for the whole
of the boot up to this point — including while runsc ran. On SEV-SNP the same moment is
governed by a rule: `docs/snp/image/init.rootfs` walks `/proc/mounts` before anything
else and powers the guest off if any writable mount is executable. This init has no such
check; it only remounts the initramfs read-only afterwards and lists the table
(`init.tdx`, the block just before step 9). That was already true in ticket 19 and
ticket 24 deliberately did not change it: the ticket's decision is that the asymmetry is
a leftover to *record*. It is recorded here. Note what it means concretely for this
experiment: on TDX runsc ran with a writable, executable `/` underneath it, and the SNP
rule that the whole of spike S1 was about proving compatible with was, on this vendor,
never consulted.

**Found by label, not by serial.** `find_workload_dev` tries the NVMe serial first, as
`find_config_dev` does, and as on ticket 19 the provider does not expose `--device-name`
that way: every namespace reports `serial='nvme_card-pd'`. Both devices were found by
their ext4 volume label — `attested-config` and the truncated `attested-workloa`, ext4
holding sixteen of the seventeen characters. The truncation is why `init.tdx` compares
against the truncated form and says so in a comment.

## What most likely killed the sandbox — named, not proven

`cannot read client sync file: waiting for sandbox to start: EOF` is the signature spike
S1 and E1 saw when the sandbox process dies before it can answer. The bundle's mount is
not the cause this time: `/workload` is `ro` and **exec-permitted**, which is the one
thing S1's second finding demanded, and E3 proved that exact mount works.

The one structural difference between this guest and every environment where this binary
has worked is the root filesystem:

    workstation (E1)  /  a real filesystem, in a namespace unshared from it       runsc works
    SEV-SNP (E3)      /dev/dm-0 / squashfs   — init.initrd switch_root'ed into it  runsc works
    TDX (E4)          rootfs / rootfs        — the initramfs IS the root, no switch_root   runsc fails

and runsc's sandbox setup calls `pivot_root(2)` twice on its way up
(`runsc/cmd/sandboxsetup/fs.go:32-48`, reached from `runsc/cmd/sentry/sentrycmd/chroot.go:181`
and `runsc/cmd/sandboxsetup/gofer_mount.go:260`). The error string in that function is
`pivot_root failed, make sure that the root mount has a parent` — and the initramfs
rootfs is the one mount in Linux that has no parent, which is why `pivot_root(2)`
documents it as the case that cannot be pivoted and why `switch_root` exists at all.
That is a coherent account of exactly this vendor failing and the other two not.

**It is a hypothesis.** The console carries only runsc's top-level error; the sandbox's
own message never reached the serial line, so nothing here proves which syscall refused.
Proving it needs `--debug` (or the sandbox's stderr on the console), which means a new
initrd, a new RTMR2 and another boot — out of scope for this ticket, which says to record
a runsc failure and stop. If the hypothesis holds, it is not a runsc bug and not a rule
to relax: it is a fact about a guest whose root is an initramfs, and the fix belongs to
the image — either a small root filesystem the initrd switch_roots into, which is what
SNP already does and what TDX gave up on purpose (there is no verity root here because
grub measures the initrd whole), or a mount the sandbox can pivot into. Naming that
choice is ticket 25's business, not this record's.

## What the rest of the boot did

Everything before and after the workload behaved exactly as ticket 19's smoke boot did:
the TDX guest driver, the NIC and the four netfilter modules loaded; the report interface
was present; the egress ceiling `197d4aae…b973` installed before the link came up and was
read back out of the kernel; the config device was found and mounted `ro,noexec,nosuid,nodev`
with the collateral refreshed this morning on it; the address came up with the VPC's
on-link gateway route; six forbidden egress attempts were all refused by a rule
(`EGRESS PROBE PASSED`); tunneld started, acquired 8000 bytes of Intel TDX evidence in
40 ms and self-checked. The tunnel it tried to establish to itself failed, and it failed
for the RTMR0 reason and no other: `CRYPTO_ERROR 0x12a (local): attest: verification failed`.

**On TDX the network is already up when the workload runs, and on SNP it is not.** The
SNP init installs the ceiling and then runs the workload before tunneld brings the link
up out of the run configuration, so the workload there has no link to leave by at all.
Here step 6 has already configured `eth0`, so the only thing between the workload and the
guest's network is `--network=none` in the flag set plus the network namespace `unshare
-n` makes. Both are inside the measurement; neither was exercised by this boot, because
the sandbox never started. Worth an experiment of its own before ticket 25 relies on it.

## What did not hold

- **Boot 1 was thrown away by a variable-name collision I introduced.** The new `LABEL`
  knob in `smoke-tdx-guest.sh` is the Compute Engine resource label; `mkconfigdev-tdx.sh`'s
  `LABEL` is the ext4 volume label. Until this ticket the smoke script's was a plain shell
  assignment that a child process could not see; a value given in the *environment* is
  exported, so it reached the device builder and the config device went out labelled
  `purpose=attested` (ext4 truncating it to sixteen bytes). The guest halted after thirty
  seconds looking for `attested-config` and never reached runsc. `boot-1/` is kept whole.
  The fix is one call wrapped in `env -u LABEL`, and it was checked on the workstation
  before boot 2: with `LABEL=purpose=attested-tunnel-t24` exported, the device now comes
  out labelled `attested-config`. Cost: one instance, four minutes.
- **The workload did not run**, as above. E4 answers its own question — the prediction —
  and leaves the ticket's other TDX question open.
- **`reason=` does not name the register.** Both the guest and the workstation say
  "launch measurement not in the reference value set" for an RTMR0 mismatch. The operator
  log does name it. Same wording ticket 19 hit; still worth fixing somewhere that is not
  this ticket.
- **`/proc/uptime` and the printk clock disagree by about a second** on this guest, as
  above.
- Nothing under `pkg/` or `runsc/` changed. The writable-must-be-noexec rule was neither
  changed, relaxed nor excepted — on this vendor it was never consulted, which is the
  asymmetry recorded above and not a new decision.

## boot-3, the hardware's answer after E5's fix — the workload runs, and RTMR2 still matches

Added 2026-09-18T11:05:29Z, after E5. Everything above this line was written between boot 2
and E5 and is unchanged, including the header's "`boot-1/` and `boot-2/` are the two
consoles": there is a third now, `boot-3/`, and a second image, `image-b/`.

E5 (`../E5/notes.md`) reproduced boot 2's failure locally on the measured initrd itself,
got the sandbox to name its own cause — `pivot_root failed, make sure that the root mount
has a parent`, in both the sentry's log and the gofer's — and put the answer in
`docs/snp/cloud/tdx/init.tdx`: inside the same namespace, before the same runsc command
with spike S1's flag set untouched, a recursive bind of `/` under `/run`, moved to where
`/` is, entered through the working directory pinned to it before the move. So **E4's
hypothesis was right and is no longer a hypothesis**, and this section is what the
hardware said about the fix.

One image, one instance, deleted the same hour it was created.

    RTMR2 predicted from image-b at 10:49:27Z, and again by hand at 10:50:41Z,
    both before the instance existed:
        038e7905a2853bf89285a1e967388a9a8cb5a996830f1eee63d036af532cb25f3d6c7636e071e01663a876dc64ca0b78
    RTMR2 the hardware reported in the quote at 11:02Z:
        038e7905a2853bf89285a1e967388a9a8cb5a996830f1eee63d036af532cb25f3d6c7636e071e01663a876dc64ca0b78

**MATCH**, 25 records again, and again exactly one record moved against image-a — record
24, the initrd's own digest (`image-b/sizes.txt`). So the prediction survives an edit to
the measured `/init`, which is the sharper version of the question E4 asked.

**And the workload ran, on the hardware:**

    initrd: uptime 1.96s
    initrd: the workload device carries a bundle at /workload/config.json
    initrd: running: unshare -Urmnpf sh -c "busybox mkdir -p /run/root; mount --rbind / /run/root; cd /run/root; mount --move . /; exec busybox chroot . sh -c 'mount -t proc -o nosuid,nodev,noexec proc /proc; exec /usr/bin/runsc --root=/run/runsc-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new run --bundle /workload workload'"
    initrd: uptime 1.96s
    Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux
    initrd: uptime 2.04s
    initrd: workload exited with status 0

**0.08 s**, against boot 2's 0.03 s of failing and E3's 0.85 s on SEV-SNP, and the same
line E3 printed. `4.19.0-gvisor` is the sentry's compile-time constant against this
guest's own `6.17.0-1022-gcp`, and `workload` is the bundle's `hostname`, so neither half
of the line can have come from the guest. tunneld started afterwards, unchanged, and
acquired 8000 bytes of Intel TDX evidence in 41 ms.

| register | what the set pins | what the hardware reported | |
|---|---|---|---|
| RTMR2 | `038e7905…a0b78` (predicted offline) | `038e7905…a0b78` | **equal** |
| MRTD | `c1ee9c16…70a5` | `c1ee9c16…70a5` | equal |
| RTMR1 | `02c7f19c…913b` or `3a446943…d691` | `02c7f19c…913b` | equal, the first-boot value |
| RTMR0 | `c2fc12a5…850a` (the two-disk shape) | `8ee4fa36…b70a3f` | **different, exactly as in boot 2** |

Both checks refused the guest and both refused it on RTMR0 alone, in the same words boot 2
produced: `the TD's observed RTMR0 is 8ee4fa36…b70a3f, which is none of the 1 values this
reference value lists` (`boot-3/verify-evidence.txt`, exit 2, and the guest's own
`SELFCHECK VERDICT REFUSED`). `8ee4fa36…b70a3f` is the three-disk `c3-standard-4` value
boot 2 observed; this run **observed it a second time and authored it nowhere**. It is
still not in any reference value, not in `build-tdx-image.sh`'s `RTMR0` default and not in
`image-b/reference-values.json`, whose `observed_rtmr0` still lists only the two-disk
`c2fc12a5…850a`. The smoke script's composite verdict therefore reads `INCOMPLETE` — the
same word boot 2 got — because it requires both the RTMR2 match and an admitted guest.
Read the two apart: the prediction matched, and the set refuses this machine shape.

**Boot time, boot-3 against boot-2, same image size to within a kilobyte:**

| | boot 2 | boot 3 | |
|---|---|---|---|
| `Trying to unpack rootfs image as initramfs` | 1.963035 | 1.910563 | |
| `Freeing initrd memory` (84,524K both) | 2.497169 | 2.438673 | unpack 0.5341 -> 0.5281 s |
| `Run /init as init process` | 2.708962 | 2.648935 | **-0.060 s** |
| egress proof done (uptime) | 1.96 s | 1.96 s | |
| workload start -> exit (uptime) | 1.96 -> 1.99 s (failed) | 1.96 -> 2.04 s (**ran**) | +0.05 s |
| tunneld (uptime) | 2.00 s | 2.06 s | +0.06 s |

The initrd grew 1,044 bytes and the kernel-side numbers moved by less than that could
explain — 0.06 s of run-to-run noise on a cloud instance, in the direction of *faster*. The
whole cost of a sandbox that actually runs is the 0.05 s between the two workload clocks.
`/proc/uptime` still reads about a second behind the printk clock on this guest, as boot 2
recorded; every workload number above is uptime-to-uptime.

**The mount table is the same table**, `/dev/nvme0n2` and `/dev/nvme0n3`, both found by
their ext4 label as before, `/config` `noexec` and `/workload` not. And the asymmetry this
ticket records is untouched: `/` is `rootfs`, it was `rw` while the sandbox ran, init
remounts it read-only afterwards and lists the table, and there is still no
writable-and-executable check on this vendor. Nothing under `pkg/` or `runsc/` changed;
the runsc flag set is byte for byte spike S1's; the writable-must-be-noexec rule was
neither changed, relaxed nor excepted.

What did not hold in boot 3: nothing new. The RTMR0 refusal was expected and is recorded
above and in `../../../../cloud/tdx/RESOURCES.md`; the `reason=` line still does not name
the register, as boot 2 noted.
