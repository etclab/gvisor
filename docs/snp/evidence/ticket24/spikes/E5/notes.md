# E5 — PASS. The sandbox named its own cause, and three lines of init.tdx answer it

Ticket 24, experiment 5, a follow-up to E4. Eight boots of E4's own kernel and
initrd under plain KVM on this workstation, unprivileged, no cloud instance and no
sudo. `commands.txt` has the exact invocations and their timestamps.

**The headline, in three parts.**

**One. E4's failure is reproducible locally, on the first attempt, with the
measured bytes.** The initrd booted in output-01 is
`c409a79cfbcd20a9f0fca7662c0423474d0c53c641a3b6b1572a8d23239b8e53`, 86,550,953
bytes — the file grub measured into RTMR2 on the hardware, not a rebuild of it —
and the console says what the hardware said:

    running container: creating container: cannot create sandbox: cannot read
    client sync file: waiting for sandbox to start: EOF
    initrd: workload exited with status 128

**Two. The cause is what E4 guessed, and the sandbox says it in its own words.**
A debugging initrd (init.tdx plus `--debug --debug-log=/run/runsc-debug/` and a
dump of the logs; never measured, never booted on TDX) makes both dying processes
speak. The sentry, in `runsc.log.…boot.txt`:

    I0918 10:34:34.894096  1 chroot.go:142] Setting up sandbox chroot in "/tmp"
    D0918 10:34:34.895127  1 timing.go:125] … reached midpoint chroot sealed read-only …
    W0918 10:34:34.895156  1 util.go:107] FATAL ERROR: error setting up chroot:
        pivot_root failed, make sure that the root mount has a parent: invalid argument

and the gofer, in `runsc.log.…gofer.txt`, three hundredths of a second earlier:

    I0918 10:34:34.879924  1 gofer_mount.go:249] Remounting root as readonly: "/proc/fs/root"
    W0918 10:34:34.880015  1 util.go:107] FATAL ERROR: failed to change the root file system:
        pivot_root failed, make sure that the root mount has a parent: invalid argument

Both are `sandboxsetup.PivotRoot` (`runsc/cmd/sandboxsetup/fs.go:32-53`; the
syscall is at `:45` and that error text at `:46`), reached from
`runsc/cmd/sentry/sentrycmd/chroot.go:181` and
`runsc/cmd/sandboxsetup/gofer_mount.go:260`. `EINVAL`, and the message's own
advice is the diagnosis: the initramfs is the one mount in Linux with no parent,
so `pivot_root(2)` cannot move it. E4's hypothesis, now not a hypothesis. The
probe below demonstrates the same rule a second way: arrangement H has *init*
try the pivot, and the kernel answers `pivot_root: Invalid argument`.

**Three. The fix is in `docs/snp/cloud/tdx/init.tdx` and the workload runs.**
Inside the same user-and-mount namespace, before the same runsc command with
spike S1's flag set unchanged:

    busybox mkdir -p /run/root; mount --rbind / /run/root; cd /run/root; mount --move . /
    exec busybox chroot . sh -c 'mount -t proc -o nosuid,nodev,noexec proc /proc; exec <RUNSC_CMD>'

and output-08, from the tree's own init.tdx:

    initrd: uptime 3.38s
    Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux
    initrd: uptime 3.59s
    initrd: workload exited with status 0

0.21 s, and the line is the sentry's compile-time constant against a guest whose
own kernel is `6.17.0-1022-gcp`, so it cannot have come from the guest; the
nodename is the bundle's `hostname`, so it cannot have come from its UTS namespace
either. E3's SNP guest printed the same line, and this is now the same claim on
both vendors.

## Why it takes two operations and not one

The bind alone is not enough and the move alone is not enough, and the reason is
two different kernel rules that happen to bite the same line of shell.

- `pivot_root(2)` refuses a root mount with no parent
  (`if (!mnt_has_parent(root_mnt)) goto out4;` in `fs/namespace.c`). A recursive
  bind of `/` at a directory under the `/run` tmpfs is a mount whose parent is
  that tmpfs, so a process rooted there can be pivoted out of.
- `clone(CLONE_NEWUSER)` refuses a process the kernel considers chrooted
  (`current_chrooted()`), and runsc-rootless clones a user namespace for the
  gofer. `current_chrooted()` compares the process's root with the *mount
  namespace's* root **followed down through whatever is mounted on it**. So
  `chroot` into a bind that sits under `/run` is "chrooted" — EPERM, and the
  gofer never execs; while a bind **moved onto `/`** and entered through the
  working directory pinned to it before the move is not, because the namespace
  root now follows down into exactly that mount.

Satisfying the first without the second gives `fork/exec /proc/self/exe:
operation not permitted`; satisfying the second without the first gives the
`EOF`. Doing both, in that order, is the whole of the fix. `pivot_root` by init
itself cannot be the answer, for the same reason runsc's cannot: there is no
parent to hang `put_old` on (arrangement H).

## The variants, and what each one did

Every row is a boot of this workstation's QEMU with E4's kernel and an initrd
differing from the measured one only in `/init`. The flag set is S1's in all of
them; only the shell around it moves.

| # | arrangement | what happened | evidence |
|---|---|---|---|
| — | the measured initrd, untouched | `cannot read client sync file … EOF`, exit 128 — E4's failure, locally | output-01 |
| — | the same, `runsc --debug` | the same, and the log names `pivot_root … the root mount has a parent` in both the sentry and the gofer | output-02 |
| V1 | `mount --bind / /` | unchanged failure. And the bind itself never happened: `mount: mounting / on / failed: Invalid argument` (output-07, arrangement B) — a non-recursive bind of `/` is refused because `/` has mounts a user namespace has locked, which is E1's "locked children" artifact in a new place | output-03 |
| V2 | `mkdir /run/root; mount --rbind / /run/root; cd /run/root; chroot .` | **a different failure**: `cannot create gofer process: gofer: fork/exec /proc/self/exe: operation not permitted`. The root now has a parent, but the gofer's `clone(CLONE_NEWUSER)` is refused because the kernel calls a chroot'ed process chrooted, so runsc never reaches the pivot at all | output-04, output-06 |
| V3 | as V2 with a non-recursive `--bind` | `mount: mounting / on /run/root failed: Invalid argument`, then `chroot: can't execute 'sh': No such file or directory`, exit 127. The bind must be recursive | output-05 |
| **D** | `mkdir /run/root; mount --rbind / /run/root; cd /run/root; mount --move . /; chroot .` | **the workload's line, exit 0** | output-07 (probe), output-08 (as init.tdx) |

The choice between V2, D and four near-misses was made in one boot rather than
six, by a probe initrd that runs eight arrangements in eight fresh namespaces and
prefixes each with `busybox unshare -U true` — a one-token test of whether the
kernel will let runsc clone a user namespace from where it stands:

| arrangement | `unshare -U` | runsc |
|---|---|---|
| A: nothing (the baseline) | 0 | `EOF` — pivot_root has no parent |
| B: `mount --bind / /` | 0 | `EOF`; the bind was refused (EINVAL) |
| C: rbind under `/run`, `chroot` it | **1 (EPERM)** | `fork/exec … operation not permitted` |
| **D: rbind, `mount --move . /`, `chroot .` through the pinned cwd** | **0** | **`Linux workload 4.19.0-gvisor …`** |
| E: `mount --rbind / /`, `chroot /` | 1 (EPERM) | `fork/exec … operation not permitted` |
| F: rbind, move onto `/`, `chroot /` | 1 (EPERM) | `fork/exec … operation not permitted` |
| G: rbind, move onto `/`, no chroot | 1 (EPERM) | `fork/exec … operation not permitted` |
| H: init's own `busybox pivot_root . oldroot` | 0 | `pivot_root: Invalid argument`, then `EOF` |

E and F are worth keeping in view, because they are the two shapes a reader would
try first and both fail: resolving `/` does **not** enter a mount stacked on the
root — only the cwd captured before the move names the new mount — and a bind of
`/` onto `/` is not a bind at all.

## The mount table, and what is still true

`/` is still the initramfs, it is still `rw` while the workload runs, and there is
still no writable-and-executable check on this vendor. Nothing about the rule was
changed, relaxed or excepted; nothing under `pkg/` or `runsc/` was touched; the
runsc flag set is byte for byte spike S1's.

The table init prints after the workload, from output-08, is **identical line for
line to the one the unfixed initrd printed in output-01** (checked with `diff`),
which is the strongest thing E5 can say about the fix's blast radius:

    initrd: mount: rootfs / rootfs ro,size=959184k,nr_inodes=239796,inode64 0 0
    initrd: mount: devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,…
    initrd: mount: proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755,inode64 0 0
    initrd: mount: tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,inode64 0 0
    initrd: mount: configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: /dev/vda /config ext4 ro,nosuid,nodev,noexec,relatime 0 0
    initrd: mount: /dev/vdb /workload ext4 ro,nosuid,nodev,relatime 0 0

Two readings of that `ro` on the first line, and both matter. It is `ro` because
init remounts the initramfs read-only in the lines just above, after the workload
and before the listing — exactly as on E4's boot 2. **While runsc ran it was
`rw`**, and the probe's own listing from inside the namespace says so:
`initrd: probe: mount: rootfs / rootfs rw,size=959184k,…` (output-07,
arrangement D). So the asymmetry E4 recorded is untouched: on TDX the sandbox
runs over a writable, executable root, no check is consulted, and the SNP rule
(`docs/snp/image/init.rootfs:37-54`) still exists only on the other vendor.

Nothing the fix mounts is in that table, because `unshare -m` put all of it in a
namespace of its own that does not propagate out (E1/output-08). The one thing
the fix leaves behind outside the namespace is an empty directory, `/run/root`, on
a tmpfs that is measured nowhere; it holds no mount and appears in no table.

`/dev/vda` and `/dev/vdb` are where the hardware says `/dev/nvme0n2` and
`/dev/nvme0n3`: virtio-blk instead of NVMe. That is the whole of the device
difference, because **both devices are found by their ext4 volume label on both
machines** — there is no udev in this guest, so `--device-name` never becomes a
serial the kernel exposes, and init.tdx's fallback branch is the only one that has
ever run (E4 established that on the hardware).

## The cost

| | workload start -> exit | |
|---|---|---|
| this workstation, unfixed (output-01) | 3.59 -> 3.68 s | 0.09 s, a failure and not a measurement |
| this workstation, fixed (output-08) | 3.38 -> 3.59 s | **0.21 s** |
| SNP hardware, E3 guest A | 3.42 -> 4.27 s | 0.85 s |
| TDX hardware, E4 boot 2 | 1.96 -> 1.99 s | 0.03 s, the failure |

0.21 s against SNP's 0.85 s is not a vendor comparison: this is a 2-CPU QEMU guest
on a workstation whose page cache already holds the binary, against a measured
guest paging a 108 MB sandbox out of a dm-verity squashfs. What it establishes is
only that the sandbox starts and exits in a fraction of a second, so the boot-time
cost on the hardware is an ordinary sandbox start and not a timeout.

The initrd the fix produces is **86,551,997 bytes**, 1,044 bytes more than the one
E4 measured, with the same 52 entries: `/init` grew and nothing else moved. `mkdir`
and `chroot` are reached through `/bin/busybox` rather than through applet
symlinks precisely so that the initrd's file list stays what ticket 19 wrote.

## Scope, and what E5 cannot say

This is not a TDX guest. There is no TD, no MRTD, no RTMR, no `tsm_report` and no
gve: `insmod tdx-guest` fails, the report interface is absent, and tunneld refuses
to start with `tsm: creating the request …: no such device or address` — which is
what a non-confidential VM looks like from inside, and is step 9, two steps after
the one E5 is about. So E5 says nothing about the measurement, about RTMR2 or about
any verdict. What it does say is that the guest's *software* reaches step 8 and
that step 8 now succeeds, on the same kernel, the same initrd bytes, the same
bundle and the same mount options the hardware gets. The hardware's answer is
E4's `boot-3`.

Two harness facts, named so they are not mistaken for findings:

- **The addressing differs on purpose.** `network.conf` here is QEMU's
  user-networking segment (10.0.2.15/24, gateway 10.0.2.2, mtu 1500) rather than a
  VPC's /32 with an off-link gateway, because step 6 is fatal in init.tdx and step
  8 is behind it. The host route init adds to the gateway is redundant on an
  on-link segment; it is still added, because that is what the measured init does.
  Everything else on the config device is boot 2's bytes.
- **The device images are 64 MiB rather than 1 GiB.** A GCE custom image must be a
  whole number of gibibytes and a file handed to QEMU need not be. The bundle
  inside is E3's, built by E3's own script: `config.json 193382ad2dfce082…`, the
  same 632 bytes boot 2 carried.
