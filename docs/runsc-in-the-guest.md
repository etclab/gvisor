# runsc in the measured guest

Ticket 24. Spike S1 proved on a workstation that runsc can run under the rule the SEV-SNP
image exists to have — no writable path is executable — given one flag. This is that result
inside the measurement on both vendors: the bazel-built static runsc and busybox's `unshare`
applet in the image, a read-only exec-permitted disk carrying one OCI bundle, a busybox
workload printing `uname -a` to the console, and tunneld starting afterwards unchanged.
Nothing under `pkg/` or `runsc/` changed — `git diff a06ba786b..HEAD -- attest pkg runsc` is
empty, so the sentry, the verifier and the tunnel are byte for byte what ticket 23 left. Five
spikes stand under it: `docs/snp/evidence/ticket24/spikes/E1` (the driver, workstation),
`E2` and `E3` (SEV-SNP hardware, three runs of the live scenario), `E4` (Google Cloud TDX,
three boots) and `E5` (eight local KVM boots of the measured TDX initrd). Work done
2026-09-18, base `a06ba786b`, 18 commits on the ticket branch; the tip is in the ticket's handoff. Nothing merged, nothing pushed.

**In one sentence:** S1's flag set needed no change on either vendor and was measured verbatim
into both images, but the *ground under it* did — a procfs that numbers pids in runsc's own pid
namespace, and on TDX a root mount with a parent, because `pivot_root(2)` cannot move an
initramfs; the 108 MB binary is 75 MB of SEV-SNP verity root and 76 MB of TDX initramfs, and it
costs no measurable SNP boot time and about 0.4 s of TDX initramfs unpack; and RTMR2 was
predicted offline before each boot and is the register the hardware reported, twice.

---

## The flag set as run in the guest

One string, defined identically in both inits and checked equal here byte for byte —
`docs/snp/image/init.rootfs:131` and `docs/snp/cloud/tdx/init.tdx:435`:

```
/usr/bin/runsc --root=/run/runsc-state --platform=systrap --network=none --ignore-cgroups \
               --rootless --gofer-network-namespace=new run --bundle /workload workload
```

with `root.readonly: true` in the bundle. That is spike S1's set unaltered, including the flag
that is the whole reason S1 exists: without `--gofer-network-namespace=new`, `pinNullNetNS`
(`runsc/container/null_netns.go:70-82`) bind-mounts an nsfs `rw` into `--root`, and the SNP rule
powers the guest off on exactly that one mount. `--root` is on `/run`, which is `rw,noexec`; the
state directory was left holding nothing at all, because with the flag the pin is never attempted.

**On SEV-SNP the driver around it is one line** (`init.rootfs:136`, echoed to the console at
`:134`):

```
unshare -Urmnpf sh -c "mount -t proc -o nosuid,nodev,noexec proc /proc; exec $RUNSC_CMD"
```

**The procfs remount is not optional**, and the error that says so names the wrong file. Without
it runsc does not start at all: `cannot create gofer process: gofer: fork/exec /proc/self/exe:
permission denied`, and for the same command sometimes `no such file or directory`. E1 followed it
through: `--rootless` gives the gofer's `exec.Cmd` a `CLONE_NEWUSER` and the spec's mappings
(`runsc/container/container.go:1646-1649`, `runsc/specutils/namespace.go:177,193-216`), and Go's
`os/exec` writes the child's maps *from the parent* through `/proc/<pid>/uid_map`
(`syscall/exec_linux.go:713-731`), where `<pid>` is the pid `clone(2)` returned — a pid in runsc's
own pid namespace. An inherited procfs numbers that pid in an ancestor namespace, so the write
lands on an unrelated process (`EACCES`) or on nothing (`ENOENT`), and Go reports either as
`&PathError{Op:"fork/exec", Path: argv[0]}`. The requirement is sharper than "runsc needs a
procfs": **runsc needs a procfs that numbers pids in runsc's own pid namespace.** `-p` forces the
remount and the remount makes `-p` safe; take one and you must take the other.

**On TDX the driver needs four more operations, and they are about the root**
(`init.tdx:434,436`):

```
unshare -Urmnpf sh -c "busybox mkdir -p /run/root; mount --rbind / /run/root; cd /run/root; \
    mount --move . /; exec busybox chroot . sh -c 'mount -t proc -o nosuid,nodev,noexec proc \
    /proc; exec $RUNSC_CMD'"
```

The sandbox and the gofer each `pivot_root(2)` on their way up
(`runsc/cmd/sandboxsetup/fs.go:45`, the error text at `:46`, reached from
`runsc/cmd/sentry/sentrycmd/chroot.go:181` and `runsc/cmd/sandboxsetup/gofer_mount.go:260`), and
the initramfs is the one mount in Linux with no parent — which is why `switch_root` exists. On
SEV-SNP `init.initrd` has switch_rooted into the verity squashfs long before this line, so the
root has a parent and the flag set works untouched. On TDX the initramfs *is* the measured root
and stays that way, so E4's boot 2 got `cannot read client sync file: waiting for sandbox to
start: EOF`, exit 128, with no `uname` line on the console. E5 reproduced that locally under plain
KVM on the measured initrd itself — `c409a79c…9b8e53`, 86,550,953 bytes, the file grub hashed into
RTMR2, not a rebuild — and a debug initrd made both dying processes say it in their own words:

```
W0918 10:34:34.895156  1 util.go:107] FATAL ERROR: error setting up chroot:
    pivot_root failed, make sure that the root mount has a parent: invalid argument   (the sentry)
W0918 10:34:34.880015  1 util.go:107] FATAL ERROR: failed to change the root file system:
    pivot_root failed, make sure that the root mount has a parent: invalid argument   (the gofer)
```

**Two kernel rules bite the same line of shell, and satisfying one alone fails.** `pivot_root(2)`
refuses a root with no parent, so a recursive bind of `/` under the `/run` tmpfs is needed — a
mount whose parent is that tmpfs. But `clone(CLONE_NEWUSER)` is refused `EPERM` for a process the
kernel considers chrooted (`current_chrooted()` compares the process's root with the *mount
namespace's* root followed down through whatever is mounted on it), and runsc-rootless clones a
user namespace for the gofer. So the bind must also be **moved onto `/`** and entered through the
working directory pinned to it before the move: the namespace root then follows down into exactly
that mount, and the process is not chrooted. The first without the second gives `fork/exec
/proc/self/exe: operation not permitted`; the second without the first gives the `EOF`. E5 decided
among eight arrangements in one boot, prefixing each with `busybox unshare -U true` — a one-token
test of whether the kernel will let runsc clone a user namespace from where it stands:

| arrangement | `unshare -U` | runsc |
|---|---|---|
| A: nothing (E4's boot 2) | 0 | `EOF` — `pivot_root` has no parent |
| B: `mount --bind / /` | 0 | `EOF`; the bind itself was refused `EINVAL` |
| C: rbind under `/run`, `chroot` it | **1 (EPERM)** | `fork/exec … operation not permitted` |
| **D: rbind, `mount --move . /`, `chroot .` through the pinned cwd** | **0** | **`Linux workload 4.19.0-gvisor …`** |
| E: `mount --rbind / /`, `chroot /` | 1 (EPERM) | `fork/exec … operation not permitted` |
| F: rbind, move onto `/`, `chroot /` | 1 (EPERM) | `fork/exec … operation not permitted` |
| G: rbind, move onto `/`, no chroot | 1 (EPERM) | `fork/exec … operation not permitted` |
| H: init's own `busybox pivot_root . oldroot` | 0 | `pivot_root: Invalid argument`, then `EOF` |

E and F are the two shapes a reader tries first and both fail: resolving `/` does **not** enter a
mount stacked on the root — only the cwd captured before the move names it — and a bind of `/`
onto `/` is not a bind. H is the same rule from init's side: no parent to hang `put_old` on, so
init cannot pivot either. (E5 also booted three whole-init variants, V1–V3, one per candidate
line, and they agree with A, C and the non-recursive bind.) Nothing is deleted and nothing is
switched: the initramfs is still the root of init's mount namespace, the table init prints
afterwards is identical line for line to the unfixed initrd's (checked with `diff`), and the one
thing the fix leaves outside the namespace is an empty `/run/root` on a tmpfs.

## What `unshare` had to be

**busybox's applet, and nothing else had to be measured.** E1 rebuilt S1's guest-like namespace
with `/bin/busybox unshare -Urmnpf` and got the same namespace, maps and capability set S1's
util-linux binary produced, byte for byte where comparable; S1's E2 configuration plus E3's flag
ran under it unchanged, every workload exited 0, and the check passed before, during and after.
The applet was already in the SNP list and is ticket 24's one addition to each
(`docs/snp/image/build-image.sh:191`, `docs/snp/cloud/tdx/build-tdx-image.sh:348`); `/bin/busybox`
is the pinned `busybox-static 1:1.36.1-6ubuntu3.1`, sha256 `dbac288c…6ac14`.

`-r` writes the *single-ID* mapping S1 said suffices — `0 253477 1` on the workstation, `0 0 1` in
the guest, where init is uid 0 in the initial user namespace — and writes `setgroups deny` by
itself, so `newuidmap` is never wanted and `--setgroups deny` need not be passed. The full
capability set is held only inside that namespace: the caller's set outside is `CapEff=0` and the
real uid is unchanged, which is S1's capability answer reconfirmed under the new driver.

| variant | driver | runsc | the check |
|---|---|---|---|
| a | `-Urmnpf`, fresh procfs inside | **exit 0** ×3 | **PASS** before, during, after |
| b | `-Urmnpf`, the driver's procfs, no remount | **exit 128** ×3, never starts | passes once a harness submount is set aside |
| c | `-Urm` only | exit 0 ×3 | passes, same proviso |
| d | `-Ur` only, no mount namespace | exit 0 ×3 | not a verdict: ran on the workstation's root |
| e | `-Urmnpf --mount-proc` | exit 0 ×3 | **PASS**, clean |

`--mount-proc` is a one-token equivalent producing an identical mount — busybox supplies
`nosuid,nodev,noexec` itself — and either form is fine; the explicit one is measured because it
says out loud what the rule requires. `--propagation` is not needed: the applet makes the new
namespace's `/` private by default, so nothing runsc mounts can propagate back into init's table.
**No variant produced a warning of any kind**: with `--gofer-network-namespace=new` the pin is not
attempted, so even `-Ur`, which S1 saw warn, runs silently. So `-p`, `-n` and `-m` are not things
runsc *needs* — it makes its own pid, ipc, uts and network namespaces given a user namespace.
What they buy the guest is `-m` keeping every runsc mount out of init's table, `-p -f` making the
workload a pid namespace whose death the kernel guarantees (a sandbox cannot outlive the workload
and go on running before tunneld), and `-n` costing nothing.

## Where the workload lives, and what that means

**On a read-only, exec-permitted mount outside the measurement**, which is S1's second finding
made into a decision. The gofer bind-mounts the bundle's rootfs and remounts it read-only with
`MS_RDONLY|MS_NOSUID|MS_NODEV` and **no** `MS_NOEXEC` (`gofer_mount.go:250`); those flags are
locked for a mount made inside a user namespace, so a remount omitting one is asking to clear it
and the kernel answers `EPERM`. A noexec source cannot be served at all. `/run` and `/tmp`
(`rw,noexec`) and the config device (`ro,noexec`) therefore do not qualify.

The device is a sibling of the config device in every respect but that one word. New scripts
`docs/snp/image/mkworkloaddev.sh` and `docs/snp/cloud/tdx/mkworkloaddev-tdx.sh` build an ext4
image without a journal from a source directory laid out as `/workload` will be; the SNP launcher
attaches it as a third virtio-blk with serial `attested-workload`
(`docs/snp/image/launch-measured-guest.sh:87-90`, behind `-workload`), the TDX smoke script
publishes it and attaches it with `--device-name attested-workload`
(`docs/snp/cloud/tdx/smoke-tdx-guest.sh:236-238`, behind `WORKLOAD_RAW`); `init.initrd:101-109`
and `init.tdx:225-300` find it and mount it `ro,exec,nosuid,nodev`, and list what they mounted as
the config device is listed.

```
initrd: workload device /dev/vdc mounted at /workload (ro,exec,nosuid,nodev; not measured)
init: mount: /dev/vdc /workload ext4 ro,nosuid,nodev,relatime 0 0
init: mount: /dev/vdb /config   ext4 ro,nosuid,nodev,noexec,relatime 0 0
```

The console line and the table are not in disagreement: `exec` is the *absence* of `MS_NOEXEC`, so
there is no option for `/proc/mounts` to print. The mount is `ro`, so the rule — which constrains
writable mounts — has nothing to say about it, and needed no exception to say nothing.

**What is measured, said once so it is not confused.** The launch measurement and RTMR2 cover
runsc (`build-image.sh:195`, `build-tdx-image.sh:375`), the flag set init launches it with
(`init.rootfs:131`, `init.tdx:435`) and the options these mounts are made with
(`init.initrd:102`, `init.tdx:290`) — the empty `/workload` directory in the image too
(`build-image.sh:185`, `build-tdx-image.sh:362`). The disk's *contents* are outside both, and
nothing in this record, in either script or in either manifest describes them as measured.
Changing the bundle does not change a register and is not claimed to.

**Two findings about building that disk, both found by reading the image back rather than by a
failure.** `mke2fs -E root_owner=0:0` owns **only the root directory**; everything `-d` copies
keeps the uid of whoever ran the script. That is not cosmetic: runsc's user namespace maps one id,
and a capability over a file is only a capability when the file's owner is mapped into the
namespace (`capable_wrt_inode_uidgid`, `user_namespaces(7)`), so a bundle owned by an unmapped uid
is refused on modes the host would have let root through. Both scripts set every inode to `0:0`
with `debugfs` afterwards and then check that they did, refusing to finish if not
(`mkworkloaddev.sh:57,68-71,75-78`). And ext4 stores sixteen bytes of label while
`attested-workload` is seventeen, so `mke2fs` warns and writes `attested-workloa`; the warning is
left visible. On SNP nothing reads it — the virtio-blk serial carries the whole name. On TDX it is
what is actually used: `find_workload_dev` (`init.tdx:256-276`) tries the NVMe serial first, and
Google exposes `serial='nvme_card-pd'` on every namespace, so the truncated-label branch at
`:269-274` is the only one that has ever run, on the hardware and under QEMU alike.

The bundle itself is one file and one static binary: `config.json`, 632 bytes,
`193382ad2dfce082…`, whose `process.args` is `["/bin/sh","-c","uname -a"]` and whose `hostname` is
`workload`, over a rootfs holding the pinned busybox, 2,124,608 bytes, `dbac288c29ba5684…`, with
`sh` and `uname` as symlinks to it. The same bundle ran on both vendors and in all four passing
boots; boot 3's workload device is boot 2's file byte for byte.

## What it costs

### SEV-SNP (E2, E3)

| file | ticket 22 | ticket 24 | delta | what it is |
|---|---|---|---|---|
| `rootfs.img` | 9,977,856 | 85,319,680 | **+75,341,824 (8.55x)** | measured through `verity.roothash` on the command line |
| `initrd.img` | 1,507,232 | 1,508,081 | +849 | `init.initrd`'s workload-device block |
| `cmdline.txt` | 195 | 197 | +2 | the verity data-block count gaining a digit |
| `tunneld` | 17,569,474 | 17,573,981 | +4,507 | not this ticket's (three days and several commits apart) |
| `vmlinuz`, `OVMF.fd` | | | 0 | unchanged |

The 108,668,311-byte binary costs 75.34 MB of image because zstd squashfs compresses it, and the
dm-verity tree over it went from **2,416 to 20,665** data blocks of 4,096 bytes. **No measurable
boot-time cost**, and structurally rather than luckily: the squashfs is mapped through dm-verity
off a virtio-blk disk and paged in on demand, so a byte nobody reads is never read. The last
printk before the verdict moved to `[3.134052]` on guest A and `[2.690345]` on guest B against
ticket 22's `[2.792852]` and `[3.137863]` — one guest faster, one slower, by more than the
difference between the images.

Init's own clock (`uptime_say`, `/proc/uptime` read by the shell, `init.rootfs:18`):

| boot | check verdict | workload start | workload exit | the sandbox | tunneld |
|---|---|---|---|---|---|
| E3 guest A, disk attached | 2.99 s | 3.42 s | 4.27 s | **0.85 s** | 4.29 s |
| E3 guest B, disk attached | 3.17 s | 3.60 s | 4.50 s | **0.90 s** | 4.51 s |
| E3 guest A, no disk | 2.62 s | — | — | — | 3.21 s |
| E3 guest B, no disk | 3.03 s | — | — | — | 3.47 s |
| E2 guest A, no disk | 3.16 s | — | — | — | 3.67 s |
| E2 guest B, no disk | 2.73 s | — | — | — | 3.16 s |

Under a second, start to exit, for a sandbox that is a 108 MB binary paged out of a dm-verity
squashfs — and it is spent before tunneld exists. The workload's line, not its exit status, is the
evidence: `Linux workload 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux`.
`4.19.0-gvisor` is the sentry's compile-time constant against this guest's own
`6.16.0-snp-guest-038d61fd6422`, which init prints twenty lines earlier, and `workload` is the
bundle's `hostname` — so neither half of that line can have come from the guest.

**The rule passed, untouched, on every guest**: `init: no writable path is executable`, the loop
at `init.rootfs:37-54` byte for byte what it was, with the fatal poweroff at `:48-53` never
reached. E1's `init-mount-check.sh` is S1's file and still matches it. Eight mount lines with no
disk and nine with it, three of them writable and all three `noexec`. **Nothing runsc made is
visible in init's namespace**: the table printed after the workload (`init.rootfs:147`) is the
same nine lines as before it — no `runsc-root`, no `runsc-proc`, no `nsfs`, no `null-netns`,
nothing under `/run/runsc-state`. That table is a second and weaker question than the check's,
which ran once before anything else and whose verdict decided the boot.

**Disk absent is two lines and a boot that continues** — the ordinary case, and every scenario
recorded before this ticket: `initrd: no workload device (virtio-blk serial attested-workload);
the boot continues without a workload`, then `init: no workload bundle at /workload/config.json;
continuing to tunneld`. `runsc` is never executed; the empty `/workload` in the squashfs is a
mount point with nothing on it rather than a missing path.

Three runs of the `live` scenario — E2 with no disk, E3 with and without — six guest boots,
`=== 29 passed, 0 failed ===` on each: attested, mutually admitted, a tunnel established,
exchanges warm and concurrent, the relay carrying it and finding no plaintext, no address resolved
off the segment. The ceiling digest is ticket 22's unchanged
`197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973` — runsc is not in
`attest/ceiling`, so what a guest presents as its policy did not move. Running a sandbox before
tunneld changed nothing about what a peer sees, which is the property ticket 25 needs.

### Google Cloud TDX (E4, E5)

| file | ticket 19 image-a | ticket 24 image-a | image-b (E5's fix) | what it is |
|---|---|---|---|---|
| `initrd.img` | 10,446,197 (49 entries) | 86,550,953 (52) | 86,551,997 (52) | measured **whole** into RTMR2 by grub |
| `init.tdx` | | 22,416 | 24,513 (+2,097) | the fix and the paragraph explaining it |
| `disk.raw` | 10,737,418,240 | same | same | 10 GiB, two files rewritten on `/boot` |
| `vmlinuz` | 16,775,240 | same | same | the provider's own kernel |
| `grub.cfg` | 272 | same | same | byte for byte identical |

`gzip -9` over the cpio turns the 108,668,311-byte runsc into 76,104,756 bytes of initrd, 70.0% of
the binary, and **every one of those bytes is inside RTMR2**, because here the initramfs is the
root and grub measures it whole. On SEV-SNP the same binary cost the initrd 849 bytes and the
verity root 75 MB. The three new cpio entries are `/usr/bin/runsc`, `dir /workload` and the
`unshare` applet symlink; E5's fix adds none — `mkdir` and `chroot` are reached through
`/bin/busybox` rather than through applet symlinks precisely so the file list stays what ticket 19
wrote (`build-tdx-image.sh:348,373`), and 2,097 bytes of shell became 1,044 bytes of gzipped
initrd.

| kernel-side anchor | ticket 19 | boot 2 | boot 3 |
|---|---|---|---|
| `RAMDISK: [mem …]` | 10,448,896 | 86,552,576 | 86,552,576 |
| `Trying to unpack rootfs image as initramfs` | 1.576365 | 1.963035 | 1.910563 |
| `Freeing initrd memory` | 1.698789 (10,204K) | 2.497169 (84,524K) | 2.438673 (84,524K) |
| unpack | **0.1224 s** | **0.5341 s** | 0.5281 s |
| `Run /init as init process` | 2.325758 | 2.708962 | 2.648935 |

An eight-fold initrd costs about 0.4 s of kernel boot, nearly all of it the unpack. Boot 3 is
0.06 s *faster* than boot 2 on an initrd 1,044 bytes larger, which is run-to-run noise on a cloud
instance. **Two caveats.** Grub's own read and SHA-384 of the 86 MB initrd happens before the
kernel's clock exists and appears in no timestamp here; whatever it costs is unmeasured. And
ticket 19's console carries no clock after `Run /init`, so "time to tunneld" cannot be compared
against it at all.

| initrd clock (`/proc/uptime`) | boot 2 | boot 3 |
|---|---|---|
| egress proof done | 1.96 s | 1.96 s |
| workload start → exit | 1.96 → 1.99 s (**failed**, exit 128) | 1.96 → 2.04 s (**ran**, exit 0) |
| the sandbox | 0.03 s, a failure | **0.08 s** |
| tunneld | 2.00 s | 2.06 s, evidence acquired in 41 ms |

Boot 3 printed the same line E3's SNP guest printed, against this guest's own `6.17.0-1022-gcp`.
E5's local KVM boots put the fixed sandbox at 0.21 s against the unfixed 0.09 s of dying; that is
not a vendor comparison — a 2-CPU QEMU guest whose page cache already holds the binary against a
measured guest paging it out of a dm-verity squashfs — and all it establishes is that the hardware
cost is an ordinary sandbox start and not a timeout.

The TDX mount table is E3's but for the device nodes, `/dev/nvme0n2 /config … noexec` and
`/dev/nvme0n3 /workload ext4 ro,nosuid,nodev`, and the initrd lists the bundle file by file with
sizes and digest prefixes (`init.tdx:292-294`). **On TDX the network is already up when the
workload runs and on SNP it is not**: the SNP init runs the workload before tunneld brings the
link up out of the run configuration, so there is no link to leave by at all; on TDX step 6 has
already configured `eth0`, and the only things between the workload and the guest's network are
`--network=none` and the network namespace `unshare -n` makes. Both are inside the measurement and
neither was exercised by these boots.

## The RTMR2 match, and the RTMR0 finding

Both TDX images' RTMR2 were predicted by `predict-rtmr2.py --raw` from the image and from nothing
else, **before any instance existed**, and both are the register the hardware reported:

| image | predicted at | RTMR2 predicted and reported | records |
|---|---|---|---|
| image-a (boot 2) | 09:53:38Z, boot at 10:15Z | `cd68e874bbfb15b746ba0679fb4a0bc3fe967b5b616a635fbd47f48538135af0ab229810fb3d293273a8c4e1438f6e25` | 25 |
| image-b (boot 3) | 10:49:27Z and again by hand 10:50:41Z, boot at 11:02Z | `038e7905a2853bf89285a1e967388a9a8cb5a996830f1eee63d036af532cb25f3d6c7636e071e01663a876dc64ca0b78` | 25 |

**MATCH** both times, and in each case **exactly one record of twenty-five moved** — record 24,
the initrd's own digest — against ticket 19's image-a (`d5ddcc42…3e0d`) and then against image-a
respectively. The vmlinuz, the grub.cfg, the GPT and every partition grub reads on the way are the
provider's constants; the initrd is the only thing in RTMR2 this ticket authored. So a 108 MB
binary inside the measured initramfs is still predictable offline, and — the sharper version of
the question — so is an edit to the measured `/init` itself.

MRTD `c1ee9c16…70a5` and RTMR1 `02c7f19c…913b` are the pinned provider constants and matched.
**RTMR0 did not**, on both boots:

| register | what the set pins | what the hardware reported | |
|---|---|---|---|
| RTMR2 | predicted offline | equal | **equal** |
| MRTD | `c1ee9c16…70a5` | `c1ee9c16…70a5` | equal |
| RTMR1 | `02c7f19c…913b` \| `3a446943…d691` | `02c7f19c…913b` | equal, the first-boot value |
| RTMR0 | `c2fc12a5…850a` (two disks) | `8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f` | **different** |

Both the guest's own self-check and this workstation judging the same quote against the same signed
set refused, and both on RTMR0 alone:

```
tunneld: SELFCHECK VERDICT REFUSED reason=launch measurement not in the reference value set
the TD's observed RTMR0 is 8ee4fa36…b70a3f, which is none of the 1 values this reference value lists
```

`8ee4fa36…b70a3f` is what a **three**-disk `c3-standard-4` TDX guest reports — boot, config,
workload. Every value recorded before it was a one-disk (`c0b8b19c…896d`) or two-disk
(`c2fc12a5…850a`) shape, and ticket 19 established by experiment that RTMR0 moves when the shape
does, so this was expected: it is a fact about the provider's firmware configuration and not about
this image. **It was observed twice and authored nowhere** — not in `build-tdx-image.sh`'s `RTMR0`
default, not in either image's `reference-values.json`, not in any build parameter this ticket
touched, because a measurement is never read off a booted machine into a reference value. Read the
two answers apart: the prediction matched, and the set refuses this machine shape.

**The collateral this was judged against** was refreshed the same day and before the boot,
2026-09-18T08:51:43Z, valid until 2026-10-18T07:56:25Z (the TCB info's `nextUpdate`, earliest of
the four), and ADR-0007's status line now says so. Ticket 22's deviation is carried forward: it was
four curl requests, because `attest-tool provision fetch` is the AMD chain tool and has no vendor
flag, so what is checked is the result — `attest-tool verify -vendor intel-tdx` reproduces ticket
19's ACCEPTED verdict field for field, and the ticket 21 byte-level replay of all 64 live
invocations gives an identical exit-status histogram (0: 8, 1: 15, 2: 37, 3: 4) with exactly one
transcript differing, inside a quoted date. No TCB moved (`tcbEvaluationDataNumber` still 20), so
no reference value's floor had to move.

## What did not hold

- **The workload did not run on TDX at the first attempt.** E4's boot 2 reached the sandbox and
  the sandbox died, exit 128, on an initrd whose RTMR2 matched perfectly. E4 named the cause as a
  hypothesis and stopped, as the ticket requires; E5 turned it into a fact and a three-operation
  fix in `init.tdx`, and boot 3 is the hardware's answer. The flag set never changed and the
  writable-must-be-noexec rule was never changed, relaxed or excepted.
- **Boot 1 was thrown away by a variable-name collision this ticket introduced.** The new `LABEL`
  knob in `smoke-tdx-guest.sh` is the Compute Engine resource label; `mkconfigdev-tdx.sh`'s
  `LABEL` is the ext4 volume label. A value given in the *environment* is exported, so it reached
  the device builder, the config device went out labelled `purpose=attested`, and the guest halted
  after thirty seconds looking for `attested-config`, never reaching runsc. The fix is one call
  wrapped in `env -u LABEL`, checked on the workstation before boot 2. Cost: one instance, four
  minutes. `boot-1/` is kept whole.
- **Neither TDX boot was admitted**, on RTMR0 and nothing else, twice. The smoke script's
  composite verdict therefore reads `INCOMPLETE`, because it wants both the RTMR2 match and an
  admitted guest.
- **`reason=` does not name the register.** Both the guest and the workstation say "launch
  measurement not in the reference value set" for an RTMR0 mismatch; only the operator log names
  RTMR0. A reader who takes `reason=` at face value will look at RTMR2, which was right.
- **`/proc/uptime` reads about a second behind the printk clock** on the TDX guest. Deltas within
  one clock are still deltas, and every workload number here is uptime-to-uptime.
- **E5 is not a TDX guest.** No TD, no MRTD, no RTMR, no `tsm_report`, no gve; `insmod tdx-guest`
  fails and tunneld refuses to start with `tsm: creating the request …: no such device or
  address`, which is step 9, two steps past the one E5 is about. E5 says nothing about the
  measurement or about any verdict — only that the guest's software reaches step 8 and that step 8
  now succeeds, on the same kernel, the same initrd bytes, the same bundle and the same mount
  options the hardware gets.
- **E1's two harness artifacts are not findings**, and are the only reason variants b and c show
  the check failing. A plain `mount --bind /proc` is refused inside a user namespace when `/proc`
  has child mounts, which this workstation has and the guest does not (`init.rootfs:21-25` mounts
  nothing under `/proc`); and variant c cannot have a real sysfs, so it used an empty noexec
  tmpfs. Neither can occur in the measured guest.

## Leftovers

1. **The TDX rule asymmetry — informational, recorded and deliberately not changed.**
   `docs/snp/image/init.rootfs:37-54` walks `/proc/mounts` before anything else and powers the
   guest off if any writable mount is executable. `init.tdx:449-458` has no such check: it only
   remounts the initramfs read-only *after* the workload and lists the table. So on TDX runsc ran
   with a writable, executable `/` underneath it — the probe's own listing from inside the
   namespace says `rootfs / rootfs rw,…` — and the rule the whole of spike S1 was about proving
   compatible with was, on this vendor, never consulted. The bind/move/chroot changes nothing
   about that table. This was already true in ticket 19; the ticket's decision is that it is a
   leftover to record, and this is the record.
2. **The three-disk RTMR0 is unpinned.** Ticket 25 or 26 must observe `8ee4fa36…b70a3f` for the
   three-disk shape and author it deliberately, the way ticket 19 authored the two-disk value, or
   attach no third disk. Until then every three-disk TDX guest is refused.
3. **`busybox mkdir` and `busybox chroot` are reached through the multi-call binary** rather than
   through applet symlinks, so that no cpio entry is added and the initrd's file list stays ticket
   19's. House style would add two `slink` lines to `build-tdx-image.sh`'s `APPLETS` (`:348`) —
   and a new RTMR2 with them.
4. **`reason=` still does not name the register** (as ticket 19 also found).
5. **The `/proc/uptime` vs printk skew of about a second** on the TDX guest.
6. **`mkconfigdev.sh:55` says "all files owned by root"** and is inaccurate for exactly the
   `mke2fs -E root_owner` reason the workload scripts fix; the config-device scripts were not
   touched.
7. **The smoke script's composite verdict prints `INCOMPLETE`** when RTMR2 matches and the guest
   is refused, which conflates the two answers a reader wants apart.
8. **The workload's `uname` is the sentry's constant.** `4.19.0-gvisor`, always, and the nodename
   is the bundle's. A workload that reads the kernel version learns a compile-time constant of
   runsc and nothing about the measured guest it is in. It matters for ticket 25 if anything
   inside is ever meant to reason about where it is.
9. **Stale collateral-expiry prose**, still saying 2026-10-08: `docs/tdx-verifier.md:177`,
   `docs/two-guests-on-tdx.md:366`, `docs/snp/cloud/tdx/SCENARIOS.md:100`. ADR-0007's own status
   line is current.
10. **The staging bucket names still say t19.** `publish-tdx-image.sh:35-36` defaults to
    `attested-tunnel-t19-*` and `purpose=attested-tunnel-t19`; this ticket passed the t24 labels
    and did not change the script, so eight buckets carry a t19 name and a t24 label.
11. **Init launches runsc for this ticket only**, so the boot has something to prove, and the
    workload runs to completion *before* tunneld exists — there is no concurrency between them at
    all yet. Ticket 25 moves the launch under the adapter.
12. **What the guest still lacks for ticket 25.** No request channel into the sandbox: the bundle
    is fixed at build time and nothing carries work in. Tunneld's socket is not reachable from
    inside — the sandbox gets `--network=none`, which is the boot ceiling, and no
    `-sandbox-socket` was passed to anything here. No policy is applied to the sandbox: nothing
    parses `n`, `f` or `x` and nothing narrows the flag set. And no liveness: init waits for the
    workload to exit and then starts tunneld, so ticket 23's finding that "apply then ack" is not
    enough when apply starts a process is untested here rather than answered.
13. **One correction to the carried-forward list.** The two ticket 21 leftovers — the old tool
    name on tunneld's console and `readAuthorKey` duplicated between `cmd/tunneld` and
    `cmd/attest-tool` — were **already fixed by ticket 22**, not left for this rebuild:
    `attest/cmd/tunneld/selfcheck.go:132` says `attest-tool verify` and `attest/refvalsfile.go:339`
    is the one `attest.ReadAuthorKey`. Nothing was owed here and nothing was done. What remains of
    that set is the third string ticket 21 named and ticket 22 did not take:
    `attest/tsm/tsm.go:116` still credits `cmd/provision-chain`, a program that stopped existing in
    ticket 21. `docs/shrink.md:234-244` still reads as though both tunneld items were open.

## The cloud, and what it cost

Three `c3-standard-4` TDX instances in `us-central1-a` — `tdx-t24-a` twice (boots 1 and 2) and
`tdx-t24-b` (boot 3) — each created and deleted the same hour, the longest-lived at roughly four
minutes, **about eleven instance-minutes in all**. Eight custom images published and all eight
deleted; eight staging buckets created and deleted inside the runs that made them. The ledger, on
create and on delete, is `docs/snp/cloud/tdx/RESOURCES.md:106-178`, with the teardown listings in
`docs/snp/evidence/ticket24/spikes/E4/teardown.txt`. No pre-existing instance was touched. E5 cost
nothing: eight local KVM boots, unprivileged, no cloud resource and no sudo.

## Evidence

| what | where |
|---|---|
| spike S1, the flag set and the two findings this ticket builds on | `docs/snp/evidence/spike-s1-runsc-in-guest/README.md` |
| E1, the busybox-only driver: five variants, the maps, why variant b fails | `docs/snp/evidence/ticket24/spikes/E1/` (`notes.md`, `output-01`–`output-08`) |
| E2, the SNP image with runsc in it, booted with no workload disk | `docs/snp/evidence/ticket24/spikes/E2/` (`notes.md`, `sizes.txt`, `manifest.txt`, `predicted-measurement.txt`, `capture/`) |
| E3, the workload disk: one boot with it and one without, same image | `docs/snp/evidence/ticket24/spikes/E3/` (`notes.md`, `config.json`, `with-disk/`, `without-disk/`) |
| E4, TDX: two images, three boots, the offline predictions and the quotes | `docs/snp/evidence/ticket24/spikes/E4/` (`notes.md`, `image/`, `image-b/`, `boot-1/`, `boot-2/`, `boot-3/`, `teardown.txt`) |
| E5, why the sandbox died and the three operations that fix it | `docs/snp/evidence/ticket24/spikes/E5/` (`notes.md`, `output-01`–`output-08`, the six init variants) |
| the Intel collateral refresh, the verify and the byte-level replay | `docs/snp/evidence/ticket24/collateral-refresh.txt`, `docs/snp/evidence/tdx/collateral/FETCH.txt`, `docs/adr/0007-provisioned-intel-collateral.md` |
| every cloud instance, image and bucket, on create and on delete | `docs/snp/cloud/tdx/RESOURCES.md` |
| the code as it stands | `init.rootfs:105-150`, `init.initrd:79-109`, `init.tdx:225-300,378-447`, `mkworkloaddev.sh`, `mkworkloaddev-tdx.sh`, `build-image.sh:153-195`, `build-tdx-image.sh:308-375`, `launch-measured-guest.sh:87-90`, `smoke-tdx-guest.sh:232-255` |

Each spike directory holds its script, its untrimmed output and a `notes.md`, as the ticket
requires. The 10 GiB `disk.raw` files and the workload device images are not kept: they are not
measured, they are reproducible from the manifests and the pinned base disk, and they were deleted
after their boots.
