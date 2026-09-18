# E1 — PASS. The busybox applet suffices; no util-linux binary has to be measured

Ticket 24, experiment 1. Workstation only, 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t24`, branch `ticket-24-runsc-in-the-measured-guest`,
tip `a06ba786b`, no sudo, no hardware. Nothing under `pkg/` or `runsc/` changed.
(The worktree is shared with the rest of ticket 24: `docs/snp/image/*` was being
edited while E1 ran, and by the time E1 finished the tip had advanced to
`233658709`, an unrelated TDX-collateral commit. Nothing E1 produced was
committed, and E1 wrote nothing outside this directory.)
One runsc binary, built by `make runsc`:

    sha256 8070bcdf0b7889d8ed3710f5920f06cf909682434b21437eb9df8d7fb6c72518
    size   108668311 bytes

which is **the same 32 bytes S1 measured** — the bazel build is reproducible
across S1's tree and this one, so E1 is a driver experiment and nothing else.

**The verdict: yes, the applet suffices.** `/bin/busybox unshare -Urmnpf` produced
exactly the namespace, the uid/gid map and the capability set that S1's util-linux
`unshare -Urmnpf` produced, byte for byte where it is comparable, and S1's E2
configuration plus E3's flag ran under it unchanged: every workload exited 0 and
the guest init's check passed before, during and after
(output-01-e2-under-busybox-unshare.txt). Nothing has to be added to the
measurement. The image build already ships the applet
(`docs/snp/image/build-image.sh:191`, `unshare` is in `ROOT_APPLETS`), and
`/bin/busybox` is the pinned `busybox-static 1:1.36.1-6ubuntu3.1`
(`build-image.sh:103,125`), sha256 `dbac288c…6ac14`, one inode reached by both
`/bin/busybox` and `/usr/bin/busybox`.

**/proc must be remounted inside, and it is not optional.** Under `-Urmnpf`
without it, runsc does not start at all. The remount's options are the ones
`init.rootfs:21` already uses for the guest's own `/proc`:

    rw,nosuid,nodev,noexec        (relatime is added by the kernel)

## The line for the guest's init

What `docs/snp/image/init.rootfs:136` already has is right, and E1 ran it:

    unshare -Urmnpf sh -c "mount -t proc -o nosuid,nodev,noexec proc /proc; exec $RUNSC_CMD"

with `RUNSC_CMD` as at `init.rootfs:131`. In the guest both `unshare` and `mount`
in that line resolve to busybox applets, which is what E1 tested: the remount was
done with `busybox mount -t proc -o nosuid,nodev,noexec proc /proc`, exit 0, and
the workload ran (output-03, part 3b). Two notes on it, neither a correction:

- **`--mount-proc` is a one-token equivalent** and produces an identical mount:

      unshare -Urmnpf --mount-proc sh -c "exec $RUNSC_CMD"

  busybox's own procfs mount comes out `proc /proc proc rw,nosuid,nodev,noexec,relatime`
  — it supplies `nosuid,nodev,noexec` itself, so the check passes (variant e,
  output-02e; and output-03 part 3a). Either form is fine; the explicit one says
  out loud what the rule requires, which is why it is the better line to measure.
- **`--propagation` is not needed.** The applet makes the new namespace's `/`
  private by default: the driver's `/` carries `shared:1` and the same line inside
  `unshare -Urm` carries no propagation tag at all, and a tmpfs mounted inside was
  absent from the caller's `/proc/mounts` afterwards (output-08, sections 1-2).
  So nothing runsc mounts can propagate back into init's table, which is what
  `init.rootfs:140-147` asserts. (`--propagation unchanged` is, for the record,
  broken in this busybox: `unshare: can't mount none on / (flags:0x0): Invalid argument`.)

## The applet's usage string, verbatim

    BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.

    Usage: unshare [OPTIONS] [PROG ARGS]

    	-m,--mount[=FILE]	Unshare mount namespace
    	-u,--uts[=FILE]		Unshare UTS namespace (hostname etc.)
    	-i,--ipc[=FILE]		Unshare System V IPC namespace
    	-n,--net[=FILE]		Unshare network namespace
    	-p,--pid[=FILE]		Unshare PID namespace
    	-U,--user[=FILE]	Unshare user namespace
    	-f			Fork before execing PROG
    	-r			Map current user to root (implies -U)
    	--mount-proc[=DIR]	Mount /proc filesystem first (implies -m)
    	--propagation slave|shared|private|unchanged
    				Modify mount propagation in mount namespace
    	--setgroups allow|deny	Control the setgroups syscall in user namespaces

## The maps the applet produced

Identical in every variant that ran (`/proc/self/*`, inside):

    uid_map     0     253477          1
    gid_map     0     253477          1
    setgroups   deny
    CapInh 0, CapPrm = CapEff = CapBnd 0x1ffffffffff, CapAmb 0
    id          uid=0 gid=0 groups=65534,65534,65534,65534,0
    own pid     1                     (with -p -f; the driver's own pid otherwise)

Three things follow. `-r` writes the *single-ID* mapping S1 said suffices, so
`newuidmap` is never wanted. `-r` also writes `deny` to `setgroups` by itself —
`--setgroups deny` need not be passed, and runsc does not mind (it ran with deny
in every passing variant). And the full capability set is held **only inside that
user namespace**: the real uid stays 253477 and the caller's set outside is
untouched, exactly as S1 E4 concluded. In the guest, where init is uid 0 in the
initial user namespace, `-r` will write `0 0 1` instead; the sandbox and gofer
already show `0 0 1` here, because their mapping is made by runsc on top of this
one.

The processes runsc starts are unchanged from S1 E2, which is the point:

    gofer    uid_map/gid_map 0 0 1   CapEff 0x4001f   mounts: one line, the image bind ro,nosuid,nodev
    sandbox  uid_map/gid_map 0 0 1   CapEff 0x8001f   mounts: runsc-root / tmpfs ro
                                                              runsc-proc /proc tmpfs rw,nosuid,nodev,noexec
                                                              proc /proc/sandbox-proc proc ro,nosuid,nodev,noexec

and the check passes against each of those tables too. The state directory is
left holding nothing at all (`drwx------ 2 0 0 40 /run/runsc-state`), because
`--gofer-network-namespace=new` means the `null-netns` pin is never attempted —
S1 E3's result, reconfirmed under the new driver.

## The five variants

| variant | driver | runsc | the check | evidence |
|---|---|---|---|---|
| a | `-Urmnpf`, fresh procfs inside | **exit 0** ×3 | **PASS** before, during, after | output-02a (and output-01, the full S1 E2 script) |
| b | `-Urmnpf`, the driver's procfs, no remount | **exit 128** ×3, never starts | passes once the harness's own `/proc` submount is set aside | output-02b, output-06 |
| c | `-Urm` only, the driver's procfs | **exit 0** ×3 | passes, same proviso | output-02c |
| d | `-Ur` only, no mount namespace | **exit 0** ×3 | not a verdict: this ran on the workstation's root, 27 offending mounts | output-02d |
| e | `-Urmnpf --mount-proc` | **exit 0** ×3 | **PASS**, clean, no proviso | output-02e |

Workload output, in every variant that ran: `hi` then `bin dev proc sys tmp`, and
`Linux s1 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux`.

**No variant produced a warning of any kind.** The ticket asked what runsc warns
about in c, and what d's pin warning becomes: the answer to both is nothing.
S1 E4 case (c) saw `Unable to pin the gofer's network namespace … ; future gofers
will create new network namespaces` because a user namespace without a mount
namespace cannot bind-mount the pin; with `--gofer-network-namespace=new` the pin
is not attempted, so `-Ur` runs silently (output-02d has no warning line, and the
workstation's own mount table is unchanged at 57 lines with no `null-netns` —
output-08 section 4; that matters because d ran in the workstation's *own* mount
namespace, so a pin would have been permanent).

So `-p`, `-n` and even `-m` are not things runsc *needs*: it makes its own pid,
ipc, uts and network namespaces given a user namespace, and with the flag it
mounts nothing outside them. What the flags buy the guest is different and worth
keeping:

- **`-m`** keeps every mount runsc makes out of init's table. Nothing propagates
  out (output-08), so `init.rootfs:147`'s second dump should be identical to the
  first — which is a *check* the guest can make, not an assumption.
- **`-p -f`** makes the workload's processes a pid namespace whose death is
  guaranteed: when that pid 1 exits the kernel reaps the whole namespace, so a
  sandbox cannot outlive the workload and go on running before tunneld. Without
  `-p`, runsc's sandbox and gofer are ordinary children of init's namespace
  (visible by host pid in output-02c and output-02d).
- **`-n`** costs nothing and means the workload's namespace cannot see the guest's
  loopback even by accident. It is also what lets the harness mount a fresh sysfs.

`-p` is what forces the procfs remount, and the remount is what makes `-p` safe.
Take one and you must take the other; variant b is what taking only the first
looks like.

## Why b fails, precisely, and why the error names the wrong file

    running container: creating container: cannot create gofer process:
    gofer: fork/exec /proc/self/exe: permission denied

twice, and once, for the same command, `… : no such file or directory`
(output-02b lines 143, 148, 174). The message names `/proc/self/exe` and that
file is **not** the problem: in b's own namespace `/proc/self` resolves,
`/proc/self/exe` is a readable symlink to `/busybox`, `cat` of it returns all
2124608 bytes and executing it works — the probe does all four in each of the
four namespaces and they behave identically (output-05).

The failing path is a different one, and it is a pid number:

- with `--rootless`, runsc gives the gofer's `exec.Cmd` a user namespace and the
  spec's uid/gid mappings — `runsc/container/container.go:1646-1649`, via
  `specutils.SetUIDGIDMappings` (`runsc/specutils/namespace.go:193-216`), whose
  `log.Infof` at `:201` and `:209` is visible in the debug log right before the
  failure (output-06: `Mapping host uid 0 to container uid 0 (size=1)`). The
  namespace itself was added by `modifySpecForDirectfs`
  (`runsc/container/container.go:2134`, also in the log);
- `startInNS` turns that into `cmd.SysProcAttr.Cloneflags |= CLONE_NEWUSER`
  (`runsc/specutils/namespace.go:177`) and calls `cmd.Start()` (`:189`);
- Go's `os/exec` then writes the child's maps **from the parent**, through
  `/proc/<pid>/uid_map`, `/proc/<pid>/setgroups` and `/proc/<pid>/gid_map`
  (`/usr/local/go/src/syscall/exec_linux.go:713-731` and `:690`), where `<pid>`
  is the pid `clone(2)` returned — a pid in **runsc's own** pid namespace;
- the `/proc` runsc was handed in variant b numbers pids in the *driver's*
  namespace, an ancestor. runsc is pid 34 there (output-06); its child gets a pid
  like 35, and `/proc/35` in an initial-namespace procfs is some unrelated
  system process — writing its `uid_map` is `EACCES` — or is nothing at all,
  which is `ENOENT`. Both were observed for the same command, which is the
  signature of a pid looked up in the wrong namespace;
- and Go reports any error from that whole sequence as
  `&PathError{Op: "fork/exec", Path: name}` with `name` = argv[0]
  (`/usr/local/go/src/os/exec_posix.go:60`), which is why the message blames
  `/proc/self/exe`. `runsc/container/container.go:1686-1688` prints the command
  and wraps the error as `gofer: %v`; `:383` adds `cannot create gofer process`.

The requirement this states is sharper than "runsc needs a procfs": **runsc needs
a procfs that numbers pids in runsc's own pid namespace.** A fresh mount gives
that (a, e). Not making a pid namespace at all gives it too (c, d). An inherited
procfs plus a new pid namespace does not, and fails before the sandbox exists.

## Two harness artifacts, named so they are not mistaken for findings

Both come from modelling the guest on a workstation and neither can occur in the
measured guest. They are also the only reason variants b, c and 3b show the check
failing.

1. **A plain `mount --bind /proc` is refused inside a user namespace when `/proc`
   has child mounts.** `mount: … wrong fs type, bad option, bad superblock on
   /proc` — `EINVAL`. This workstation has two mounts on
   `/proc/sys/fs/binfmt_misc` (an autofs and a binfmt_misc); they are `MNT_LOCKED`
   in the copied mount namespace, and a non-recursive bind would unhide what they
   cover, which an unprivileged mounter may not do. `--rbind` succeeds and drags
   them along, and `umount -l` on them is refused. The autofs one is
   `rw,relatime` with **no noexec**, so the check trips on it — in b, c and 3b —
   and on nothing else. Each of those outputs therefore also runs the check with
   everything under `/proc/` removed, and it passes. The guest mounts nothing
   under `/proc` (`init.rootfs:21-24`), so there the plain bind is what would
   happen; variant e is the proof, where busybox's own fresh procfs has no
   children and the plain bind **succeeded** (output-02e, output-03 part 3a).
   Worth carrying forward all the same: if anything is ever mounted under the
   guest's `/proc`, a bind of it stops being possible and the check gains a line
   that has nothing to do with runsc.
2. **Variant c cannot have a real sysfs.** A fresh sysfs needs a network
   namespace owned by the current user namespace and `-Urm` has none, and a bind
   of `/sys` fails for the same locked-children reason. Nothing in this experiment
   reads `/sys` — the sentry has its own (S1 E4/output-02) — so
   `guest-like-ns-procbind.sh` falls back to an empty `nosuid,nodev,noexec` tmpfs
   and says which of the three it used. The guest mounts its own sysfs at
   `init.rootfs:22` and inherits it.

## Surprises

- **The runsc binary is bit-identical to S1's** (sha256 `8070bcdf…c72518`), from a
  different worktree and a different day. Nothing was expected of that; it means
  every S1 number can be compared to an E1 number without an "unless the build
  moved" clause.
- **`-Ur` alone runs the workload.** S1 E4 case (c) found it ran with a warning;
  with E3's flag there is no warning, no pin, and nothing at all in the caller's
  mount table. The mount namespace is therefore a containment choice, not a
  requirement — which is a stronger statement than S1 could make.
- **The error message in variant b points at the wrong file.** A reader who takes
  `fork/exec /proc/self/exe: permission denied` at face value will look at noexec
  mounts and file modes and find nothing wrong, because nothing is: the fault is a
  pid number resolved in an ancestor namespace. Recorded at length above for
  exactly that reason.
- **The workload's `uname -a` is gVisor's, not the guest's.**
  `Linux s1 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 GNU/Linux`
  against the guest-like namespace's own `6.11.0-rc3-snp-host-85ef1ac03941`. The
  hostname is the bundle's (`"hostname": "s1"`), and the kernel string is a
  sentry constant. A workload that reads the kernel version — to decide anything,
  or to put it in a report — learns a compile-time constant of runsc and nothing
  about the measured guest.
- **`--propagation unchanged` is broken in this busybox** (`can't mount none on /
  (flags:0x0)`). Not needed, but if anyone reaches for it, it does not work.

## What did not change from S1

Reconfirmed under the new driver, not re-litigated: the sentry's and gofer's mount
tables and capability sets; the sandbox's internal view (`9p ro` root, plus `/sys`,
`/dev`, `/proc`, `/dev/pts`, `/tmp` writable and invisible to any host table); the
empty state directory with `--gofer-network-namespace=new`; and S1's second
finding, that a bundle on a writable **noexec** mount cannot work — the last
section of output-01 puts the bundle on `/tmp` (`rw,nosuid,nodev,noexec`) and the
gofer dies before the sandbox exists, `exit 128`,
`cannot read client sync file: waiting for sandbox to start: EOF`, exactly as S1
E2 and E3 recorded. The workload image must sit on an exec-permitted read-only
mount, which is what `/workload` (`ro,exec,nosuid,nodev`) is.

## Scope

A user namespace shaped like the guest, not the guest: no SNP, no TDX, no measured
boot, no dm-verity root, and the guest kernel's own configuration (user
namespaces, nsfs, 9p, seccomp) is still untested. `init-mount-check.sh` is S1's
file byte for byte and still matches the guest init's loop, verified against both
the committed `init.rootfs` (where S1's line numbers 30-44 hold) and the working
tree, where ticket 24's own edits have moved the loop to lines 36-51
(output-07-the-check-is-still-S1s.txt). Nothing was committed; nothing outside
`docs/snp/evidence/ticket24/spikes/E1/` was written.
