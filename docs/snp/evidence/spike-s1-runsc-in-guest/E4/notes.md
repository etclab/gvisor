# E4 — a real workload runs, and a user namespace is all systrap's CAP_SYS_PTRACE needs

Spike S1, experiment 4. Same runsc binary as E1 and E2 (sha256 8070bcdf…, built
from ebbe8cba8), same unprivileged user (pniroula, uid 253477), no sudo,
workstation only, nothing rebuilt. E2's configuration throughout part 1: inside
a guest-like `unshare -Urmnpf` namespace whose every writable mount is noexec,
`--root=<state on /run> --platform=systrap --network=none --ignore-cgroups
--rootless run --bundle <bundle> <id>`, `root.readonly: true`, rootfs a
directory holding a static busybox on an exec-permitted read-only bind.

## 1. The workload ran

`/bin/busybox sh -c 'echo hi; ls /'` — exit 0, and the sandbox printed:

    hi
    bin
    dev
    proc
    sys
    tmp

(output-01-workloads.txt section 2). The E1/E2 trivial workload (`true`) was run
first in the same session for comparison and also exited 0, as did the second
E4 workload and both live variants — five containers, all exit 0.

The guest init's check still fails, for the one reason E2 recorded and E3 has
since fixed: the pinned `null-netns` nsfs mount, `rw` with no `noexec`. E4
changes nothing about that; it appears once per `--root` directory, and this
experiment used a separate `--root` per container, so five of them accumulate.
Not this experiment's subject.

## 2. The sandbox's view of its filesystem

From `/bin/busybox sh -c 'cat /proc/mounts; ls -la /; id; cat /proc/self/status
| grep -i cap'`, in full in output-02-sandbox-view.txt:

    none /         9p     ro,trans=fd,…,cache=fscache,…,directfs
    none /sys      sysfs  rw,dentry_cache_limit=1000
    none /dev      dev    rw,mode=0755
    none /proc     proc   rw,dentry_cache_limit=1000
    none /dev/pts  devpts rw
    none /tmp      tmpfs  rw,mode=01777

    drwxr-xr-x 2 0 0 4096 bin       dr-xr-xr-x 9 0 0 0 proc
    drwxr-xr-x 6 0 0  360 dev       drwxr-xr-x 12 0 0 0 sys
                                    drwxrwxrwt 2 0 0 40 tmp
    uid=0 gid=0
    CapInh = CapPrm = CapEff = CapBnd = CapAmb = 0

Three things worth saying about it. The root is the sentry's own gofer-backed
filesystem (`9p … directfs`) and it is `ro`, which is `root.readonly: true`
arriving inside. `/sys`, `/dev`, `/proc`, `/dev/pts` and `/tmp` are writable and
none of them is `noexec` — but none of them is a host mount either: they are the
sentry's internal VFS, they exist only in sentry memory, and they are invisible
in every host mount table (E1 section "Mounts", and the live captures here).
The guest's writable-must-be-noexec rule reads `/proc/mounts` in the guest, so
it never sees these. And the workload's own capability sets are all zero: the
container process holds nothing, in the sandbox or out of it.

## 3. `true` versus busybox `sh`: no difference

Sections 4 and 5 of output-03-true-vs-sh.txt are the same container, same flags,
same namespace, differing only in the workload (`sleep 25` against
`sh -c 'echo hi; ls /; sleep 25'`, both held alive so the host side could be
read). Normalised and diffed, everything that matters is identical:

- the gofer's mount table — one line, `/dev/md0p1 / ext4 ro,nosuid,nodev,relatime`
- the sentry's mount table — the same three lines as E1 and E2,
  `runsc-root / tmpfs ro`, `runsc-proc /proc tmpfs rw,nosuid,nodev,noexec`,
  `proc /proc/sandbox-proc proc ro,nosuid,nodev,noexec`
- uid_map and gid_map, `0 0 1` for both processes
- the capability sets, sentry `0x8001f` and gofer `0x4001f`
- the state directory: the same four entries, `null-netns`, `runsc-<id>.sock`,
  `<id>_sandbox:<id>.lock`, `<id>_sandbox:<id>.state`, and after the container
  exits only `null-netns`

The diff shows three lines of difference and none of them is the workload:
the section header; one more `null-netns` line in the later capture, because
this session pinned one per `--root` and the second run came after the first;
and the **order** of the global flags in the re-exec'd argv
(`--platform=… --rootless=true … --root=… --network=none` against
`--root=… --network=none --platform=… --rootless=true …`). That last is
`Config.ToFlags` iterating a Go map — `for name, val := range keyVals` at
runsc/config/flags.go:363 — so the order is randomised per process and has
nothing to do with the workload.

## 4. CAP_SYS_PTRACE: the user namespace is enough, no host privilege

**(a) where runsc reads the requirement.** systrap declares it at
pkg/sentry/platform/systrap/systrap.go:398-402 (`RequiresCapSysPtrace: true` at
:400), against the field at pkg/sentry/platform/platform.go:505. Two call sites
read it, and both only *grant* the capability inside a namespace runsc is
already creating — neither checks whether the host gave it one:

- runsc/cmd/sentry/sentrycmd/boot.go:495-501, under `if b.applyCaps` (:488):
  appends `CAP_SYS_PTRACE` to the bounding, effective and permitted sets that
  the sentry will hold, merged with `DirectfsSandboxLinuxCaps` (:504,
  `directfsSandboxCaps` at :61-67 = chown, dac_override, dac_read_search,
  fowner, fsetid) and applied at :556. This is the operative site in E1/E2/E4:
  directfs is on by default (runsc/config/flags.go:155), so the sentry is
  started with `--apply-caps=true` (visible in the argv in
  output-03-true-vs-sh.txt) and comes out with `CapPrm=CapEff=CapBnd=0x8001f`
  and `CapAmb=0` — 0x1f is those five directfs caps, 0x80000 is bit 19,
  CAP_SYS_PTRACE.
- runsc/sandbox/sandbox.go:1243-1245: adds `CAP_SYS_PTRACE` to the *ambient*
  set of the sandbox process, alongside CAP_SYS_ADMIN, CAP_SYS_CHROOT and
  CAP_SETPCAP (:1236-1241), on the path where runsc itself asks for
  `CLONE_NEWUSER`.

**(b) plain shell, no outer unshare, no `--rootless`.** Refused, twice over, and
neither refusal mentions a capability:

    $ runsc --root=… --platform=systrap --network=none --ignore-cgroups \
            run --bundle … s1-e4-b
    running container: creating container: cannot create gofer process:
    newuidmap failed: exec: "newuidmap": executable file not found in $PATH
    EXIT=128

With `--debug` the decision is visible: directfs is on, the spec declares no
user namespace, so `modifySpecForDirectfs` (runsc/container/container.go:2113)
adds one and copies the caller's *identity* mapping into it (:2134-2135) — from
the initial user namespace that is `0 0 4294967295`. A mapping of 4294967295 IDs
is not one an unprivileged process may write, so `CanUseUnprivilegedMapping`
(runsc/sandbox/sandbox.go:2466) says no and `SetUserMappings` (:2489) shells out
to the setuid helper `newuidmap` (:2503), which is not installed on this
workstation. With `--directfs=false` that fixup is skipped and the refusal moves
one step earlier, to the gofer:

    running container: creating container: cannot create gofer process:
    unable to run a rootless container without userns
    EXIT=128

runsc/container/container.go:1644 (and the same string on the sandbox side at
runsc/sandbox/sandbox.go:1179). So what runsc demands of an unprivileged caller
is a *user namespace and a uid mapping it is allowed to write* — not a host
capability. Confirmed by removing only that obstacle and nothing else: with no
unshare and no `--rootless`, but a user namespace and a single-ID mapping
(0 -> 253477, size 1) declared in the spec, the same workload runs, exit 0,
`hi` and the listing (case (b-userns) in output-04-capsysptrace.txt). The sentry
of that run holds `CapPrm=CapEff=CapBnd=0x8001f` while `Uid: 253477 253477
253477 253477` and `uid_map: 0 253477 1` — CAP_SYS_PTRACE inside the namespace,
uid 253477 and zero capabilities outside it. The caller's own `CapEff` was 0
throughout.

**(c) outer `unshare -Ur` only, plus `--rootless`.** Exit 0, `hi` and the
listing. Inside the `unshare -Ur` the caller has uid_map `0 253477 1` and
`CapEff 0x1ffffffffff` — a full set, but only within that user namespace — so
`MaybeRunAsRoot` (runsc/specutils/namespace.go:243) finds the four capabilities
it looks for and returns without re-execing. The one thing that fails is the
null-netns pin, because this caller has a user namespace but no mount namespace
of its own:

    Unable to pin the gofer's network namespace at "…/null-netns"
    (bind-mounting namespace of PID …: operation not permitted); future gofers
    will create new network namespaces. This slows down gVisor startup.

runsc/container/container.go:1699, a warning and nothing more; the container
runs. The kernel refuses that bind because the initial mount namespace is owned
by the initial user namespace, where this process has nothing. The host mount
table was 57 lines with zero null-netns lines before and after everything E4
ran.

**(d) yama.** `/proc/sys/kernel/yama/ptrace_scope` is `1` on this host and it
affected nothing: every run above succeeded at scope 1. Scope 1 restricts
`PTRACE_ATTACH` to descendants, and systrap only ever traces stub processes the
sentry forked itself.

**Conclusion.** CAP_SYS_PTRACE is needed only inside the user namespace runsc
creates (or the guest-like one it is handed), and no host capability is needed:
the sentry ran with `CapEff 0x8001f` while its real uid on the host stayed
253477 and the caller's own effective set was empty, in all three arrangements
that supply a user namespace — `--rootless` alone (E1), an outer
`unshare -Ur` (case c), and a user namespace declared in the spec with a
mapping the caller may write (case b-userns).
