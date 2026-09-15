# E1 — runsc runs a trivial workload rootless, read-only root, on this workstation

Spike S1, experiment 1. Workstation only, no hardware, no ticket.
Tree: `spike-s1-runsc-in-guest` at `ebbe8cba8e0f600fb5ba3db98e3f02cc610f9d19`
(clean). Kernel 6.11.0-rc3-snp-host. User pniroula, uid 253477, no sudo used.

## What worked

The flag set the spike asked about worked as given, with nothing added:

    runsc --root=<state> --platform=systrap --network=none --ignore-cgroups \
          --rootless run --bundle <bundle> <id>

`root.readonly: true` in the bundle, rootfs a single static busybox, workload
`/bin/busybox true`. Exit 0. Five further variations (`--debug`,
`--directfs=false`, `--overlay2=root:memory`, `--TESTONLY-unsafe-nonroot=true`,
and the `runsc do` form) also exited 0, so none of them is needed
(output-04). `--TESTONLY-unsafe-nonroot` in particular is not needed; the
Makefile's dev target passes it, this experiment does not.

## The build

`go build ./runsc` cannot work on this branch and this is not a tooling
problem to fix: the tree is bazel-first. 49 lines of errors in three kinds
(output-01) — generated protobuf packages that do not exist as Go packages
(`*_go_proto`), `go:embed` targets that bazel generates (`vdso_amd64.so`,
`sighandler.built-in.amd64.bin`), and directories where a `_test.go` file
declares a different package than its neighbours, which bazel tolerates and
`go build` does not.

Native `bazel build -c opt //runsc:runsc` also fails, for one reason only:
`/usr/bin/aarch64-linux-gnu-gcc: No such file or directory`, in eleven actions
(output-02). `pkg/sentry/loader/vdsodata/BUILD` uses `arch_genrule`, whose
`arch_transition` (tools/arch.bzl:9-20) builds `//vdso` and the systrap sysmsg
blobs for **both** amd64 and arm64 unconditionally, so an amd64-only host
cannot build runsc natively without the arm64 cross compiler.

`make runsc` works: it runs the same bazel inside `gvisor.dev/images/default`,
which carries that cross compiler. That image was already present locally, so
nothing was downloaded. Binary: 108,668,311 bytes, static, `runsc version
0.0.0 / spec: 1.2.1` (output-03).

## The process tree

`--rootless` re-execs. `specutils.MaybeRunAsRoot` (runsc/specutils/namespace.go:243)
checks for CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SETUID, CAP_SETGID and, lacking
them, re-executes `/proc/self/exe` under `CLONE_NEWUSER|CLONE_NEWNS` with
uid 0 mapped to the caller. So four processes:

    runsc                 the CLI
    /proc/self/exe        the rootless re-exec, in its own user+mount namespace
    runsc-gofer           CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET
    runsc-sandbox         CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET

`comm` is `exe` for all three re-exec'd ones; only argv[0] names them.

## Mounts

Nothing runsc does is visible in the caller's mount namespace in this
configuration. While the sandbox ran, the host mount table was unchanged at 57
lines and no line mentioned runsc (output-05). Every mount below is inside a
namespace runsc created.

The sentry (`runsc-sandbox`), after `pivot_root`:

    runsc-root /                  tmpfs  ro,relatime
    runsc-proc /proc              tmpfs  rw,nosuid,nodev,noexec,relatime
    proc       /proc/sandbox-proc proc   ro,nosuid,nodev,noexec,relatime

One writable mount, and it is noexec. Source: the chroot tmpfs is mounted
`MS_NOSUID|MS_NODEV|MS_NOEXEC` at runsc/cmd/sentry/sentrycmd/chroot.go:150 and
sealed `MS_REMOUNT|MS_RDONLY|MS_BIND` at chroot.go:176; the `/proc` tmpfs at
chroot.go:87-88 and the procfs at chroot.go:91-93 are both noexec.

The gofer (`runsc-gofer`), after `pivot_root` and `chroot("/root")`:

    /dev/md0p1 / ext4 ro,nosuid,nodev,relatime

which is the bundle's rootfs bind-mounted and then remounted
`MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV` because `root.readonly` is
true (runsc/cmd/sandboxsetup/gofer_mount.go:250). Note what is **not** in
those flags: `MS_NOEXEC`. The container root stays executable, which is what
the sentry needs in order to map the workload's binary, and it is `ro` rather
than `rw`, which is how it satisfies a writable-must-be-noexec rule.

The full mount sequence, from strace (output-08), in order:

    gofer:   mount("", "/", MS_REC|MS_SLAVE)
             mount("runsc-root", /proc/fs, tmpfs, MS_NOSUID|MS_NODEV|MS_NOEXEC)
             mount("", /proc/fs, MS_UNBINDABLE)
             mount("/proc", /proc/fs/proc, MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_BIND|MS_REC)
             mount(/proc/fs/proc/self/fd, /proc/fs/proc/fs, MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_BIND)
             mount(<bundle>/rootfs, <bundle>/rootfs, MS_BIND|MS_REC)      <- no flags: inherits the source's
             mount("", <bundle>/rootfs, MS_REC|MS_SLAVE)
             mount(<bundle>/rootfs, /proc/fs/root, MS_BIND|MS_REC)
             mount(/proc/fs/root, ..., MS_RDONLY|MS_NOSUID|MS_NODEV|MS_REMOUNT|MS_BIND)
             pivot_root(".", ".") ; chroot("/root")
    sentry:  mount("", "/", MS_REC|MS_SLAVE)
             mount("runsc-root", /tmp, tmpfs, MS_NOSUID|MS_NODEV|MS_NOEXEC)
             mount("runsc-proc", /tmp/proc, tmpfs, MS_NOSUID|MS_NODEV|MS_NOEXEC)
             mount("proc", /tmp/proc/sandbox-proc, proc, MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)
             mount("", <chroot>, MS_RDONLY|MS_REMOUNT|MS_BIND)
             pivot_root(".", ".")

and one more, in the caller's own mount namespace rather than a new one:

    mount("/proc/<pid>/ns/net", "<--root>/null-netns", MS_BIND)

That is `pinNullNetNS` (runsc/container/null_netns.go:70, called from
runsc/container/container.go:1698). It pins an empty network namespace in the
`--root` directory so later gofers can reuse it. Here it lands inside the
rootless re-exec's private mount namespace and so is invisible to the caller.
E2 shows what happens when there is no re-exec.

The mount table the workload sees inside the sandbox (output-06) is the
sentry's own VFS, not host mounts: root over 9p `ro` (directfs), plus sysfs,
dev, proc, devpts and an internal tmpfs on /tmp. None of it reaches the host.

## Identity and capabilities

Both uid_map and gid_map, for sentry and gofer alike, are the single line
`0 253477 1` — the mapping `MaybeRunAsRoot` installs.

    runsc-sandbox  CapPrm=CapEff=CapBnd=0x000000000008001f
                   cap_chown, cap_dac_override, cap_dac_read_search,
                   cap_fowner, cap_fsetid, cap_sys_ptrace
                   CapAmb=0, NoNewPrivs=1, Seccomp=2 (filter), 1 filter
    runsc-gofer    CapPrm=CapEff=CapBnd=CapAmb=0x000000000004001f
                   cap_chown, cap_dac_override, cap_dac_read_search,
                   cap_fowner, cap_fsetid, cap_sys_chroot
                   NoNewPrivs=1, Seccomp=2 (filter), 1 filter

CAP_SYS_PTRACE is present in the sentry, as systrap declares it must be
(pkg/sentry/platform/systrap/systrap.go:398-402, `RequiresCapSysPtrace: true` at :400;
added to the ambient set at runsc/sandbox/sandbox.go:1243-1245). These are
capabilities **inside a user namespace whose only mapping is the caller's own
uid**, not host capabilities — the process's real uid is still 253477. That is
the answer E4 will want: no host privilege was granted, the user namespace was
sufficient.

## What runsc wrote where

`--root` state directory, while a container lives:

    null-netns                          0  (the pinned netns, see above)
    runsc-<id>.sock                     0  unix socket
    <id>_sandbox:<id>.lock              0
    <id>_sandbox:<id>.state          2095  JSON, in output-07 in full

After the container exits only `null-netns` is left. There is no overlay upper
on disk: the metric metadata records `"overlay":"root:self"`, and the internal
tmpfs is sentry memory. The chroot is a private tmpfs at `os.TempDir()`
(chroot.go:140) inside the sentry's mount namespace; the caller's `/tmp` is
untouched by the run. `--debug --debug-log=<dir>/` writes four files there:
`.run.txt` (twice, once per runsc process), `.boot.txt`, `.gofer.txt`.

## Host facilities used

user, mount, IPC, UTS, PID and network namespaces; `mount(2)`; `pivot_root(2)`;
`chroot(2)`; a procfs instance (and `/proc/self/fd` for the mount-by-fd dance
in `specutils.SafeMount`); `execve` of `/proc/self/exe`
(runsc/specutils/specutils.go:97) three times; a writable `--root` directory;
and capabilities held only within a user namespace. No device node: systrap's
`OpenDevice` returns nil (systrap.go:393-395). No cgroup, with
`--ignore-cgroups`.
