# Spike S1: does runsc run inside the measured guest's rules?

Workstation only, 2026-09-15, tree `ebbe8cba8`, one runsc binary (sha256 `8070bcdf…c72518`,
built by `make runsc` because `go build ./runsc` cannot work on this branch and native bazel
lacks an arm64 cross compiler; see E1). No sentry change, no image build, no hardware, no sudo.
Nothing under `pkg/` or `runsc/` changed. Each experiment's exact commands and untrimmed
outputs are in `E1/` to `E4/`; each has a `notes.md`.

## Result: PASS, with one runsc flag

runsc under systrap, `--network=none`, `--ignore-cgroups`, rootless, runs a static busybox
workload in a read-only root while every writable mount in the caller's namespace is noexec,
and the guest init's check (`docs/snp/image/init.rootfs:30-44`) passes, **provided runsc is
also given `--gofer-network-namespace=new`**. Without that flag the check fails on exactly one
mount and the guest would power off. The guest rule needs no exception.

| experiment | outcome |
|---|---|
| E1 rootless `true`, root read-only, workstation | exit 0; every mount runsc makes lives in a namespace it created; host mount table unchanged |
| E2 same, every writable mount noexec, guest-like namespace | workload exit 0; check **FAIL**: `WRITABLE AND EXECUTABLE: /run/runsc-state/null-netns (nsfs,rw)` |
| E3 smallest relaxation | `--gofer-network-namespace=new`: mount never created, check **PASS**, no measured startup cost |
| E4 busybox `sh -c 'echo hi; ls /'` in E2's configuration | exit 0, prints `hi` and `bin dev proc sys tmp`; no host capability needed |

## Flag set

```
runsc --root=<state-dir> --platform=systrap --network=none --ignore-cgroups --rootless \
      --gofer-network-namespace=new run --bundle <bundle> <id>
```
with `root.readonly: true` in the bundle. Not needed, each tried and recorded in E1:
`--TESTONLY-unsafe-nonroot`, `--debug`, `--directfs=false`, `--overlay2=root:memory`.
`runsc do` also works but is the only path that unmounts the null-netns pin (`runsc/cmd/do.go:498`);
`runsc run` and `runsc delete` never do.

## Mount table

Nothing runsc makes appears in the caller's mount namespace except the one offender.
All of runsc's own tmpfs and procfs mounts are already noexec, and the sentry chroot is sealed
read-only (`runsc/cmd/sentry/sentrycmd/chroot.go:87-93,150,176`; `runsc/cmd/sandboxsetup/gofer_mount.go:139-164`).

| namespace | mount | options |
|---|---|---|
| sentry | `runsc-root /` tmpfs | `ro,relatime` |
| sentry | `runsc-proc /proc` tmpfs | `rw,nosuid,nodev,noexec` |
| sentry | `proc /proc/sandbox-proc` | `ro,nosuid,nodev,noexec` |
| gofer | bundle rootfs bind at `/` | `ro,nosuid,nodev` (exec allowed, from `root.readonly`, `gofer_mount.go:180,250`) |
| gofer, transient | `/proc/fs` tmpfs, `/proc` and `/proc/self/fd` binds | all `ro` or `noexec` |
| **caller** (default flags only) | `nsfs <root>/null-netns` | `rw` |

Inside the sandbox the workload sees a 9p read-only root plus `/sys`, `/dev`, `/proc`,
`/dev/pts`, `/tmp` all `rw` without `noexec`, but these are the sentry's in-memory VFS and
never appear in any host mount table (E4/output-02).

## The one offender and why it appeared only in the guest-like namespace

`pinNullNetNS` (`runsc/container/null_netns.go:70-82`, called from `runsc/container/container.go:1698`)
bind-mounts an empty network namespace into `--root` as a startup optimisation for later
gofers. A bind inherits its source's flags, nsfs is `rw` with no `noexec`, so a noexec state
directory does not help, and the mount persists after the container exits. On the workstation
(E1) `--rootless` re-executes into a private user and mount namespace when the caller lacks
capabilities (`runsc/specutils/namespace.go:243-253`), hiding the pin. In a guest-like
`unshare -Urmnpf` the caller already has them, so the pin lands in the guest's own mount table.
The nsfs inode is not executable in any sense (size 0, mode 0444, exec gives EACCES; E3/output-11);
the check trips because it keys on the option string alone.

Candidates tried in E3 and rejected: `host` (gofer joins the guest's netns), a nested
`unshare -m` (hides every runsc mount from the check), a pre-made directory at the pin path
(undocumented filename, error path), `--shared-root` read-only (works but indirect), `--root`
read-only (runsc cannot run at all: lock file EROFS).

## Second finding: where the workload image may live

The bundle and rootfs on a writable noexec mount fail in the gofer's read-only remount:
`mount(..., "bind", 0x1027, "") failed: operation not permitted` at `gofer_mount.go:250`. The
flag word omits `MS_NOEXEC`, which is locked in a user namespace like `MS_NOSUID` and
`MS_NODEV` that the comment at `:243-248` does name. So the workload's root must sit on an
**exec-permitted, read-only** mount. The ticket 19 guest's verity squashfs root qualifies
(`docs/snp/image/init.initrd:52-63`); `/run`, `/tmp` (rw,noexec, `init.rootfs:17-18`) and the
config device (ro,noexec, `init.initrd:65-70`) do not. A workload image delivered from
outside the measurement would need a new read-only exec-permitted mount. The rule as written
permits that; nobody has decided it. Named, not made.

## Capabilities: user namespaces suffice

systrap declares `RequiresCapSysPtrace` (`pkg/sentry/platform/systrap/systrap.go:398-402`).
Both readers only grant the capability inside a user namespace runsc already creates
(`runsc/cmd/sentry/sentrycmd/boot.go:495-501`; `runsc/sandbox/sandbox.go:1243-1245`); neither
checks the host. Measured: sentry `CapEff=0x8001f` (five directfs caps plus `CAP_SYS_PTRACE`),
`uid_map 0 253477 1` on the workstation and `0 0 1` inside the guest-like namespace, caller's
`CapEff=0`, real uid unchanged. Yama `ptrace_scope=1` affected nothing. Without any user
namespace, runsc refuses with `newuidmap ... not found` (directfs) or `unable to run a rootless
container without userns` (`runsc/container/container.go:1644`); the demand is a user namespace
with a writable uid mapping, never a host capability. A user namespace without a mount
namespace also runs (the pin fails with a warning).

## What the ticket 19 initrd lacks for this to run there

Everything below is what the workstation runs supplied and the guest init does not, today:

- **Namespaces.** A user namespace with a uid/gid mapping runsc may write (a single-ID map
  suffices, `newuidmap` not needed when already inside one), plus mount, PID, IPC, UTS and
  network namespaces, which runsc creates itself given the user namespace. The guest runs
  tunneld as PID 1's child in the initial namespaces; something must `unshare` first, or run
  runsc `--rootless` and let it re-execute.
- **procfs.** A procfs instance and `/proc/self/fd` for the mount-by-fd path, and
  `/proc/self/exe` (re-executed three times). The guest mounts `/proc` already.
- **mount(2), pivot_root(2), chroot(2)** inside the user namespace; `CAP_SYS_ADMIN`,
  `CAP_SYS_CHROOT`, `CAP_SYS_PTRACE` only within that namespace. No host capability, no
  device node, no cgroups (`--ignore-cgroups`), no iptables.
- **A writable state directory** for `--root` (lock and metadata files). A noexec tmpfs such
  as the guest's `/run` is enough, with `--gofer-network-namespace=new` so nothing is mounted
  into it.
- **An exec-permitted read-only mount** holding runsc, the bundle and the workload rootfs. The
  measured root qualifies; a workload delivered later does not fit on any existing mount.
- **The runsc binary itself**: 108 MB static, not in the current image, and `go build` cannot
  produce it on this branch; the image build would need the bazel output.

Not tested here: the guest kernel's config (user namespaces, nsfs, 9p or directfs, seccomp
filters) and a busybox-only userland driving `unshare`. Those are the next tiny experiments if
the gVisor tickets keep their shape, which this result says they can.
