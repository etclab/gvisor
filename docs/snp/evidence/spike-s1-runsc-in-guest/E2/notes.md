# E2 — FAIL, by exactly one mount

Spike S1, experiment 2. Same tree (`ebbe8cba8`), same runsc binary as E1, same
unprivileged user, no sudo, workstation only.

**FAIL.** The workload ran — every one of the three containers exited 0 with the
root filesystem read-only and every writable mount noexec. But the guest init's
check prints one line, and one line is a power-off:

    WRITABLE AND EXECUTABLE: /run/runsc-state/null-netns (nsfs,rw)
    FATAL: writable executable path present; powering off without running tunneld

## The one offending mount

    nsfs /run/runsc-state/null-netns nsfs rw 0 0

`pinNullNetNS` (runsc/container/null_netns.go:70, called from
runsc/container/container.go:1698) bind-mounts the gofer's empty network
namespace into the `--root` directory so that later gofers can reuse it instead
of creating a new one. A bind mount takes its flags from the source mount, and
nsfs is `rw` with no `noexec`, so putting the state directory on a noexec tmpfs
does not help: the nsfs mount lands on top of it with nsfs's own flags. It is
also not transient — it is still there after the container exits (section 5 of
output-01), which is the point of pinning it.

Why E1 never saw it: `--rootless` makes runsc check for CAP_SYS_ADMIN,
CAP_SYS_CHROOT, CAP_SETUID and CAP_SETGID and, lacking them, re-execute
`/proc/self/exe` inside a fresh `CLONE_NEWUSER|CLONE_NEWNS`
(runsc/specutils/namespace.go:243-253). Everything runsc then mounts, including
this one, is in that private mount namespace. Inside `unshare -Urmnpf` the
caller already holds those capabilities, `MaybeRunAsRoot` returns immediately,
no new mount namespace is made, and the pin lands in the caller's — which is
the guest's. Nothing else changed between E1 and E2; this is the whole
difference.

## Everything else passed

- The namespace before runsc ran: `no writable path is executable`.
- `/proc/<sentry>/mounts`: `no writable path is executable`.
- `/proc/<gofer>/mounts`: `no writable path is executable`.
- The three workloads: exit 0.

The sentry's own mount table, inside the guest-like namespace, is the same as
in E1 and needs no help from the harness:

    runsc-root / tmpfs ro,relatime
    runsc-proc /proc tmpfs rw,nosuid,nodev,noexec,relatime
    proc /proc/sandbox-proc proc ro,nosuid,nodev,noexec,relatime

and the gofer's is one line:

    /dev/md0p1 / ext4 ro,nosuid,nodev,relatime

uid_map and gid_map are `0 0 1` for both (E1's were `0 253477 1`, because there
the mapping was made by runsc's own re-exec; here it is inherited from the
`unshare -U -r`). Capabilities are unchanged from E1: the sentry holds
cap_sys_ptrace, the gofer cap_sys_chroot, both only inside the user namespace.

## The crux: runsc's own mounts are already noexec

This is what the spike wanted to know, and the answer is that runsc does not
need to be persuaded. Every tmpfs and procfs runsc creates for itself is
mounted `MS_NOSUID|MS_NODEV|MS_NOEXEC`:

    runsc/cmd/sentry/sentrycmd/chroot.go:150      the sentry's chroot tmpfs
    runsc/cmd/sentry/sentrycmd/chroot.go:87-88    the sentry's /proc tmpfs
    runsc/cmd/sentry/sentrycmd/chroot.go:91-93    the sentry's procfs
    runsc/cmd/sandboxsetup/gofer_mount.go:139-141 the gofer's /proc/fs tmpfs
    runsc/cmd/sandboxsetup/gofer_mount.go:158     the gofer's /proc bind
    runsc/cmd/sandboxsetup/gofer_mount.go:163-164 the gofer's /proc/self/fd bind

and the sentry's chroot is then sealed read-only (chroot.go:176). The one mount
runsc makes that is **not** noexec is the container's root:

    gofer_mount.go:180  mount(rootfs, rootfs, MS_BIND|MS_REC)   — no flags, so it
                        inherits whatever the bundle's own mount had
    gofer_mount.go:250  MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV
                        when spec.Root.Readonly is set

That is deliberate: the sentry has to map the workload's binary executable, so
the container root cannot be noexec. `root.readonly: true` is what makes it
comply — it comes out `ro` rather than `rw`, and a rule that only constrains
writable mounts has nothing to say about it. This is why E1 and E2 both ran
with the root read-only and both passed on that mount.

## Variation: the bundle and its rootfs on a writable noexec mount

Asked for by the experiment, and it does not work. With the bundle copied to
`/tmp` (rw,nosuid,nodev,noexec) the gofer dies before the sandbox starts
(output-02):

    gofer_mount.go:249 Remounting root as readonly: "/proc/fs/root"
    FATAL ERROR: Error setting up root FS: remounting root as read-only with
    source: "/proc/fs/root", target: "/proc/fs/root", flags: 0x1027, err:
    mount("/proc/fs/root", "/proc/fs/proc/self/fd/16", "bind", 0x1027, "")
    failed: operation not permitted

0x1027 is `MS_RDONLY|MS_NOSUID|MS_NODEV|MS_REMOUNT|MS_BIND` — no `MS_NOEXEC`.
A mount created inside a user namespace has its nosuid/nodev/noexec flags
locked (mount_namespaces(7)), so a remount that omits one of them is asking to
clear it, and the kernel answers EPERM. The comment right above that line
(gofer_mount.go:245-248) says exactly this about MS_NOSUID and MS_NODEV;
MS_NOEXEC is the one it does not carry. The caller then sees only the second-
order failure, `cannot read client sync file: waiting for sandbox to start:
EOF`, which is why this needed `--debug` to read.

So a noexec container rootfs fails twice over: the remount is refused here, and
even if it were not, the sentry could not map the workload's binary from a
noexec mount.

## What this leaves for E3

Not this experiment's job to fix, but the shape of it is narrow: one mount,
`null-netns`, created by one call site, whose purpose is a startup
optimisation. E1 shows runsc already has a mode in which that mount is
invisible to the caller — the one it takes when it does not already hold the
capabilities it wants.

## Harness notes

- The guest root is a squashfs (docs/snp/image/build-image.sh:183), read-only
  by construction, so the model mounts the image read-only and lets it stay
  executable. That is not a concession: the guest's rule is that writable
  mounts must be noexec, and a read-only mount is not writable.
- The measured guest mounts no /dev at all (init.rootfs:15-19); its device
  nodes are inside the squashfs. `mknod` is refused in a user namespace, so the
  harness mounts a noexec tmpfs on /dev and bind-mounts host device nodes into
  it, each remounted `nosuid,noexec` — otherwise they arrive carrying the host
  devtmpfs's `rw` with no noexec and trip the check for reasons that have
  nothing to do with runsc. This is a harness artifact and is marked as such in
  guest-like-ns.sh.
- `unshare` needs `-p -f` and `-n` as well as `-U -r -m`: mounting a fresh
  procfs or sysfs requires the pid and net namespaces to be owned by the
  current user namespace, and without them those mounts fail with EPERM.
