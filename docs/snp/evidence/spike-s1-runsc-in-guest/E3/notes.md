# E3 — the smallest relaxation is not a relaxation: one runsc flag

Spike S1, experiment 3. Same tree (686716227), same runsc binary as E1 and E2
(sha256 8070bcdf…), same unprivileged user, no sudo, workstation only. E2's
harness reused byte for byte.

**The answer: add `--gofer-network-namespace=new` to runsc's flags.** The guest
init's writable-must-be-noexec rule needs no exception, `docs/snp/image/init.rootfs`
needs no edit, and no mount of any kind is created outside the namespaces runsc
makes for itself. The workload still runs (exit 0), and the state directory is
left empty rather than holding a mount.

## Why there is a flag at all

The pin has exactly one call site and it is guarded by a config value, not by
`--rootless`, `--network`, `--root` or anything else:

    runsc/container/container.go:1620    goferNetNS, goferNetNSFile, pinGoferNetNS := goferNetworkNamespace(conf)
    runsc/container/container.go:1695-1703  if pinGoferNetNS { pinNullNetNS(...) }
    runsc/container/container.go:1736-1770  func goferNetworkNamespace(conf) — the switch
    runsc/container/null_netns.go:70-82     the bind mount itself

`goferNetworkNamespace` switches on `conf.GoferNetworkNamespace` alone
(container.go:1737) and returns `pinNetNS = true` only in the
`GoferNetworkNamespaceNull` arm (container.go:1756). The three values, and the
flag that sets them:

    runsc/config/config.go:797-811     new | host | null   (null is the default)
    runsc/config/flags.go:160          flagSet.Var(goferNetworkNamespacePtr(GoferNetworkNamespaceNull), "gofer-network-namespace", …)
    runsc/config/config.go:127-129     the field
    runsc/config/config.go:585-592     SharedRoot() — where the pin is put: --shared-root, else --root

`new` is not a weakening. config.go:807-808 says of `null`: "This provides the
same isolation as `GoferNetworkNamespaceNew` without the cost of a new nets
[sic] per gofer" — `null` is the optimisation, `new` is the thing it optimises,
and config.go:809-810 already names rootless as a case where runsc falls back
to `new` by itself. `host`, by contrast, puts the gofer in the caller's — the
guest's — network namespace, so it is the one value that does trade isolation
away.

Two smaller facts from the same read:

- Nothing in `runsc run` ever unmounts the pin. The only caller of
  `specutils.UnmountNullNetNS` (runsc/specutils/namespace.go:313-324) in the
  whole tree is `runsc do` (runsc/cmd/do.go:498). This is why E2 still saw the
  mount after the container exited.
- The pin happens immediately after the gofer starts, so it happens even when
  the container then fails: in output-12 the run died in the gofer's root-FS
  setup and `/run/st-noexec-rootfs/null-netns` was pinned all the same.

## Candidates

Each was run in its own guest-like namespace (the pin is not transient, so one
namespace could only ever fail once and then stay failed). Every case's output
begins with the check passing before runsc runs.

| candidate | workload | null-netns in /proc/mounts | init check | evidence |
|---|---|---|---|---|
| baseline, E2's flags | exit 0 | yes, and it persists | **FAIL** | output-02 |
| `--gofer-network-namespace=new` | exit 0, twice | none | **PASS** | output-03 |
| `--gofer-network-namespace=host` | exit 0, twice | none | PASS, but the gofer joins the guest's netns | output-04 |
| `--shared-root=<read-only dir>` | exit 0 | none (pin refused, EROFS) | **PASS** | output-05 |
| `--root=<read-only dir>` | **exit 128** | none | passes, vacuously | output-06 |
| nested `unshare -m` around runsc | exit 0 | none at guest level; present inside | **PASS** | output-07 |
| `<root>/null-netns` pre-made a directory | exit 0, twice | none (pin refused, EISDIR) | **PASS** | output-08 |
| `<root>/null-netns` pre-made a 0444 file | exit 0 | yes | **FAIL** | output-09 |

Notes on the ones that pass but are worse than the flag:

- **`--shared-root` on a read-only directory** works by making the pin fail, not
  by not attempting it; runsc says so and carries on:
  `Unable to pin the gofer's network namespace at "/roshared/null-netns"
  (creating mount point: open /roshared/null-netns: read-only file system);
  future gofers will create new network namespaces.` `--root` stays writable,
  which it must. It also aims any future shared state at a read-only path.
- **nested `unshare -m`** does not prevent the mount, it hides it: the pin is in
  the runsc CLI's `/proc/<pid>/mounts` and absent from the guest's, both
  observed while the sandbox lived (output-07). That is the wrong trade for this
  guest — it hides *every* mount runsc makes from the check that is the guest's
  whole argument, not just this one.
- **the pre-created directory** works because `pinNullNetNS` opens the mount
  point with `os.OpenFile(path, O_RDONLY|O_CREATE, 0444)` (null_netns.go:72),
  which returns EISDIR on a directory, before it ever reaches the
  `unix.Mount` — so the best-effort `os.Remove(path)` at null_netns.go:78 is not
  reached and the guard survives (empty or not; the `.keep` file in the case
  script is belt and braces). It depends on an undocumented filename and on an
  error path, which a flag does not.
- **a read-only regular file is not a guard**: `O_RDONLY|O_CREATE` on an
  existing regular file succeeds whatever its mode, and a bind mount over a
  regular file is exactly what the pin wants. FAIL.

`--root` on a read-only path is not a candidate at all: runsc needs the state
directory writable and stops before the sandbox exists —
`running container: creating container: cannot lock container metadata file:
acquiring lock on "/roroot/e3-root-ro_sandbox:e3-root-ro.lock": open …:
read-only file system`, exit 128 (output-06).

## What the pin buys (output-13)

Three sequential containers with `null` against three with `new`, in the
guest-like namespace, `busybox time` around each:

    null: real 0.38s, 0.34s, 0.32s      (run 1 pins, runs 2-3 reuse)
    new:  real 0.32s, 0.39s, 0.36s

No measurable difference at this scale on this machine. The optimisation is
real in the code's terms — it saves a `CLONE_NEWNET` per gofer — but nothing in
the tunnel's shape (one sandbox, one gofer, cold start) is paying for it.

## What the offending mount actually is (output-11)

    /proc/mounts     nsfs /run/st-characterise/null-netns nsfs rw 0 0
    /proc/self/mountinfo
                     2440 865 0:4 net:[4026536019] /run/st-characterise/null-netns rw - nsfs nsfs rw
    the mount under it
                     865 862 0:83 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,…

Per-mount options `rw`, super options `rw`: no `nosuid`, no `nodev`, no
`noexec` in either field. That is the entire reason the check trips, and it is
inherited from nsfs, which is why putting the state directory on a noexec
tmpfs (as the guest does) does not help — the nsfs mount lands on top of it
with its own flags.

Executable in any meaningful sense: no.

    stat        regular empty file, size 0, mode 0444, uid/gid 65534 (unmapped)
    touch  <path>/x    Not a directory      ENOTDIR — it is one inode, not a directory
    mkdir  <path>/d    Not a directory      ENOTDIR
    cp /busybox <path> Operation not permitted
    chmod +x <path>    Operation not permitted   — the x bit cannot be set
    cat <path>         read error: Invalid argument
    exec <path>        Permission denied (126)

Nothing can be created on it, its contents cannot be read or written, its mode
cannot be changed, and executing it is refused. For contrast, in the same run,
executing a binary on the noexec `/run` underneath gives the same visible
"Permission denied" for an entirely different reason.

### What the check would have to know, if it were ever changed

Not needed — the flag removes the mount — but stated so the rule can be judged:
`init.rootfs:33-40` reads `dev mnt type opts` from `/proc/mounts` and keys on
`opts` alone. To let this one through it would have to use a second field:

- **on `type`**: skip `nsfs`. Exact, and it is what actually makes the mount
  harmless (an nsfs mount is one namespace inode and nothing else can ever
  appear on it). It is also a named exception someone has to justify in the
  threat model.
- **on the path being a non-directory**: `[ -d "$mnt" ] || continue`. Broader
  and weaker: it would also skip a bind mount of a *regular* file that is
  writable and does carry the x bit, which nsfs cannot be but a bind of some
  other file could.

Both are changes to the guest's rule surface. The flag is not.

## The second finding, reconfirmed (output-12)

With the bundle and its rootfs on `/tmp` (rw,nosuid,nodev,noexec) the gofer
dies before the sandbox starts, exactly as in E2:

    gofer_mount.go:249 Remounting root as readonly: "/proc/fs/root"
    FATAL ERROR: Error setting up root FS: remounting root as read-only with
    source: "/proc/fs/root", target: "/proc/fs/root", flags: 0x1027, err:
    mount("/proc/fs/root", "/proc/fs/proc/self/fd/16", "bind", 0x1027, "")
    failed: operation not permitted

and the caller sees only `cannot create sandbox: cannot read client sync file:
waiting for sandbox to start: EOF`, exit 128.

The line and its comment:

    runsc/cmd/sandboxsetup/gofer_mount.go:250   flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
    runsc/cmd/sandboxsetup/gofer_mount.go:243-248
        // If root is a mount point but not read-only, we can change mount options
        // to make it read-only for extra safety.
        // unix.MS_NOSUID and unix.MS_NODEV are included here not only
        // for safety reasons but also because they can be locked and
        // any attempts to unset them will fail.  See
        // mount_namespaces(7) for more details.

The comment names MS_NOSUID and MS_NODEV as locked-and-therefore-carried and
does not mention MS_NOEXEC, which is locked in exactly the same way; 0x1027 is
`MS_RDONLY|MS_NOSUID|MS_NODEV|MS_REMOUNT|MS_BIND`, so the remount asks to clear
a locked `noexec` and the kernel answers EPERM.

**The relaxation this needs, named:** the workload's bundle and rootfs must sit
on a mount that is exec-permitted and read-only. It cannot sit on the guest's
writable noexec tmpfs.

Does that matter for the guest? Not for the root, which already has the right
shape, and the same bundle on the read-only image root runs (exit 0, output-12,
second half):

    docs/snp/image/init.initrd:52-63   dm-verity maps the image, then
                                       `mount -t squashfs -o ro /dev/dm-$MINOR /newroot`
                                       — read-only, and nothing removes exec
    docs/snp/image/build-image.sh:182-199  the root is a squashfs with a
                                       dm-verity hash tree appended; the root
                                       hash rides on the measured command line
    docs/snp/image/init.rootfs:17-18   /run and /tmp are the writable mounts,
                                       both tmpfs nosuid,nodev,noexec

So a workload image baked into the measured squashfs works as is. What does not
work is a workload image delivered at run time onto `/run` or `/tmp`, and the
config device is no help either: init.initrd:69 mounts it `ro,noexec,nosuid,nodev`
deliberately ("so it is mounted read-only and nothing on it can run",
init.initrd:66-67). Delivering a workload rootfs from outside the measurement
would therefore need a *new* read-only, exec-permitted mount — allowed by the
guest's rule as written, since the rule only constrains writable mounts, but a
decision about what may be executed that has not been made. Naming it, not
making it.

## Scope

Workstation only: a user namespace shaped like the guest, not the guest. E4
covers the privilege question. Nothing under `pkg/` or `runsc/` was modified.
