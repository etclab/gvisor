# The rehearsal: what the two consoles said

Two guests, one image, the `adapter` scenario, **no SNP** and a **stock runsc**.
`=== 24 passed, 0 failed ===`, both guests, and both consoles are here whole
(`capture/adapter/console-a.txt`, `console-b.txt`, 42,910 bytes each).

**What this rehearses and what it cannot.** The adapter did not exist when this
ran: the runsc inside the measurement is ticket 24's binary, which does not know
the two flags init now passes it, and a control boot has no report interface so
tunneld refuses to start before it ever creates a socket. So nothing here says
anything about a tunnel, an intercept or a stream. What it does say is that the
*ground under them* is right — the order, the wait, the exit's start condition,
the page, and a guest that survives all of it — which is the only part that could
be got wrong before the adapter lands and the only part that is expensive to
discover on the hardware.

## The order, which is the ticket's one change to init

Guest A's console, by line number:

```
509  init: the config device carries a tunnel table; the workload is a sandbox on the adapter (ticket 25)
510  init: tunnel-table: {"default_exit":"guest-b",
511  init: tunnel-table:  "names":{"web.peer-b":{"port":80}}}
512  init: uptime 3.34s
513  init: running /usr/bin/tunneld  -sandbox-socket /run/tunneld/sandbox.sock in the background, ahead of the workload
...
536  init: the workload device carries a bundle at /workload/config.json
538  init: uptime 3.48s
```

tunneld at 3.34 s and the workload at 3.48 s, and the harness checks the two line
numbers rather than the two clocks (`before`, `tunnel-on-two-guests.sh`). On the
guest of ticket 24 those two lines are the other way round, and that is the whole
difference the config device's tunnel table makes.

## The wait, and the one branch a control boot takes

```
517  tunneld: link eth0 up with 10.14.0.2/24
518  tunneld: report interface /sys/kernel/config/tsm/report: present, 0 request(s) outstanding; …
519  tunneld: refusing to start: tsm: creating the request …: no such device or address
520  tunneld: EXIT status=1
521  init: tunneld exited before /run/tunneld/sandbox.sock existed; no sandbox can attach
522  init: not starting the exit: there is no sandbox socket for it to attach to
```

The poll is `[ ! -S "$SANDBOX_SOCKET" ]` with `kill -0 $TPID` inside it, so a
tunneld that died is noticed in the same half second rather than after the
thirty-second timeout, and the exit is not started into nothing. **On a real boot
this is the branch that is not taken**, and that half of the loop is the one
thing in this init that the rehearsal cannot exercise.

Note line 517: **tunneld brought the link up before it refused**. That is why the
egress probe at the end still had a routing table to be refused by, and it is
also the fact behind the property ticket 24 had and ticket 25 gives up: on the
adapter path the guest's link is up while the workload runs. What replaces it is
in `init.rootfs`'s own comment — the workload has no interface, no address and no
route of its own, because it is a `--network=none` sandbox.

## The page

```
523  init: busybox httpd is serving /run/httpd on 127.0.0.1:80 (loopback only: the segment cannot reach it)
524  init: httpd says: <!doctype html>
...
535  init: httpd says: served-by: guest-a
```

and guest B's line 535 is `served-by: guest-b`. One image, one `/srv/index.html`
inside the measurement, and one line appended from the `sandbox_id` on each
guest's config device. That line is what makes "guest A's console holds guest B's
page" a statement about where bytes came from, and init fetching its own page
before any sandbox exists is what separates "the page was never served" from "the
tunnel did not carry it".

`/run` is `rw,noexec` and stays that way: the page is a file written into a
tmpfs, httpd execs nothing (no CGI), the sandbox socket is a socket, and the
check at `init.rootfs:37-54` ran before any of it and passed —
`init: no writable path is executable`, and the mount table printed after the
workload is the same nine lines as the one printed before it.

## The workload, failing exactly as intended

```
537  init: running: unshare -Urmnpf sh -c 'mount -t proc … exec /usr/bin/runsc --root=/run/runsc-state
     --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new
     --tunnel-socket=/run/tunneld/sandbox.sock --tunnel-table=/config/tunnel-table.json run
     --bundle /workload workload'
539  flag provided but not defined: -tunnel-socket
540  Usage: runsc <flags> <subcommand> <subcommand args>
599  init: uptime 4.17s
600  init: workload exited with status 2
```

The flag set is on the console in full, which is what the harness asserts against
(`--tunnel-socket=… --tunnel-table=…` as one string). Stock runsc refuses it,
prints its usage, exits 2, **and init carries on** — through the mount table,
through `wait` on a tunneld that had already gone, through the egress probe, to

```
620  init: powering off
```

Not the fatal poweroff at `init.rootfs:48-53`: `WRITABLE AND EXECUTABLE` appears
on neither console, and the egress probe passed on both — four attempts, four
refusals, `EGRESS PROBE PASSED`.

## What it cost the image

| file | ticket 24 | the rehearsal image | delta |
|---|---|---|---|
| `rootfs.img` | 85,319,680 | 90,243,072 | **+4,923,392** |
| `initrd.img` | 1,508,081 | 1,508,081 | 0 |
| `cmdline.txt` | 197 | 197 | 0 (the verity block count did not gain a digit) |
| `vmlinuz`, `OVMF.fd` | | | 0 |

4.7 MB of squashfs for a 9,204,810-byte `agent-probe`, a 657-byte page, a
103-byte `/etc/hosts` and four symlinks into a busybox that was already measured.
The runsc in this image is ticket 24's byte for byte, so the delta is ticket 25's
and nothing else's — and it will move again when the real runsc lands.

## Timings, off init's own clock

| | guest A | guest B |
|---|---|---|
| check verdict | 2.81 s | 2.69 s |
| tunneld started | 3.34 s | 3.12 s |
| workload start → exit | 3.48 → 4.17 s | 3.22 → 3.92 s |

The workload's 0.6–0.8 s here is a runsc that read its command line and gave up, not
a sandbox; ticket 24 measured a real one at 0.85–0.90 s on this hardware.

## What did not hold, or is not shown

- **No tunnel, no stream, no intercept, no exit.** Everything below `EXIT
  serving` in the scenario's assertion list is skipped on a control boot, by
  design (`scenario_adapter`'s `if [ "$SNP" = 0 ]` branch). The relay recorded
  `a_to_b_frames=0`: with tunneld refusing to start, nothing was ever put on the
  segment, so `MARKER not found` is true here for a trivial reason and means
  nothing until the real run.
- **The socket-appeared branch is unexercised.** So is every line after it that
  depends on it, including the exit's `-allow` list reaching `agent-probe`.
- **The `agent-probe` binary is measured but was never executed.** It is in
  `manifest.txt` at `./usr/bin/agent-probe`, sha256
  `cee5c9abee948d024d754cf5837bd9e74ab79630ce52f43b24effc3c583c59e0`, and nothing
  on either console came from it.
- **A seccheck receiver is not part of this design and is not missing from it.**
  The refusal the control fetch produces is visible twice over without one: the
  sandbox's own `wget: bad address '…'`, on the console, and the sentry's
  `ENETUNREACH` for anything that did get an address. The
  `sentry/egress_refused` point exists and is emitted through the ordinary sink
  machinery, but a `--pod-init-config` trace session and a receiver process
  inside the measured guest would both be new measured things, for evidence the
  console already carries. The loopback proof is where a receiver belongs.
- **The double space in `running /usr/bin/tunneld  -sandbox-socket`** is `$PUSH`
  being empty, as it is in every scenario that pushes no policy. Cosmetic, and
  the same shape ticket 22 left.
