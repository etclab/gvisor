# The SNP run of ticket 25, in one dispatch

Ticket 25's item: *one run of the same topology inside the local SEV-SNP guest
from ticket 24, through the job spool, with the console captured*. Everything
below is ready and rehearsed except the one thing that is not: the runsc that
knows `--tunnel-socket` and `--tunnel-table`. **Do not start until that binary
exists**; with any other runsc the workload launch fails on the two flags and the
run proves only what the rehearsal already proved
(`rehearsal/notes.md`, `=== 24 passed, 0 failed ===` on a control boot).

Nothing here needs `sudo` typed. The two QEMUs open `/dev/sev` and go through the
spool; everything else runs as the ordinary user.

## Before you start

| | |
|---|---|
| the adapter's runsc | `make runsc` in this worktree → `bazel-bin/runsc/runsc_/runsc`. Statically linked, and `runsc flags` must list `-tunnel-socket` and `-tunnel-table`. The flags and the helper are in the source already; what is missing is a build. |
| the root runner | up as root in tmux session `root-runner-m4`, watching `/home/pniroula/Projects/gvisor/docs/snp/root-spool` |
| the author key | `$STACK/image-ticket14-packaging/author.key` — the key whose public half is inside every image this harness re-signs a set for |
| `attest/` compiles | `package-tunneld.sh` runs `go test ./cmd/tunneld` first and builds `agent-probe` after it; both have to pass |

```
export PATH=/usr/local/go/bin:$PATH
export STACK=/home/pniroula/Projects/gvisor/.scratch/attested-secure-tunnel/host-stack
export SCRATCH=<a directory outside the repo>     # the bundle source and the disk
cd /home/pniroula/Projects/gvisor-t25
```

## 1. The image

```
OUT=$STACK/image-ticket25 \
AUTHOR_KEY=$STACK/image-ticket14-packaging/author.key \
RUNSC=/home/pniroula/Projects/gvisor-t25/bazel-bin/runsc/runsc_/runsc \
  bash docs/snp/image/package-tunneld.sh
unset OUT
```

`AGENT_PROBE` is deliberately not set: the script builds it from
`attest/cmd/agent-probe` (step 2b), checks it is static and carries no checkout
path, and passes it to `build-image.sh`. The build prints the predicted launch
measurement and emits the signed reference value set beside the image. **Copy
`$STACK/image-ticket25-packaging/packaging.txt` and `$STACK/image-ticket25/manifest.txt`
into the evidence directory**; the manifest names every measured input, including
`./usr/bin/agent-probe`, `./srv/index.html` and `./etc/hosts`.

## 2. The prediction, again and on its own

```
SEV_SNP_MEASURE_VENV=$STACK/sev-snp-measure-venv-ticket14 \
  bash docs/snp/image/predict-measurement.sh $STACK/image-ticket25 \
       -vcpus 4 -vcpu-type EPYC-v4 \
       -out docs/snp/evidence/ticket25/snp/predicted-measurement-independent.txt
```

It must equal `sed -n 's/^launch_measurement: //p' $STACK/image-ticket25/manifest.txt`.
This is ticket 07's rule and ticket 24's practice: the number is computed from the
four measured files before anything boots, and it is never read off a machine.

## 3. The reference values

There is nothing to do. The set the config devices carry is the one step 1
emitted and signed; the harness copies it onto both devices unchanged
(`make_config`). **Do not author a second set, and do not pin an RTMR, a policy
digest or a peer measurement by hand** — ticket 24's E2 pinned nothing beyond
this and neither does this run. The only two documents that differ between the
two guests are the four files under `docs/snp/evidence/ticket25/snp/config/`, and
they are not measured and are not signed.

## 4. The workload disk

```
bash docs/snp/evidence/ticket25/snp/make-bundle.sh $SCRATCH/workload-src $SCRATCH/workload.img
```

One disk, attached read-only to **both** guests. One bundle: the pinned static
busybox, `/adapter-probe.sh`, and an `/etc` with `resolv.conf` pointing at
`127.0.0.53` (where the sentry answers), `nsswitch.conf` saying `hosts: files
dns`, and an `/etc/hosts` holding localhost **and neither peer name** — if a peer
name were in there the fetch would never reach the sentry and the run would prove
nothing. Record the disk's sha256 (`mkworkloaddev.sh` prints it) and the script's
output; the disk itself is megabytes and is not measured, so it is not committed.

## 5. The run

```
docs/snp/tunnel-on-two-guests.sh \
    -image $STACK/image-ticket25 \
    -out $STACK/image-ticket25-run \
    -scenario adapter -quick \
    -workload $SCRATCH/workload.img \
    -spool /home/pniroula/Projects/gvisor/docs/snp/root-spool \
    -capture docs/snp/evidence/ticket25/snp/run
```

**Run this from an ordinary session, never from inside the spool.** The harness
spools the boot job itself, and `docs/snp/root-runner.sh` is a single-threaded
loop: a harness placed in the spool cannot be handed the job it is waiting for,
and it times out after 630 s while the orphaned boot job runs afterwards with no
relay. That cost one boot pair on 2026-09-18 (`run/notes.md`, "what did not
hold" 5). Only the two QEMUs need root, and the harness arranges that itself.

`-quick` is `-run-for 150`, which gives each tunneld a 240 s hold — the workload
finishes in seconds and the hold is what keeps a peer's answerer alive while the
other guest is still fetching. **Do not run this scenario past half an hour**
without changing `init.rootfs`: the exit is started with `-timeout 30m`, which is
a number in the measured image, and a hold longer than that would leave the guest
listening with nothing behind the socket. `-quick` is two orders of magnitude
inside it. The harness writes one `.job` into the spool and
waits; the root runner boots both guests from that one job, because two halves of
a conversation cannot be run one after the other.

## 6. What to capture

The `-capture` directory is written by the harness and already holds what is
wanted: both consoles whole, the relay summary and its pcap, the `boot.job` that
was spooled, the four per-guest adapter files (`tunnel-table-a.json`,
`tunnel-table-b.json`, `exit-allow-a`, `exit-allow-b`), the egress record cut out
of each console, the image's manifest and signed documents, and
`workload-config.json` read back **out of the ext4 image** rather than copied from
the directory it was built from. Add by hand:

- the spooled job, its `.out` and its `.rc` from the spool directory;
- `packaging.txt` and `manifest.txt` from step 1, and the independent prediction
  from step 2;
- a `notes.md` in the shape of `run/notes.md`: the order with line numbers,
  the two hops, the controls, the timings off init's own clock, the image-size
  delta against the rehearsal image (which isolates the adapter's cost in runsc,
  because everything else about the two images is the same), and a "what did not
  hold" section.

Grep both consoles for anything secret before committing. There is no API key in
this run — the agent role never executes in the guest; `agent-probe` runs only as
`-exit` — but grep anyway, as ticket 23 does.

## 7. The pass criteria

The harness asserts all of these and prints `=== N passed, 0 failed ===`. Read
them as three groups.

**It is the run that was intended** (both guests):

- `init: the config device carries a tunnel table` — the adapter path was taken.
- tunneld's start line appears **before** the workload's, checked by line number.
- the console carries the flag set in full, including
  `--tunnel-socket=/run/tunneld/sandbox.sock --tunnel-table=/config/tunnel-table.json`.
- `init: the sandbox socket is up at /run/tunneld/sandbox.sock` — the branch the
  rehearsal could not reach.
- `a sandbox in another process opens and accepts streams here` — tunneld's own
  echo stood down, so anything that answered a peer was the exit.
- `EXIT serving, allow=` — `agent-probe` attached and is holding its list.
- `init: httpd says: served-by: guest-a` on A and `…guest-b` on B.
- `init: no writable path is executable`, no `WRITABLE AND EXECUTABLE`, and
  `init: powering off` at the end rather than the fatal poweroff.

**The two hops, one each way** — this is the ticket's claim:

- guest A's console holds `served-by: guest-b`, and B's holds `served-by:
  guest-a`. Each guest's page is on its own loopback and nowhere else, so those
  bytes can only have crossed the segment inside a tunnel.
- `EXIT accepted a stream from peer=` on both, and `EXIT dialed web.peer-b:80` on
  B and `EXIT dialed web.peer-a:80` on A.
- `4.19.0-gvisor` on both consoles: the process that fetched was in a sandbox.
- `tunneld: PEER key=` on both and `tunneld: REFUSED` on neither.

**The controls** — two per guest, and both are a name that did not resolve rather
than a connection refused, because the sentry answers NXDOMAIN for a name the
table does not carry and `wget` never gets an address:

- `bad address 'not-in-the-table.example'` on both — in nobody's table.
- `bad address 'web.peer-a'` on **A** and `bad address 'web.peer-b'` on **B** —
  each guest is refused the name that is in the *other* guest's table. This is
  the sharpest line in the run: one disk, one image, two guests, and the only
  difference is an unmeasured table that the measured sentry enforces.

**And the segment:** `a_to_b_frames` non-zero, `MARKER not found` for the marker
`served-by: guest-` (the plaintext that crossed, named), and the only addresses
resolved on the segment are `10.14.0.2` and `10.14.0.3`.

## 8. If something fails

| symptom | where to look |
|---|---|
| `init: tunneld exited before /run/tunneld/sandbox.sock existed` | tunneld's `refusing to start` line above it. On SNP it should not appear at all. |
| the helper cannot open the socket | `sandbox.Listen` chmods it 0600 and the owner is the guest's root. init, runsc, the helper and the exit are all uid 0 in the initial user namespace, and `unshare -Ur` maps 0 to 0, so this should not happen; if it does, it is a uid that is not mapped and not a path that is not visible. A pathname socket on `/run` crosses both the mount-namespace copy and the new network namespace — only an abstract socket is per-network-namespace — and that was checked on the workstation before this was written. |
| `EXIT refused "web.peer-b:80": it is not in -allow=…` | `exit-allow` on the **serving** guest's config device — B serves `web.peer-b`. |
| `bad address 'web.peer-b'` on guest **A** | A's `tunnel-table.json`, or the sentry's resolver. That name is the one A is supposed to reach. |
| `wget: can't connect … Network unreachable` | the name resolved and the connect was refused: wrong port in the table, or the helper/tunneld path. Not a resolver problem. |
| `EXIT dialed web.peer-b:80 -> …` then nothing | `httpd` on the serving guest: check its `init: httpd says:` block. |
| the runner never ran the job | `tmux attach -t root-runner-m4` — and check the harness is not itself a job in the spool |
| `open /config/tunnel-table.json: permission denied` | the config device's inodes are not root-owned; `mkconfigdev.sh` chowns them all and checks, since 2026-09-18 |
| an `EXIT` line is missing but the page arrived | the guest's serial console drops lines under contention; `EXIT <dest> ended` is the same evidence |
| a stream opens but no peer is admitted | the ordinary attestation failure surface; `tunneld: REFUSED` names it. |

## 9. Afterwards

Commit the capture and the notes with explicit paths. Then
`docs/runsc-in-the-guest.md` gains a paragraph — this run is the first in which
the measured guest's sandbox reaches something, and it is also where the property
ticket 24 recorded (*the workload runs before tunneld, so there is no link to
leave by*) is deliberately traded for the adapter. `init.rootfs`'s own comment
already says so; the record should too.
