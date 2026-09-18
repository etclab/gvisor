# The SNP run of ticket 26, in one dispatch

Ticket 26's item, on the bench: two measured SEV-SNP guests, a sandbox on each,
a policy pushed at each by the other and enforced by the sentry, one of those
policies **replaced while a fetch is in flight**, and both sandboxes killed so
that the tunneld beside each one loses the liveness the contract's third version
watches for.

Everything below is ready. What is not ready is the code it runs on top of, and
that is the whole of the "before you start" section: this ticket's hardware
scenario was prepared while two other agents were building the things it
asserts. **Do not start until they have landed and you have the four strings
below in your hand.**

## 0. What this needs from the rest of the ticket, and how to check it

| what | where it comes from | how to check | what the harness does with it |
|---|---|---|---|
| **runsc with `Policy.Narrow` and the exec sink** | the sentry agent: `runsc/boot/controller.go`, `pkg/sentry/policyx/`, `pkg/sentry/socket/netstack/tunnel*.go` | `make runsc` in this worktree, then `bazel-bin/runsc/runsc_/runsc flags` must still list `-tunnel-socket` and `-tunnel-table` | it is the binary `package-tunneld.sh` measures into the image |
| **the `SANDBOX applied` line on the Host path** | the contract agent: `attest/sandbox/host.go` | `grep -n 'SANDBOX applied' attest/sandbox/host.go` — today **only `attest/sandbox/null.go:115` has it**, and the adapter path uses `Host`, not `Null` | five assertions read the digest off it (`applied_digests` in `docs/snp/tunnel-on-two-guests.sh`). **Without it the run has no console evidence that the sandbox took the policy at all.** Ask for the same four fields `null.go` prints: `format=`, `version=`, `bytes=`, `sha256=` |
| **the liveness refusal sentence** | the contract agent: `attest/refusal.go`, the eleventh reason | `grep -n 'ReasonPolicyNotLive' attest/refusal.go` | the harness greps for one variable, `LIVENESS_REASON`, defaulting to *"the policy pushed to the peer is no longer live"*. If the sentence is worded differently, run with `LIVENESS_REASON='<the real one>'` in the environment and then fix the default |
| **the `exec_refused` reason string** | the sentry agent: the new seccheck point `sentry/exec_refused`, `reason=not-in-x` | `grep -rn 'exec_refused' pkg/sentry/seccheck/` | the run does **not** assert on it — there is no seccheck receiver inside a measured guest. It asserts on the workload's own `EXEC REFUSED /bin/probe` line, which is the errno the shell reported. Record the reason string in `notes.md` from the loopback spikes instead |

Two strings the harness already relies on **exist today** and should not be
renamed: `tunneld: SANDBOX liveness lost: it pulsed …` and
`tunneld: SANDBOX liveness lost: the sandbox closed its socket`
(`attest/sandbox/host.go`, `lost()` and `reportLost`).

Nothing here needs `sudo` typed. The two QEMUs open `/dev/sev` and go through
the spool; everything else runs as the ordinary user.

## Before you start

| | |
|---|---|
| the adapter's runsc | `make runsc` in this worktree → `bazel-bin/runsc/runsc_/runsc`. Statically linked, and `runsc flags` must list `-tunnel-socket` and `-tunnel-table`. |
| the root runner | up as root in tmux session `root-runner-m4`, watching `/home/pniroula/Projects/gvisor/docs/snp/root-spool`. `tmux ls` says whether it is. |
| the author key | `$STACK/image-ticket14-packaging/author.key` — the key whose public half is inside every image this harness re-signs a set for |
| `attest/` compiles | `package-tunneld.sh` runs `go test ./cmd/tunneld` first and builds `agent-probe` after it; both have to pass |
| the busybox on this host | `busybox-static 1:1.36.1-6ubuntu3.1`; `make-bundle.sh` copies `/bin/busybox` into the bundle and the image build uses the same package |

```
export PATH=/usr/local/go/bin:$PATH
export STACK=/home/pniroula/Projects/gvisor/.scratch/attested-secure-tunnel/host-stack
export SCRATCH=<a directory outside the repo>     # the bundle source and the disk
cd /home/pniroula/Projects/gvisor-t26
```

## 1. The image

```
OUT=$STACK/image-ticket26 \
AUTHOR_KEY=$STACK/image-ticket14-packaging/author.key \
RUNSC=/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc \
  bash docs/snp/image/package-tunneld.sh
unset OUT
```

`AGENT_PROBE` is deliberately not set: the script builds it from
`attest/cmd/agent-probe` (step 2b), checks it is static and carries no checkout
path, and passes it to `build-image.sh`. **Copy
`$STACK/image-ticket26-packaging/packaging.txt` and
`$STACK/image-ticket26/manifest.txt` into the evidence directory.**

This image differs from ticket 25's in `/sbin/init` and in the runsc binary, and
in nothing else. The `init.rootfs` difference is ticket 26's two timing knobs and
the eight mebibytes of `/run/httpd/large` it generates; the manifest's size delta
against `$STACK/image-ticket25/manifest.txt` isolates what the sentry work cost,
because everything else about the two images is the same.

## 2. The prediction, again and on its own

```
SEV_SNP_MEASURE_VENV=$STACK/sev-snp-measure-venv-ticket14 \
  bash docs/snp/image/predict-measurement.sh $STACK/image-ticket26 \
       -vcpus 4 -vcpu-type EPYC-v4 \
       -out docs/snp/evidence/ticket26/snp/predicted-measurement-independent.txt
```

It must equal `sed -n 's/^launch_measurement: //p' $STACK/image-ticket26/manifest.txt`.
The number is computed from the four measured files before anything boots, and
it is never read off a machine.

## 3. The reference values

Nothing to do. The set step 1 emitted and signed is the one the harness copies
onto both config devices unchanged (`make_config`). **Do not author a second set,
and do not pin an RTMR, a policy digest or a peer measurement by hand.** The only
documents that differ between the two guests are the twelve files under
`docs/snp/evidence/ticket26/snp/config/`, and they are neither measured nor
signed — which is the point, because one of them is the policy this ticket is
about.

## 4. The workload disk

```
bash docs/snp/evidence/ticket26/snp/make-bundle.sh $SCRATCH/workload-src $SCRATCH/workload.img
```

One disk, attached read-only to **both** guests. Read the listing it prints. Two
lines matter:

```
/bin/busybox  <sha256>
/bin/probe    <a different sha256>
```

`/bin/probe` is the exec control and the script refuses to build a bundle in
which the two digests are equal. Record the disk's sha256 (`mkworkloaddev.sh`
prints it); the disk is megabytes and is not measured, so it is not committed.

## 5. The run

```
docs/snp/tunnel-on-two-guests.sh \
    -image $STACK/image-ticket26 \
    -out $STACK/image-ticket26-run \
    -scenario policy \
    -workload $SCRATCH/workload.img \
    -spool /home/pniroula/Projects/gvisor/docs/snp/root-spool \
    -capture docs/snp/evidence/ticket26/snp/run
```

**Run this from an ordinary session, never from inside the spool.** The harness
spools the boot job itself, and `docs/snp/root-runner.sh` is a single-threaded
loop: a harness placed in the spool cannot be handed the job it is waiting for,
and it times out while the orphaned boot job runs afterwards with no relay. That
cost one boot pair on 2026-09-18 (`../../ticket25/snp/run/notes.md`, "what did
not hold" 5).

**There is no `-quick` and no `-run-for` here, and giving them changes nothing.**
This scenario is driven by the two numbers on the config devices — guest A is
killed at 150 s, guest B at 210 s, and guest B starts its second tunneld at 40 s
— and the harness derives the tunneld hold (`last + 150` = 360 s) and the boot
timeout (`last + 330` = 540 s) from them and prints all five numbers before it
boots anything. To make the run shorter or longer, edit
`docs/snp/evidence/ticket26/snp/config/{a,b}/{kill-after,narrow-after}` and
nothing else. **Do not take it past half an hour**: the exit is started with
`-timeout 30m`, which is a number inside the measured image.

Budget about eleven minutes of wall clock: two boots, three hundred and sixty
seconds of hold, and the harness's own checks.

## 6. What to capture

The `-capture` directory is written by the harness and already holds both
consoles whole, the relay summary and its pcap, the `boot.job` that was spooled,
the image's manifest and signed documents, `workload-config.json` read back out
of the ext4 image, the egress record cut out of each console, and — new in this
ticket — the twelve unmeasured files as each guest was actually given them:

```
tunnel-table-{a,b}.json  exit-allow-{a,b}
push-policy-{a,b}.json   push-policy-narrow-{a,b}.json
tunneld-narrow-{a,b}.json
kill-after-{a,b}         narrow-after-{a,b}
```

Add by hand:

- the spooled job, its `.out` and its `.rc` from the spool directory;
- `packaging.txt` and `manifest.txt` from step 1, and the independent prediction
  from step 2;
- `mkworkloaddev-output.txt` and the two digests from step 4;
- a `notes.md` in the shape of `../../ticket25/snp/run-2/notes.md`: the order
  with line numbers, the four things the run set out to show, the timings off
  init's own clock, the image-size delta against ticket 25's image, and a "what
  did not hold" section.

**Grep both consoles and every captured file for the API key before committing.**
There is no key in this run — the agent role never executes in the guest, and
`agent-probe` runs only as `-exit` — but grep anyway, as ticket 23 does.

## 7. The pass criteria

The harness asserts all of these and prints `=== N passed, 0 failed ===`. Read
them as six groups; the transcript prints them in this order.

**It is the run that was intended** (both guests): the tunnel table put the guest
on the adapter path; tunneld started before the workload, by line number; the
flag set is on the console in full; the config device carried a policy to push;
httpd is serving and `/run/httpd/large` is 8 388 608 bytes; `init: httpd says:
served-by: guest-<g>`; no writable executable path was ever found.

**The policy is in force.** Guest A's first applied digest is the sha256 of
`config/b/push-policy.json` and guest B's is `config/a/push-policy.json`'s —
each guest's console carries the digest of the document the *other* guest pushed,
because a push is applied by the tunneld beside the sandbox it governs. Then the
two hops, `served-by: guest-b` on A and `served-by: guest-a` on B, each exit
dialing the one destination its list permits, and `4.19.0-gvisor` on both.

**The two controls, one per letter.** `bad address 'not-in-the-table.example'` on
both guests is `N`. `workload: EXEC REFUSED /bin/probe` on both is `X`, and the
line above it — *"no policy carrying an x is in force in this sandbox yet"* — is
what makes it a transition rather than a constant: the same execve succeeded
before the push landed.

**The policy can be replaced.** Guest A's console carries **two** applied digests
and the second is `config/b/push-policy-narrow.json`'s; guest B's carries one.
Guest B says `init: narrow-after: 40s elapsed; starting a second tunneld`. Guest
A's workload says `NARROWED web.peer-b stopped resolving` and, from the stream
that was already open when that happened, `LONG COMPLETE bytes=8388608`.

**The policy is watched.** `tunneld: SANDBOX liveness lost: it pulsed …` on guest
A, and a refusal naming liveness. This is the mismatch branch and it is expected:
tunneld does not parse `n`, `f` or `x`, so a legitimate narrowing pushed on a
second tunnel looks to the first pusher's watcher exactly like a different
policy, and it closes that tunnel. It costs nothing, because guest A's own fetch
is on the tunnel guest A dialed.

**Liveness ends with the workload.** `init: kill-after: …s elapsed` on both,
`tunneld: SANDBOX liveness lost: the sandbox closed its socket` on both, a
refusal naming liveness on guest B, and *not* `nothing killed this workload` on
either — a workload that ran out of sleep proves nothing about a kill.

**And the segment:** `a_to_b_frames` non-zero, `MARKER not found` for
`served-by: guest-`, and only `10.14.0.2` and `10.14.0.3` resolved on it.

**Two lines that are printed and not asserted.** `workload: OBSERVE exec
/bin/uname` and `workload: OBSERVE exec /bin/sh` say what the sentry did with an
execve through a symlink to `/bin/busybox`. That decides what an `x` written by
path can mean and nothing in this run depends on it; copy both into `notes.md`,
whichever way they came out.

## 8. If something fails

| symptom | where to look |
|---|---|
| no `SANDBOX applied` line anywhere, on either guest | §0, row 2. `Host.Apply` logs nothing today. The policy may well have been applied; the console cannot say so. |
| `FAIL … refused, naming liveness` but everything else passed | the sentence moved. `grep -n Reason attest/refusal.go`, then re-run the assertions with `LIVENESS_REASON=…`. |
| `workload: EXEC NOT REFUSED after 30 attempts` | the exec sink is not installed, or `x` was never applied. Check for an applied digest above it on the same console. |
| `workload: NOT NARROWED` | guest B's second tunneld never established. Look for its own `tunneld:` lines on B's console after `narrow-after`, and for a `REFUSED` on A. |
| `workload: LONG SHORT bytes=…` | the stream was cut. If the byte count is near zero the fetch never started; if it stops within a second of the narrowing, `Policy.Narrow` did not leave live streams alone — **that is the stop condition in the ticket**, not a harness problem. |
| guest B's second tunneld says `refusing to start: listen … asks for port` | `tunneld-narrow.json` lost its empty `listen`. An empty one is the only one the ceiling has no opinion about. |
| guest B's second tunneld cannot reach guest A | it dials with a socket of its own (`quic.DialAddr`), and the ceiling grants `udp dport 4433` outbound on eth0 from any source port. If this fails the ceiling changed. |
| `init: tunneld exited before /run/tunneld/sandbox.sock existed` | tunneld's `refusing to start` line above it. On SNP it should not appear at all. |
| `EXIT refused "web.peer-b:80": it is not in -allow=…` | `exit-allow` on the **serving** guest's config device — B serves `web.peer-b`. |
| `bad address 'web.peer-b'` on guest **A** *before* the narrowing | A's `tunnel-table.json`, or the first push narrowed more than it should have. Compare the first applied digest against `config/b/push-policy.json`. |
| `wget: can't connect … Network unreachable` | the name resolved and the connect was refused: off-policy connect is `ENETUNREACH` by design, so this is `n` not carrying the port. |
| the runner never ran the job | `tmux attach -t root-runner-m4` — and check the harness is not itself a job in the spool |
| `open /config/tunnel-table.json: permission denied` | the config device's inodes are not root-owned; `mkconfigdev.sh` chowns them all and checks, since 2026-09-18 |
| an `EXIT` line is missing but the page arrived | the guest's serial console drops lines under contention; `EXIT <dest> ended` is the same evidence and `exit_served` accepts either |

## 9. Afterwards

Commit the capture and the notes with explicit paths. Then
`docs/policy-in-the-sentry.md` gains the SNP transcript, and this run is the
first in which a measured sentry enforced a policy it was handed rather than one
it booted with.

Add a line to the ledger discipline this ticket inherits: the SNP run creates no
cloud resource and spends no API money, so there is nothing to put in
`docs/snp/cloud/tdx/RESOURCES.md` for it. The TDX run is the one with a ledger
(`../tdx/RUNBOOK.md`).
