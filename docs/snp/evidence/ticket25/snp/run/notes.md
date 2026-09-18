# The SNP run: two sandboxes on the adapter, one image, two hardware guests

**`=== 51 passed, 2 failed ===`**, and the two that failed are two log lines that
did not survive guest B's serial console — not two things that did not happen.
Everything the ticket asks for happened, in both directions, on SEV-SNP
hardware. 2026-09-18, worktree `/home/pniroula/Projects/gvisor-t25`, branch
`ticket-25-the-adapter-intercept-and-handoff`. One boot pair.

```
image                 $STACK/image-ticket25
launch measurement    697bbdcd57b30d44c9ef8e287ad3641bf72f728a54080c418b42cd02a43f40afaa955928e6e86e9996397b06ef56186e
                      predicted offline twice before any guest existed, and reported by both guests
runsc                 ab593dc254fe9617d8370ce77f81ae5abeb4483e4c980c4605247d441a1f4f70, 108,931,400 bytes
agent-probe           cee5c9abee948d024d754cf5837bd9e74ab79630ce52f43b24effc3c583c59e0, 9,204,810 bytes
tunneld               57d56c404a0fa5a12186af3b93c046f4ad47bf543866e27d071680f45cdea24c
ceiling digest        197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973
workload disk         59570b7819c6e12683555ec2b39d435cfe0ad3d6436a33622f209810e535c691 (one disk, both guests, not measured)
```

## The one sentence

Two guests booted one image; the only difference between them was a 64-byte
JSON file on an unmeasured disk; and that file decided, through a resolver
inside the measured sentry, which of three names each guest's sandbox could
reach — while the page each fetched came out of the *other* guest's loopback,
through an exit that had judged its peer's evidence, over a tunnel whose bytes
the machine in the middle of the segment could not read.

## The timeline, per guest, off init's own clock

| | guest A | guest B |
|---|---|---|
| `no writable path is executable` | 3.03 s | 2.80 s |
| tunneld started, in the background, ahead of the workload | 3.50 s | 3.23 s |
| `the sandbox socket is up at /run/tunneld/sandbox.sock` | 4.01 s | 3.73 s |
| httpd serving, and init's own fetch of its own page | `served-by: guest-a` | `served-by: guest-b` |
| `EXIT serving, allow=` | `web.peer-a:80` (A:569) | `web.peer-b:80` (B:569) |
| runsc started | 4.19 s | 3.80 s |
| workload exited 0 | 5.48 s | 5.28 s |
| **the sandbox** | **1.29 s** | **1.48 s** |
| `tunneld exited with status 0`, `powering off` | A:636 | B:634 |

The sandbox costs about the same 1.3–1.5 s it cost in ticket 24 (0.85–0.90 s
there), and the extra is `--debug` writing 16 MB of log to a tmpfs.

## The two hops

**Guest A's sandbox fetched guest B's page.** The sentry's own account (A:612-614):

```
tunnel dns: q=web.peer-b type=A answer=100.64.1.0
tunnel dns: q=web.peer-b type=AAAA answer=noerror-empty
tunnel attach: web.peer-b:80 -> peer "guest-b": ok in 52.848771ms, host fd 40, local 100.64.0.1:40001
```

and what came back, on A's console inside the workload's output (A:589-590):

```
served-by: guest-b
workload: wget exit 0 for web.peer-b
```

**Guest B's sandbox fetched guest A's page**, the mirror image (B:612-614, B:590-591):

```
tunnel dns: q=web.peer-a type=A answer=100.64.1.0
tunnel attach: web.peer-a:80 -> peer "guest-a": ok in 128.791466ms, host fd 40, local 100.64.0.1:40001
served-by: guest-a
workload: wget exit 0 for web.peer-a
```

Neither page is reachable on the segment: each httpd binds `127.0.0.1:80` inside
its own guest. `served-by:` is written by `/sbin/init` out of the `sandbox_id` on
each guest's config device, so the line on A's console can only have been
produced inside B.

**And the far end saw an attested peer, not an address** (A:576-577):

```
EXIT accepted a stream from peer="guest-b" vendor=amd-sev-snp
     measurement=697bbdcd…186e policy_digest=197d4aae…b973
EXIT dialed web.peer-a:80 -> 127.0.0.1:80
```

The measurement in that line is the number predicted offline for the image, and
the policy digest is the compiled-in ceiling's.

## The four controls

Two per guest, and every one of them is a name that never became an address:

| guest | name | the sentry said |
|---|---|---|
| A | `web.peer-a` (in B's table, not in A's) | `tunnel dns: q=web.peer-a type=A answer=nxdomain` (A:615) |
| A | `not-in-the-table.example` | `answer=nxdomain` (A:617) |
| B | `web.peer-b` (in A's table, not in B's) | `answer=nxdomain` (B:610) |
| B | `not-in-the-table.example` | `answer=nxdomain` (B:615) |

and the workload's own view, four times: `wget: bad address '…'`, followed by
`the name did not resolve, so it is not in this guest's tunnel table; not
retrying`. **This is the sharpest pair of lines in the run**: `web.peer-a`
resolves on B and does not resolve on A, and the two guests are the same image,
the same binaries, the same workload disk and the same page. The only thing that
differs is 64 bytes on a disk that is in no measurement, and the thing that
enforced it is in the measurement.

## The segment

```
l2relay: RELAYED a_to_b_frames=56 b_to_a_frames=52 a_to_b_bytes=40116 b_to_a_bytes=34054
l2relay: MARKER not found hits=0 marker='served-by: guest-' in 108 frames carrying 74170 bytes
  ethertypes : IPv4=104, ARP=4     ip protocols: UDP=104
  arp targets : 10.14.0.2, 10.14.0.3
```

The marker is the page's own text. It crossed the segment twice — once each way —
and the machine copying every frame could not find it in any of them. 104 UDP
frames and nothing else; the only addresses either guest asked for are each
other's.

## Both guests attested, and each admitted the other

```
tunneld: tsm: provider "sev_guest" (amd-sev-snp) returned 1184 bytes of evidence …
         bundled the 4759-byte chain provisioned in /config for chip 9b3716…5243
         at bootloader=9 tee=0 snp=23 microcode=72
tunneld: PEER key=08d7c0d5d466e270… chain=0957b4aa0678b511… measurement=697bbdcd57b30d44… (on A, about B)
tunneld: PEER key=273bb2084aab779a… chain=0957b4aa0678b511… measurement=697bbdcd57b30d44… (on B, about A)
```

Distinct keys, one chain (one chip), and the measurement each reported is the one
predicted offline. `tunneld: REFUSED` appears on neither console.

## What did not hold

**1. Two of guest B's exit log lines are not on guest B's console, and the two
assertions that look for them failed.** They are

```
EXIT accepted a stream from peer="guest-a" … measurement=… policy_digest=…
EXIT dialed web.peer-b:80 -> 127.0.0.1:80
```

and guest A has both of its equivalents. What guest B *does* have is
`EXIT web.peer-b:80 ended` (B:609), which `serveConnect` writes only after
`net.Dial` succeeded and the pump finished — the refusal path returns before it
(`attest/cmd/agent-probe/exit.go:153-170`). So B's exit accepted the stream and
dialed, three times over: that line, guest A holding B's page, and A's own
mirror-image pair.

It is console loss and not function. The two missing lines are the longest the
exit writes (~230 characters), they were due at `14:51:14.76` — the exact instant
B's own workload was writing A's page body to the same serial port and tunneld
was writing its `PEER` line — and B's `… ended` line arrived out of order, after
init's post-workload mount table (B:609 against A:594). **The assertions were
deliberately not edited after the fact.** They are over-specific about *which* of
the exit's lines has to survive a contended serial console, and the next run
should accept `EXIT <dest> ended` as the same evidence.

**2. The measured guest's console drops lines under contention.** That is the
general form of (1) and it is new: no scenario before this one had four
processes writing to `/dev/console` at once. Anything a future run must prove
should be read out of a file in the guest and printed once, the way the sentry's
debug log is, rather than written live by a process competing with the workload.

**3. `tunneld: SANDBOX attached on /run/tunneld/sandbox.sock` appears twice on
each guest.** Expected and worth writing down: the exit and the runsc tunnel
helper are both clients of the same socket. Nothing went wrong — the exit is the
only one that calls `Accept`, and the helper only calls `Open` — but a second
client on that socket is a thing this design now has, and a pushed policy in this
arrangement would go to whichever `sandbox.Host` picked. No policy was pushed
here.

**4. The sandbox is slower than ticket 24's, by about 0.5 s**, because
`--debug --debug-log=/run/runsc-debug/` is now in the measured flag set: 16,900
bytes of `run` log on the rehearsal and 16 MB across the three logs here. It buys
the `tunnel dns:` and `tunnel attach:` lines above, which are the only direct
evidence of what the adapter decided, and without which the failed run below
could not have been diagnosed at all.

**5. Two boot pairs were spent, not one, and the first was my mistake.** It is
kept whole in `segment-down/`. I put the *harness itself* into the job spool; the
runner is a single-threaded loop (`docs/snp/root-runner.sh`), so the boot job the
harness spools from inside its own job could not run until the harness finished,
and the harness timed out waiting for it after 630 s. The runner then picked up
the orphaned boot job and ran it with no relay — its relay had died with the
harness — so both guests booted and neither could reach the other:

```
tunnel attach: web.peer-b:80 -> peer "guest-b": unavailable in 5.02039148s
  (… tunneld: tunnel not established: "guest-b" at 10.14.0.3:4433:
   tunnel: dialing 10.14.0.3:4433: timeout: no recent network activity)
```

That pair is not wasted as evidence: it is a real SNP boot in which everything
local worked — evidence acquired, socket up at 3.95 s, the exit attached with its
list, httpd serving, the sandbox resolving `web.peer-b` to `100.64.1.0` and
asking for a stream, both controls NXDOMAIN, workload exit 0 — and only the
segment was missing. It is also what the `unavailable` path looks like on
hardware, which nothing else here shows. The runbook now says plainly that the
harness must be run from an ordinary session and spools only the boot job.

**6. A bug found and fixed before the hardware, on a free control boot.** The
first control boot of this image died with

```
FATAL ERROR: running container: creating container: cannot create sandbox:
  cannot create sandbox process: starting the tunnel helper:
  opening the tunnel table "/config/tunnel-table.json": permission denied
```

`mkconfigdev.sh` set only the root directory's owner (`-E root_owner=0:0`) and
left every file owned by whoever ran it, and this session's umask is 077, so the
table was mode 0600 owned by uid 253477. Every previous reader of that device was
tunneld, which runs as init's root in the initial user namespace and has
`CAP_DAC_OVERRIDE` over any file; the tunnel table is the first file on it read
from **inside** runsc's user namespace, which maps one id, and a capability over
a file is only a capability when the owner is mapped
(`capable_wrt_inode_uidgid`, `user_namespaces(7)`). This is ticket 24's
`mkworkloaddev.sh` finding, one device over, and it has the same fix: every inode
chowned to 0:0 with `debugfs` and checked afterwards. Had it not been caught on
an unprivileged boot it would have cost the hardware pair, because the harness
running as root would have hidden it.

## Files here

| file | what |
|---|---|
| `capture/` | the harness's own capture: both consoles whole, the relay and its pcap, the spooled `boot.job`, the four per-guest adapter files, the egress record per guest, the image's signed documents, `workload-config.json` read back out of the ext4 image |
| `jobs/` | the job the harness spooled, its output untrimmed, its exit status; and the outer job that deadlocked |
| `segment-down/` | the first pair, whole: two consoles and the orphaned job |
| `manifest.txt`, `packaging.txt`, `reference-values.inputs.txt` | what was measured and what went into the signed documents |
| `predicted-measurement-independent.txt` | the launch measurement computed a second time, on its own, before anything booted |
| `mkworkloaddev-output.txt`, `harness-stdout.txt` | the disk, and the harness's own transcript |
