# The SNP run of ticket 26: `=== 73 passed, 0 failed ===`

The run the record names. One image, two SEV-SNP guests, one workload disk
attached to both, 2026-09-18, branch `ticket-26-the-sandbox-honors-a-pushed-policy`.
It is the fourth boot pair of five; `../run/`, `../run-2/`, `../run-3/` and
`../run-5/` are kept as they stand and the section "The five pairs" below says
what each one changed and what it cost. Nothing under `pkg/`, `runsc/` or
`attest/` was touched to get here: every change between the pairs is in the
harness, in the unmeasured config, or in `/sbin/init`.

```
image                 $STACK/image-ticket26 (rebuilt in place for each pair)
launch measurement    5d73c959b5356dc63bf1ea4dd39562dee6679713c6fe87168bb75817defea9fde1c213863ea2d3beed28d9da4feb6dbc
                      predicted offline twice before either guest existed, and reported by both
verity root hash      4fe103f12515250a74ee88a8675d25543bbbd58135531262732176979034658e (21,916 data blocks)
runsc                 6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819, 109,044,910 bytes
                      (bazel-bin/runsc/runsc_/runsc at 3acfe11b5, copied to $STACK/runsc-ticket26)
tunneld               241fb424f1f3db04dfbd8688c993b7f2d0cf63baa2c3bc31bc11802388a027c6, 17,597,809 bytes
agent-probe           fc100aad383a0023079f64d2272585fe871e6539a7f87cd075233577dd22af6a, 9,214,897 bytes
/sbin/init            d6111b514656a4273bc54d31edde1288fb22465b94d5bd5fd5c29a074411e1db, 29,767 bytes
ceiling digest        197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973 (unchanged since ticket 22)
author public key     3f27c388b8c18afb53cce0214c3a9c7650290073d23ceffe09042c8d017dec72
workload disk         524087392626984847b6f97d6cf98a211adae654cc7e87d7fb3e5b698d8cfdf3 (not measured)
  /bin/busybox        dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14
  /bin/probe          75dfb7becbff66f9083b1fa955bef2d0c6de178a8892bbfaff82fa26515d00b9   the exec control
boot job              policy/boot.job.ran, rc 0, spooled by the harness from an ordinary session
```

## What differs from ticket 25's image

Five files, and the ticket is in four of them:

| | ticket 25 | ticket 26 |
|---|---|---|
| `/usr/bin/runsc` | `ea305e12…4ba0`, 108,957,306 B | `6019cbf4…7819`, 109,044,910 B (**+87,604**) |
| `/usr/bin/tunneld` | `57d56c40…a24c`, 17,573,981 B | `241fb424…027c6`, 17,597,809 B (**+23,828**) |
| `/usr/bin/agent-probe` | `cee5c9ab…59e0`, 9,204,810 B | `fc100aad…af6a`, 9,214,897 B (**+10,087**) |
| `/sbin/init` | `1ee5c0cb…a1ff`, 20,706 B | `d6111b51…e1db`, 29,767 B (**+9,061**) |
| verity data blocks | 21,905 | 21,916 (**+11**, 45,056 B) |

The runbook said the difference would be `/sbin/init` and runsc. It is those two
and the two Go binaries as well, because contract v3 is in both ends: tunneld
gained the eleventh refusal reason and the liveness watch, and `agent-probe`
gained the client side of the `alive` message it now sends as an attached
sandbox. The kernel, the firmware, `/etc/hosts`, `/srv/index.html` and every
busybox applet are byte for byte ticket 25's.

## The five pairs

Every pair booted the same two guests with the same twelve unmeasured files; what
changed is named, and nothing that changed is in the enforcement path.

| pair | what changed since the one above | measurement | result |
|---|---|---|---|
| `../run/` | — | `f8b60b78…ef31` | 69 passed, 4 failed |
| `../run-2/` | tunnel idle timeout 60 s → 420 s (harness); the exec control asks once before anything else (workload script) | `f8b60b78…ef31` | 72 passed, 1 failed |
| `../run-3/` | `kill_later` reads the whole process table before it signals, and prints it (`/sbin/init`) | `5dad2470…c5fb` | 68 passed, 5 failed |
| **`.` (run-4)** | `kill_later` matches **argv[0] out of `/proc/PID/cmdline`** and not `comm` (`/sbin/init`) | `5d73c959…6dbc` | **73 passed, 0 failed** |
| `../run-5/` | the sentry's `tunnel narrow:` lines are picked out of the debug log onto the console (`/sbin/init`) | `1bc0c930…a1f2` | 71 passed, 2 failed — two console lines lost, below |

The three failures the first pair found are worth the space, because two of them
are facts about the design and one is a fact about gVisor:

1. **A liveness watch lives exactly as long as the tunnel the policy arrived
   on.** `attest/tunneld/push.go`'s `watchLiveness` polls `conn.Live()` every
   second and returns — silently, with no line and no refusal — the moment it is
   false. At the sixty-second idle timeout every earlier scenario used, both
   tunnels here idled out about a minute after the last fetch and a hundred
   seconds before the first kill, so the kill that was supposed to end liveness
   had nobody watching. Nothing is wrong with that: a watch whose tunnel is gone
   has nothing left to tear down. But it means *this* run's idle timeout has to
   outlive its own hold, and it now does (420 s, derived as `hold + 60`, printed
   with the other four numbers before anything boots).
2. **The exec control is a race with the push, and the first pair lost it.**
   `EXEC REFUSED /bin/probe on attempt 1` is a true statement about a governed
   sandbox and no statement at all about the transition, because the policy had
   landed before the workload's first execve. The workload now asks once, before
   it does anything else, and prints whichever way it came out. In pairs 2, 4 and
   5 it won the race on both guests; the window is the two-tenths of a second
   between the sandbox starting and the peer dialing.
3. **`kill_later` could not see the sandbox.** It matched `comm`, and the
   sentry, the gofer and the tunnel helper are all re-execs of `/proc/self/exe`
   with `Args[0]` set afterwards, so each one's `comm` is `exe` —
   `runsc/container/container.go:1486` says so in as many words. The third pair
   printed the table it was matching against and settled it:
   `the sandbox in this table is unshare(183) runsc(184)`. Two processes, and the
   one whose death is the contract's teardown — the helper, which holds the
   sandbox's end of tunneld's socket — was not among them. Matching argv[0] out
   of `cmdline` finds all five:

   ```
   init: kill-after: round 1, the sandbox in this table is unshare(181) /usr/bin/runsc(182) runsc-gofer(190) runsc-tunnel-helper(191) runsc-sandbox(192)
   init: kill-after: round 1 killed 5 processes
   ```

## The pass table

All 73, grouped as the runbook groups them. `A` and `B` are the two consoles,
`policy/console-a.txt` and `policy/console-b.txt`.

| group | criterion | A | B |
|---|---|---|---|
| the right run | booted the measured image and ran the packaged tunneld | PASS | PASS |
| | read the author key from inside the launch measurement | PASS | PASS |
| | read the set and chain from the config device | PASS | PASS |
| | the tunnel table put this guest on the adapter path | PASS | PASS |
| | tunneld started before the workload, by line number | PASS | PASS |
| | runsc launched with the adapter's two flags | PASS | PASS |
| | the config device carried a policy for this guest to push | PASS | PASS |
| | httpd serving, and `/run/httpd/large` is 8,388,608 bytes | PASS | PASS |
| | `init: httpd says: served-by: guest-<g>` | PASS | PASS |
| | no writable path in the image is executable, and none was ever found | PASS | PASS |
| | powered off at the end rather than being stopped | PASS | PASS |
| attested | acquired its own evidence from the platform | PASS | PASS |
| | bundled the chain provisioned on its config device | PASS | PASS |
| | is listening; the sandbox socket came up; a sandbox attached | PASS | PASS |
| | the exit attached holding the list its config device carries | PASS | PASS |
| | admitted its peer's evidence, refused nobody | PASS | PASS |
| | said what it was about to push, out of its own config device | PASS | PASS |
| **in force** | the sandbox was given the policy the *other* guest pushed, by digest | PASS | PASS |
| | the sandbox was served the peer's page through the peer's exit, under it | PASS | PASS |
| | the exit served a peer's stream and dialed its one permitted destination | PASS | PASS |
| | an exit recorded the attested identity of the peer it served | PASS (both) | |
| | the fetching process was inside a gVisor sandbox | PASS | PASS |
| **the controls** | the name in nobody's policy did not resolve | PASS | PASS |
| | an exec outside the policy's `x` was refused inside the sandbox | PASS | PASS |
| | and it was allowed before the policy landed | PASS | |
| **replaced** | the sandbox was given a second policy without being restarted | PASS | |
| | and it is the narrower document guest B pushed, by digest | PASS | |
| | guest B started a second tunneld rather than restarting the first | | PASS |
| | guest B's own sandbox was never narrowed: one policy, one digest | | PASS |
| | the dropped name stopped resolving | PASS | |
| | the stream already open when that happened arrived whole | PASS | |
| | the same body read in one go from the other side | | PASS |
| **watched** | tunneld noticed its sandbox pulsing a digest it was not watching for | PASS | |
| | and refused, naming liveness | PASS | |
| **ends with the workload** | init killed the sandbox after its config device's seconds | PASS | PASS |
| | the socket closing is what tunneld saw, not three missed pulses | PASS | PASS |
| | and it refused the tunnel the policy arrived on, naming liveness | PASS | PASS |
| | the workload was killed rather than running out of work | PASS | PASS |
| the segment | the exchange went through the relay | PASS | |
| | the relay could not find the page's text on the wire | PASS | |
| | no guest looked for a gateway or anything off the segment | PASS | |

### The policy in force, and whose it is

```
A:581  SANDBOX applied format=policy version=1 bytes=110 sha256=681331c69aedad34d51e9e1f325889ff81863885d1067055bf005ca9e33b785d
B:583  SANDBOX applied format=policy version=1 bytes=110 sha256=b23887d06a044f0752371ed8899c752ce0023a2aeaec56424e0cc3b747381268
```

`681331c6…b785d` is `sha256sum` of `../config/b/push-policy.json` and
`b23887d0…81268` is `../config/a/push-policy.json`'s: each guest's console
carries the digest of the document the **other** guest pushed, because a push is
applied by the tunneld beside the sandbox it governs. Both lines appear twice,
once from `attest/sandbox`'s host logger and once with tunneld's prefix, which is
one line written to two sinks and not two applications.

### The two hops, in the guests' own words

```
A:583  EXIT accepted a stream from peer="guest-b" vendor=amd-sev-snp measurement=5d73c959…6dbc policy_digest=…
A:584  EXIT dialed web.peer-a:80 -> 127.0.0.1:80
A:602  served-by: guest-b
A:603  workload: wget exit 0 for http://web.peer-b/
B:599  served-by: guest-a
B:603  workload: wget exit 0 for http://web.peer-a/
```

and the sentry's own account of the same two fetches, out of the debug log:

```
A  tunnel dns: q="web.peer-b" type=A answer=100.64.1.0
A  tunnel attach: web.peer-b:80 -> peer "guest-b": ok in 96.482342ms, host fd 41, local 100.64.0.1:40001
B  tunnel attach: web.peer-a:80 -> peer "guest-a": ok in 159.689431ms, host fd 41, local 100.64.0.1:40001
```

### The two controls, one per letter

`N`, on both guests, and it is the sentry's responder that says so:

```
A:605  workload: --- GET http://not-in-the-table.example/ (attempt 1)
A:608  workload: wget exit 1 …: the name did not resolve, so this sandbox's policy does not carry it
A      tunnel dns: q="not-in-the-table.example" type=A answer=nxdomain
```

`X`, and it is a transition and not a constant — the same execve ran a moment
earlier, before the push landed:

```
A:579  workload: exec /bin/probe attempt 0: it ran (rc=127); no policy carrying an x is in force in this sandbox yet
A:581  SANDBOX applied … sha256=681331c6…b785d
A:609  workload: EXEC REFUSED /bin/probe on attempt 1: /policy-probe.sh: line 150: /bin/probe: Permission denied
A      exec refused: path="/bin/probe" sha256=75dfb7be…d00b9 reason=not-in-x        (policyx.go:228)
```

Both guests print all four lines. `rc=127` is busybox declining to be a `probe`
applet, which is what "it ran" looks like; what matters is that the errno changed
from "it ran" to `EACCES` across one push, and that the sentry names the identity
it refused and the reason `not-in-x` — the reason string recorded on the
workstation in `../../adapter-check/notes.md` and never asserted on here, because
there is no seccheck receiver inside a measured guest.

### The policy replaced, under a stream that was already open

```
B:654  init: narrow-after: 40s elapsed; starting a second tunneld to push /config/push-policy-narrow.json at the peer
A:620  SANDBOX applied format=policy version=1 bytes=76 sha256=92fb0e17644f61d44d0fa7c8ed10d2c5af5b9ccf75911a4d106463ba2967248e
A:628  workload: NARROWED web.peer-b stopped resolving on attempt 14: wget: bad address 'web.peer-b'
A:633  workload: LONG COMPLETE bytes=8388608 (the whole body arrived, and the stream outlived whatever happened to the policy under it)
B:616  workload: LONG-B bytes=8388608 expected=8388608
```

Guest A's console carries two applied digests and guest B's one, which is the
whole of "replaced, not restarted": the same sandbox, the same workload process,
a second policy. The eight mebibytes were being read a chunk a second when the
second policy landed, and all 8,388,608 of them arrived.

### The policy watched, both branches

The mismatch branch, which the narrowing produces by construction — tunneld does
not parse `n`, `f` or `x`, so a legitimate narrowing pushed on a second tunnel is
a different digest to the first pusher's watch:

```
A:626  tunneld: SANDBOX liveness lost: it pulsed 92fb0e17…7248e, expected 681331c6…b785d
A:627  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live:
       a peer at 10.14.0.3:50351 pushed a policy this sandbox no longer enforces: it pulsed …
```

and the branch the ticket is really about, on both guests, after the kill:

```
A:635  init: kill-after: 150s elapsed; killing the sandbox, so that nothing inside it gets to say goodbye
A:637  init: kill-after: round 1, the sandbox in this table is unshare(181) /usr/bin/runsc(182) runsc-gofer(190) runsc-tunnel-helper(191) runsc-sandbox(192)
A:653  tunneld: SANDBOX liveness lost: the sandbox closed its socket
A:654  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live:
       a peer at 10.14.0.3:59512 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
B      the same two lines, after `init: kill-after: 210s elapsed`
```

Neither guest says `nothing killed this workload`, which is the line the workload
prints if it reaches the end of its sleep: what ended these two sandboxes was a
signal from outside and not a script that ran out of work.

## Timings, off init's own clock

| | A | B |
|---|---|---|
| `no writable path is executable` | 3.24 s | 3.25 s |
| tunneld started → sandbox socket up (evidence, chain, listener) | 3.75 → 4.25 s (**0.50 s**) | 3.73 → 4.24 s (**0.51 s**) |
| runsc launched | 4.52 s | 4.41 s |
| runsc spawn → the sandbox's first name lookup | **0.572 s** | **0.496 s** |
| first `tunnel attach` on a tunnel that did not exist yet | 96.5 ms | 159.7 ms |
| later attaches on the warm tunnel (median, n) | 21.0 ms (16) | 23.3 ms (3) |
| narrow-after fired | — | 44.40 s |
| kill-after fired | 154.52 s | 214.41 s |
| all five sandbox processes signalled | 155.29 s (**0.77 s**) | 215.09 s (**0.68 s**) |
| the table is clear | 156.88 s | 216.58 s |
| teardown reported, bounded by those two | ≤ 2.4 s after the kill | ≤ 2.2 s after the kill |

The teardown bound is the console's, not the watch's: `attest/sandbox`'s watch
ticks at a quarter of a pulse (250 ms), and what the 2.4 s brackets is the kill
loop signalling five processes and init printing its mount table in between.
`../run-5/` measures the other half of this, the sentry's own cost of taking a
policy, because its `/sbin/init` puts the `tunnel narrow:` lines on the console:
**1.314 ms on A and 965 µs on B, of which the table swap was 173 µs and 67 µs.**

## The segment

```
l2relay: RELAYED a_to_b_frames=8316 b_to_a_frames=8234 a_to_b_bytes=9010174 b_to_a_bytes=9015758 tampered=0
l2relay: MARKER not found hits=0 marker='served-by: guest-' in 16550 frames carrying 18025932 bytes
  ethertypes : IPv4=16536, ARP=14      arp targets : 10.14.0.2, 10.14.0.3
```

Eighteen megabytes crossed the wire — the two pages, the two eight-mebibyte
bodies and the handshakes — and the machine copying every frame found neither
page's text. Only the two guests' own addresses were ever resolved on it.

## Two lines printed and not asserted

```
workload: OBSERVE exec /bin/uname (a symlink to busybox): rc=0 out='Linux workload 4.19.0-gvisor …'
workload: OBSERVE exec /bin/sh (a symlink to busybox): rc=0 out='ran'
```

Both on both guests, both ran. An `x` written as a path therefore names the file
an execve **resolved to** and not the name it was given: `/bin/uname` and
`/bin/sh` are symlinks to the `/bin/busybox` the policy permits, and the sentry
reported the target. That is spike E2 §3a's answer, unchanged on hardware, and it
decides what a path in `x` can mean — a busybox applet symlink is the applet's
target, and a shebang script is reported as itself.

## What did not hold

**Nothing in this pair.** 73 of 73. What did not hold in the other four is in
"The five pairs" above, and three things are worth carrying forward:

1. **`../run-3/` recorded a defect in the contract, not in the harness, and it is
   not fixed here.** Guest B's console carries `SANDBOX applied … b23887d0…81268`
   and, for the sixty seconds after it, thirty lines of
   `exec /bin/probe attempt N: it ran … no policy carrying an x is in force in
   this sandbox yet`. `attest/sandbox/host.go`'s `Apply` pushes to *the
   attachments that exist at that instant* (`h.conns` is copied under the lock and
   iterated), and on that boot guest A dialed and pushed before guest B's runsc
   helper had attached — the console shows
   `REFUSED … the policy pushed to the peer was not applied` at line 556, the
   helper attaching at 558, and the successful apply at 577 reaching only what was
   attached then. A sandbox that attaches after a push never receives it, tunneld
   says a policy is in force, and the sentry beside it is enforcing nothing. On a
   vendor whose only diagnostic is the console this is the difference between a
   claim and a fact. Recorded, not fixed (`DOCTRINE`: fixes are the
   definition-of-done items).
2. **The receiving side's watch is not reliably observed at the kill.** Over the
   two pairs with a working kill, guest A reported the socket close twice and
   guest B once. In `../run-5/` guest B's console carries neither the loss nor the
   refusal, and both would have been printed in the middle of init's debug dump —
   the same region where this pair's two lines landed *garbled* (`console-b.txt`
   line 722 interleaves three writers). Ticket 25's run 1 recorded the same
   console-contention loss and drew the same lesson: anything a run must prove
   should be printed away from a flood, and init's dump of the sentry's debug log
   is the flood. Not fixed here; a sixth pair would have cost a boot and bought a
   line.
3. **Nothing measured the `f` list.** It is empty in both pushed documents on
   purpose, and what makes the bundle's root read-only and the config device
   `noexec` is the mount table, which the console prints after the workload:
   `/dev/vdc /workload ext4 ro,nosuid,nodev,relatime`. `F` is mounts and only
   mounts in this ticket, and the record says so rather than the policy.

Two more things are true of this pair and are not failures.
`--debug --debug-log=/run/runsc-debug/` is in the measured flag set and costs
about half a second of sandbox start — it is the price of every `tunnel dns:`,
`tunnel attach:` and `tunnel narrow:` line quoted above existing at all. And
`tunneld: SANDBOX attached` appears twice per guest, because the exit and the
runsc tunnel helper are both clients of one socket; unchanged since ticket 25,
benign, and — as `Apply` pushing to every attachment shows — load-bearing.
