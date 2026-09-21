# The SNP run, on the reviewed adapter: `=== 52 passed, 0 failed ===`

The run the record names. One image, two SEV-SNP guests, one boot pair,
2026-09-18, branch `ticket-25-the-adapter-intercept-and-handoff`. Run 1
(`../run/`) is kept as it stands and is still the fuller failure record; this is
the same topology on the adapter as it was finally reviewed, and nothing about
the boundary changed between them.

```
image                 $STACK/image-ticket25 (rebuilt in place)
launch measurement    81dbfc3818d9918c061e27c32cfb9694d06d06bc51df323d8f3436d0612a85e182e8f06b14a39ca1eff3ed7375a6add9
                      predicted offline twice before any guest existed; reported by both guests
verity root hash      7c131c2e36648159e3f7de533b441d5bd7ec2af1ac87343ff8317269722e30ec (21,905 data blocks)
runsc                 ea305e126ab20e4abc525317f8ab7c04179b0cf0e08a517de6c3799a4b3c4ba0, 108,957,306 bytes
agent-probe           cee5c9abee948d024d754cf5837bd9e74ab79630ce52f43b24effc3c583c59e0  (byte for byte run 1's)
tunneld               57d56c404a0fa5a12186af3b93c046f4ad47bf543866e27d071680f45cdea24c  (byte for byte run 1's)
ceiling digest        197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973
workload disk         59570b7819c6e12683555ec2b39d435cfe0ad3d6436a33622f209810e535c691  (the same file run 1 booted)
boot job              jobs/tunnel-720121-adapter.job, rc 0, spooled by the harness from an ordinary session
```

## What differs from run 1, and it is one file

`diff` of the two manifests moves five lines and they all follow from one:

| | run 1 | run 2 |
|---|---|---|
| `/usr/bin/runsc` | `ab593dc2…4f70`, 108,931,400 B | `ea305e12…4ba0`, 108,957,306 B (**+25,906**) |
| `rootfs.img` | `78325844…9901` | `fabf7ecf…e368` |
| verity data blocks | 21,898 | 21,905 |
| `cmdline.txt` | `3712287a…687c` | `f6dd75f8…6368` |
| launch measurement | `697bbdcd…186e` | `81dbfc38…add9` |

`tunneld`, `agent-probe`, the kernel, the firmware, the initrd, `/etc/hosts`,
`/srv/index.html` and every applet are identical. The workload disk is the same
file, not a rebuild. So the two runs differ in the adapter's own binary and in
nothing else a guest executes.

The seven review fixes are visible in the console in exactly one way — the
resolver's log line now quotes the name, and the two source lines moved:

```
run 1   tunnel_dns.go:190] tunnel dns: q=web.peer-b  type=A answer=100.64.1.0     tunnel.go:381
run 2   tunnel_dns.go:193] tunnel dns: q="web.peer-b" type=A answer=100.64.1.0    tunnel.go:400
```

Nothing else in either guest's transcript reads differently, which is what
"the boundary behaviour is unchanged" looks like from outside.

## The pass table

All 52. Grouped as the runbook groups them.

| group | criterion | A | B |
|---|---|---|---|
| the right run | booted the measured image and ran the packaged tunneld | PASS | PASS |
| | no writable path in the image is executable | PASS | PASS |
| | read the author key from inside the launch measurement | PASS | PASS |
| | read the set and chain from the config device | PASS | PASS |
| | the tunnel table put this guest on the adapter path | PASS | PASS |
| | **tunneld started before the workload, not after it** | PASS | PASS |
| | runsc launched with the adapter's two flags | PASS | PASS |
| | httpd serving on its own loopback, and init fetched its own page | PASS | PASS |
| | powered off at the end rather than being stopped | PASS | PASS |
| | no writable executable path was ever found | PASS | PASS |
| attested | acquired its own evidence from the platform | PASS | PASS |
| | bundled the chain provisioned on its config device | PASS | PASS |
| | is listening | PASS | PASS |
| | **the sandbox socket came up for the adapter's helper to dial** | PASS | PASS |
| | tunneld handed the socket to another process and stopped answering itself | PASS | PASS |
| | the exit attached, holding the list its config device carries | PASS | PASS |
| | admitted its peer's evidence / refused nobody | PASS | PASS |
| **the two hops** | **A's sandbox was served B's page, through B's exit** | **PASS** | |
| | **B's sandbox was served A's page, through A's exit** | | **PASS** |
| | the exit served a stream a peer opened and dialed its one permitted destination | PASS | PASS |
| | an exit recorded the attested identity of the peer whose stream it served | PASS (both) | |
| | the fetching process was inside a gVisor sandbox | PASS | PASS |
| **the controls** | the name in nobody's table did not resolve | PASS | PASS |
| | the peer name in the *other* guest's table did not resolve | PASS | PASS |
| the segment | the exchange went through the relay | PASS | |
| | the relay could not find the page's text on the wire | PASS | |
| | no guest looked for a gateway or anything off the segment | PASS | |

### The two hops, in the guests' own words

```
A:611  tunnel dns: q="web.peer-b" type=A answer=100.64.1.0
A:612  tunnel dns: q="web.peer-b" type=AAAA answer=noerror-empty
A:613  tunnel attach: web.peer-b:80 -> peer "guest-b": ok in 109.085389ms, host fd 40, local 100.64.0.1:40001
A:586  served-by: guest-b
A:587  workload: wget exit 0 for web.peer-b

B:613  tunnel dns: q="web.peer-a" type=A answer=100.64.1.0
B:615  tunnel attach: web.peer-a:80 -> peer "guest-a": ok in 44.277268ms, host fd 40, local 100.64.0.1:40001
B:592  served-by: guest-a
B:593  workload: wget exit 0 for web.peer-a
```

and the far end of each, with the identity it was serving — **this time both
guests kept all three of the exit's lines**, where run 1 lost two of guest B's to
a contended serial console:

```
B:572  EXIT accepted a stream from peer="guest-a" vendor=amd-sev-snp
       measurement=81dbfc38…add9 policy_digest=197d4aae…b973
B:573  EXIT dialed web.peer-b:80 -> 127.0.0.1:80
B:574  EXIT web.peer-b:80 ended
A:594  EXIT accepted a stream from peer="guest-b" … measurement=81dbfc38…add9 policy_digest=197d4aae…b973
A:595  EXIT dialed web.peer-a:80 -> 127.0.0.1:80
A:596  EXIT web.peer-a:80 ended
```

The measurement in those lines is the number predicted offline for this image.

### The four controls

```
A:614  tunnel dns: q="web.peer-a"               type=A answer=nxdomain
A:616  tunnel dns: q="not-in-the-table.example" type=A answer=nxdomain
B:611  tunnel dns: q="web.peer-b"               type=A answer=nxdomain
B:616  tunnel dns: q="not-in-the-table.example" type=A answer=nxdomain
```

with `wget: bad address '…'` in the sandbox each time. `web.peer-a` resolves on B
and does not resolve on A, from one image, one workload disk and one page; the 64
bytes that differ are on a disk in no measurement, and the thing that enforced
them is in it.

### The segment

```
l2relay: RELAYED a_to_b_frames=49 b_to_a_frames=48 a_to_b_bytes=32116 b_to_a_bytes=31666
l2relay: MARKER not found hits=0 marker='served-by: guest-' in 97 frames carrying 63782 bytes
  ethertypes : IPv4=93, ARP=4   ip protocols: UDP=93   arp targets : 10.14.0.2, 10.14.0.3
```

Both pages crossed this segment and the machine copying every frame found neither.

## Timings, off init's own clock

| | A | B | run 1 A / B |
|---|---|---|---|
| `no writable path is executable` | 3.13 s | 3.31 s | 3.03 / 2.80 |
| tunneld up, ahead of the workload | 3.49 s | 3.79 s | 3.50 / 3.23 |
| sandbox socket up | 4.00 s | 4.29 s | 4.01 / 3.73 |
| exit serving, runsc started | 4.08 s | 4.38 s | 4.19 / 3.80 |
| workload exited 0 | 5.31 s | 5.52 s | 5.48 / 5.28 |
| **the sandbox** | **1.23 s** | **1.14 s** | 1.29 / 1.48 |
| attach | 109.1 ms | 44.3 ms | 52.8 / 128.8 |

Both numbers sit inside run 1's spread in both directions, so the 25,906 bytes
and the seven fixes cost nothing measurable here. Every fetch succeeded on its
first attempt; the retry loop never ran a second pass on either guest.

## What did not hold

**Nothing in this run.** 52 of 52, and the three things run 1 recorded under this
heading are all accounted for:

1. **The two over-specific assertions were fixed before this run, not after it**,
   and the fix is `exit_served` in `docs/snp/tunnel-on-two-guests.sh`: either of
   the two lines `serveConnect` writes after a successful `net.Dial` will do,
   because naming one of them asserts something about a serial port. Replayed
   against run 1's committed consoles it turns that run's two failures into
   passes, which is the correct verdict for run 1. **This run would have passed
   under the old assertions too** — both guests kept all three lines — so the
   change bought nothing here and is insurance for the next contended console.
2. **Console line loss did not recur.** It is a property of timing and not of the
   image; the general lesson from run 1 stands, which is that anything a future
   run must prove should be read out of a file and printed once, the way the
   sentry's debug log is.
3. **`tunneld: SANDBOX attached` still appears twice per guest** — the exit and
   the runsc tunnel helper are both clients of one socket. Unchanged, benign,
   still worth knowing.

Two things are true of this run that are not failures but should not be read past.
`--debug --debug-log=/run/runsc-debug/` is in the measured flag set and costs
about half a second of sandbox start, which is the price of the `tunnel dns:` and
`tunnel attach:` lines above being on the console at all. And no policy was
pushed, so the second client on the sandbox socket was never asked to answer one.
