# Ticket 26 on Google Cloud TDX: a measured sentry honouring a policy its peer pushed

Three boot pairs on `c3-standard-4` Confidential VMs in `us-central1-a`,
2026-09-18, branch `ticket-26-the-sandbox-honors-a-pushed-policy`. Six instances
in all, every one deleted inside the hour it was created; the ledger is
`../../../cloud/tdx/RESOURCES.md` and it is the authority on what existed.

| pair | created → deleted | result | what it settled |
|---|---|---|---|
| `boot-1/` | 21:06Z → 21:17Z | `44 passed, 28 failed` | both guests attested and reported the three-disk RTMR0; **no sandbox started** and **no peer was admitted**. Two harness faults, both fixed below |
| `boot-2/` | 23:25Z → 23:37Z | `69 passed, 5 failed` | the run the ticket's TDX item rests on: two sandboxes under pushed policies, the two hops, both controls, the narrowing, the teardown |
| `boot-3/` | 23:48Z → 23:59Z | `71 passed, 3 failed` | the same again with one assertion's wording corrected, and a second sample for RQ5 |

**The headline, and it is two answers read apart, as ticket 24 insisted.**

```
RTMR2 predicted from the image at 2026-09-18T20:45:30Z, before any instance existed:
    7f7c43153cab5dd6353922eec2fdd628d93f29aae4b6f862c025914e9671a513d76de26580e062a68a5a86d8af404aa1
RTMR2 the hardware reported, on all six guests of all three pairs:
    7f7c43153cab5dd6353922eec2fdd628d93f29aae4b6f862c025914e9671a513d76de26580e062a68a5a86d8af404aa1
```

**MATCH**, 25 records, and the prediction is in `predicted-rtmr2.txt` with its
timestamps. And the register ticket 24 could only observe:

```
RTMR0 reported by every guest of this three-disk shape:
    8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f
```

which is the value `RTMR0-DECISION.md` authored and the sets name, so **this is
the first run of this project whose guests are admitted on the shape they are**.
No script read it off a machine: `build-tdx-image.sh` passes the two values a
human typed, and the only thing this run does with a quote is judge it.

## What the hardware answers and what it does not

The compiled-in egress ceiling (`attest/ceiling/ceiling.nft`) permits **no TCP
egress at all** from a measured guest: the output chain rejects every TCP packet
with a reset before it reaches any accept, and the only things granted are
`udp/4433` on `eth0` and loopback. Nothing inside a measured guest can reach
`api.anthropic.com`, so the workload on hardware is the page fetch — ticket 25's
shape — and **not** a model call. The model-backed `agent-probe` run is proven on
loopback only (`../../ticket25/loopback/`, `../../ticket25/claude-smoke/`), where
the host's own network is underneath the adapter. The hardware answers *is the
policy enforced by a measured sentry, and can it be replaced under a live
workload*; the loopback answers *does a real agent complete a task through it*.
Neither answers the other's question, and a record that blurred them would be
claiming a TDX guest reached Anthropic. No API key exists anywhere in this run,
and no API money was spent on hardware.

The egress proof is on every console anyway, four attempts per guest with the
errno each time (`egress-{a,b}.txt`), so the ceiling is recorded as holding
rather than assumed.

## The registers, and the four verdicts

| register | what the set pins | what the hardware reported | |
|---|---|---|---|
| RTMR2 | `7f7c4315…04aa1` (predicted offline) | `7f7c4315…04aa1` | **equal**, six guests |
| MRTD | `c1ee9c16…70a5` | `c1ee9c16…70a5` | equal |
| RTMR1 | `02c7f19c…913b` (first boot) or `3a446943…d691` | `02c7f19c…913b` | equal, the first-boot value |
| RTMR0 | `c2fc12a5…850a` (two disks) **or** `8ee4fa36…b70a3f` (three) | `8ee4fa36…b70a3f` | **equal to the second**, which ticket 26 authored |

Four verdicts per pair, from this workstation, `attest-tool verify -vendor
intel-tdx` against the signed sets and the provisioned Intel collateral
(`verify-evidence-{a,b}.txt`):

```
guest A's quote against guest B's set   ACCEPTED   (the check that matters)
guest B's quote against guest A's set   ACCEPTED
guest A's quote against its own set     ACCEPTED
guest B's quote against its own set     ACCEPTED
```

and each guest said the same of itself on its own console:
`tunneld: SELFCHECK VERDICT ADMITTED: this platform satisfies this sandbox's own
reference value set`.

**This is a deviation from `RUNBOOK.md` §7 and it is the interesting one.** The
runbook expected both self-checks to be REFUSED on the policy digest, "which is
what mutual pinning means". That expectation is pre-ticket-22: since ticket 22 a
guest presents the sha256 over the **egress ceiling compiled into its own
tunneld** and not the digest of any document on any disk, and both guests boot
one image, so both present `197d4aae…b973`. `run-tdx-t26.sh` authored each set to
admit the *other guest's emitted policy document* instead, and boot pair 1 shows
exactly what that costs — on every dial, in both directions:

```
tunneld: PEER key=4c4d318b1b63e374… measurement=7f7c43153cab5dd6… vendor=intel-tdx
tunneld: REFUSED verification refused: guest policy or policy digest not permitted by
         the reference value: peer presents policy digest 197d4aae216ff9c2…b973
```

No tunnel, so nothing the scenario is about could happen. Both sets admit the
ceiling now, the self-check is admitted, and each guest admits the other. What
still makes the two guests two guests is the measurement pinning and guest B's
extra forward to a measurement nobody has built.

## Boot pair 1, and the two faults it found

1. **`open /config/tunnel-table.json: permission denied`.** The config device's
   inodes were not root-owned. `mkconfigdev-tdx.sh` did what
   `docs/snp/image/mkconfigdev.sh` used to do before ticket 25: `-E
   root_owner=0:0` sets the root directory and `-d` copies the builder's uid onto
   everything else. The tunnel table is read by `runsc run` inside the user
   namespace `unshare` makes, which maps one id, 0 to 0, and a capability over a
   file is only a capability when the file's owner is mapped
   (`capable_wrt_inode_uidgid`, `user_namespaces(7)`). So the guest booted,
   attested, and died here:

   ```
   running container: creating container: cannot create sandbox: cannot create sandbox
   process: starting the tunnel helper: opening the tunnel table
   "/config/tunnel-table.json": open /config/tunnel-table.json: permission denied
   ```

   The chown and the check that refuses a device without it are now in
   `mkconfigdev-tdx.sh`, copied from the SEV-SNP script paragraph for paragraph.
   The SEV-SNP runbook has had this in its "if something fails" table since
   2026-09-18; the TDX script had never been given the fix.
2. **The sets admitted a digest no guest presents**, above.

A third, smaller one, found by reading rather than booting: `write_side()`
declared `local g="$1" … d="$W/$g"` in one statement, and bash expands every word
of a `local` command *before* it assigns any of them, so `$g` was the outer one —
unset, and `set -u` ended the run at the first config device with `g: unbound
variable`. That attempt created nothing and is kept as
`boot-1/aborted-first-attempt.txt`. The dry run cannot catch it, because the dry
run does not write config devices.

## What the two good pairs showed

Quoting boot-3 unless noted; boot-2 says the same with different pids.

**The policy is in force, and it is the peer's.**

```
A  SANDBOX applied format=policy version=1 bytes=110 sha256=681331c69aedad34…b785d
B  SANDBOX applied format=policy version=1 bytes=110 sha256=b23887d06a044f07…81268
```

`681331c6…` is `sha256sum` of `../snp/config/b/push-policy.json` and
`b23887d0…` is `a/push-policy.json`'s: each guest's console carries the digest of
the document the **other** guest pushed. The same twelve unmeasured files drove
the SEV-SNP run, and the two digests are the same two numbers there.

**The two hops.** `served-by: guest-b` on A and `served-by: guest-a` on B, each
exit dialing the one destination its list permits, and `4.19.0-gvisor` on both —
the fetching process was inside a gVisor sandbox on a TDX guest whose RTMR2 was
predicted before it existed.

**The two controls.** `wget: bad address 'not-in-the-table.example'` on both is
`N`. `workload: EXEC REFUSED /bin/probe … Permission denied` on both is `X`, and
the line above it makes it a transition:

```
workload: exec /bin/probe attempt 0: it ran (rc=127); no policy carrying an x is in force in this sandbox yet
workload: EXEC REFUSED /bin/probe on attempt 2: /policy-probe.sh: line 150: /bin/probe: Permission denied
```

on all four guests of the two good pairs. The sentry's own reason string —
`exec refused: path="/bin/probe" sha256=75dfb7be…d00b9 reason=not-in-x` — is not
asserted on here, because there is no seccheck receiver inside a measured guest;
it is recorded on the workstation in `../adapter-check/notes.md`.

**The policy is replaced, under a workload that keeps running.**

```
B  initrd: narrow-after: 40s elapsed; starting a second tunneld to push /config/push-policy-narrow.json at the peer
A  SANDBOX applied format=policy version=1 bytes=76 sha256=92fb0e17644f61d4…7248e
A  workload: NARROWED web.peer-b stopped resolving on attempt 14: wget: bad address 'web.peer-b'
A  initrd: sentry: tunnel narrow: applied in 169.519µs, of which the table swap was 11.407µs
```

Guest A's console carries two applied digests and guest B's one. The stream that
was open across the narrowing carried two more mebibytes after it and then ended
**45 bytes short** of 8,388,608 (`LONG SHORT bytes=8388563`); boot-2 ended 3,903
bytes short. See "what did not hold".

**The policy is watched, and the workload's exit ends it.**

```
A  tunneld: SANDBOX liveness lost: it pulsed 92fb0e17…7248e, expected 681331c6…b785d
A  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live: …
A  initrd: kill-after: 150s elapsed; killing the sandbox, so that nothing inside it gets to say goodbye
A  initrd: kill-after: round 1, the sandbox in this table is unshare(379) /usr/bin/runsc(380) runsc-gofer(391) runsc-tunnel-helper(392) runsc-sandbox(400)
A  tunneld: SANDBOX liveness lost: the sandbox closed its socket
B  the same, after `kill-after: 210s elapsed`, and a refusal naming liveness
```

Both branches of the liveness rule, on hardware, on both guests. The five
processes the kill names are why it works at all: they are matched by argv[0] out
of `/proc/PID/cmdline`, because the sentry, the gofer and the tunnel helper are
re-execs of `/proc/self/exe` and every one of their `comm`s is `exe`. The SEV-SNP
run of this ticket is where that was diagnosed (`../snp/run-3/notes.md` printed the
table) and fixed (`../snp/run-4/notes.md`, the argv[0] match).

**And the mount that makes a sandbox possible here at all:**

```
initrd: workload device /dev/nvme0n3 found by the ext4 label, mounted at /workload (ro,exec,nosuid,nodev; not measured); it holds:
```

the one mount in the guest that permits exec, and the reason there is a third
disk and therefore a third RTMR0.

## Timings, off the initrd's own clock

| | boot-2 A | boot-2 B | boot-3 A | boot-3 B |
|---|---|---|---|---|
| sandbox socket up / workload launched | 2.68 / 2.74 s | — / 2.72 s | 2.46 / 2.51 s | — / 2.90 s |
| evidence acquired (`SELFCHECK acquired … in`) | 40 ms | 47 ms | 41 ms | 41 ms |
| establish (`LATENCY … kind=establish`) | — | 15.5 ms | — | 15.2 ms |
| the sentry taking a pushed policy | 176.7 µs | 200.3 µs | 169.5 µs | 195.2 µs |
| of which the table swap | 13.9 µs | 18.4 µs | 11.4 µs | 20.1 µs |
| narrow-after fired | — | 42.72 s | — | 42.91 s |
| kill-after fired | 152.75 s | 212.72 s | 152.51 s | 212.90 s |
| the sandbox's table is clear | 153.90 s | 213.86 s | 153.66 s | 214.05 s |
| teardown, bounded by those two | ≤ 1.15 s | ≤ 1.14 s | ≤ 1.15 s | ≤ 1.15 s |

`../rq5-tdx.md` is the same numbers arranged as the paper's six components.

## Two lines printed and not asserted

```
workload: OBSERVE exec /bin/uname (a symlink to busybox): rc=0 out='Linux workload 4.19.0-gvisor …'
workload: OBSERVE exec /bin/sh (a symlink to busybox): rc=0 out='ran'
```

on all four guests of the two good pairs, the same answer the SEV-SNP pair gave:
an `x` written as a path names the file an execve **resolved to**, not the name
it was given.

## What did not hold

1. **The long body arrives a few bytes short on this vendor, twice.**
   `LONG SHORT bytes=8384705` (boot-2) and `bytes=8388563` (boot-3) against
   8,388,608. It is **not** the stop condition the ticket names: the narrowing
   landed about twenty seconds and two mebibytes earlier and the stream went on
   carrying bytes across it, which is the property under test, and the far end
   kept serving (`EXIT accepted a stream … EXIT web.peer-b:80 ended` on B
   throughout). On the same pair guest B read the same 8,388,608-byte body in one
   go and got all of it (`LONG-B bytes=8388608`), and the same workload script on
   SEV-SNP completed three times out of three. So what is short is the tail of a
   slow read — `head -c 131072` a second apart through a QUIC stream and an exit
   — and the candidates are the reader's last partial read and the serving
   side's timeout, not `Policy.Narrow`. Recorded, not fixed.
2. **`initrd: EXIT status=` is not on either console, in any of the three
   pairs.** Compute Engine serves an empty body for a stopped instance; the
   watcher chases the tail for ninety seconds and then does one whole-buffer
   read, and the last lines are simply not retrievable. Tickets 19 and 24 record
   the same thing. Everything the run asserts on is above that line.
3. **Boot pair 2 failed two assertions on a word.** The console says
   `SELFCHECK VERDICT ADMITTED` and the check looked for `ACCEPTED`; the verdicts
   themselves were right and the workstation's four `attest-tool verify` runs
   agreed. Corrected in the runner before boot pair 3, which passes them.
4. **Serial console interleaving is worse here than on the bench.** Several lines
   in each console are three writers deep (`initrd: debug: D0918 23:27:13.98initrd:
   debug: 1initrd: debug: Dtunneld: SANDBOX liveness lost: …`), because init dumps
   the sentry's debug log while tunneld is still writing. Every line this run
   asserts on survived in all three pairs, but it is the same hazard ticket 25's
   run 1 recorded, and the lesson is unchanged: print what must be proved away
   from a flood.

## Provenance of the inputs

- **Collateral**: not refetched. `../../tdx/collateral/` was fetched
  2026-09-18T08:51:43Z and is valid until 2026-10-18T07:56:25Z; every boot of this
  run happened on 2026-09-18 in America/New_York (the last verdict at 23:58Z,
  19:58 EDT), which is the same calendar day, so the ticket's "fresh collateral
  the same day as any TDX run" is satisfied by the fetch already recorded.
  `tcbEvaluationDataNumber` is 20 and no reference value's floor moved.
- **Image**: built 2026-09-18T20:42:38Z → 20:45:31Z from the pinned base disk
  `d0b2b2c2…474f`, with `runsc` `6019cbf4…7819` (109,044,910 bytes, the binary
  this branch builds) inside the measured initrd. `manifest.txt` and
  `packaging.txt` are beside this file; `image-build.txt` is the whole build.
- **Author key**: `$STACK/image-ticket26-tdx/author.key`, generated for this
  ticket at 20:42:30Z; its public half `5660943e…b048a` is inside RTMR2 and is
  what signed all six documents the guests read.
- **Bundle**: `../snp/make-bundle.sh … -tdx`, byte for byte the SEV-SNP bundle on
  a one-gibibyte disk, `/bin/busybox dbac288c…6ac14` and `/bin/probe
  75dfb7be…d00b9`.
