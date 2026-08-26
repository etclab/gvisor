# Measurement sensitivity and refusal

Milestone 2, ticket 08. The point at which the measured image's integrity claim stops being an
argument and becomes a table: six confidential guests, six builds of the same image differing
by one byte each, six launch measurements predicted offline before any of them booted, and six
verdicts taken against the one reference value set signed for the unmodified build.

`docs/snp-measured-image.md` (ticket 06) asserts that changing a covered byte moves **M**.
`docs/snp-measurement-prediction.md` (ticket 07) gives the argument for why it must, and says
in as many words that demonstrating it is this ticket. Vocabulary is `CONTEXT.md`; the
decisions are ADR-0004, ADR-0005 and ADR-0006. The harness is
`docs/snp/image/sensitivity-on-hardware.sh` and its recorded run is
`docs/snp/image/evidence/ticket08/sensitivity-run.txt`.

---

## Result

| variant | what changed | M moved | its guest |
|---|---|---|---|
| `base` | nothing — the image as built | — | **accepted** |
| `none` | nothing, but `rootfs.img` and `initrd.img` regenerated from the same staging trees | no | **accepted** |
| `rootfs-file` | one hexadecimal character of `/etc/attested-tunnel/author.pub` | yes | refused: *launch measurement not in the reference value set* |
| `rootfs-byte` | one byte of `rootfs.img`, in the padding past the filesystem's own size | yes | refused: *launch measurement not in the reference value set* |
| `initrd` | one byte of a **comment** in the initrd's `/init` | yes | refused: *launch measurement not in the reference value set* |
| `cmdline` | one **trailing space** on the kernel command line | yes | refused: *launch measurement not in the reference value set* |

Every measurement in the third column was computed by AMD's `sev-snp-measure` from files on
disk, written to `predicted-measurement.txt`, and only then was a guest booted. Every guest
reported exactly the measurement predicted for it. That is what makes this a demonstration
rather than a readback: there was an independent expectation to be wrong about.

```
base         16c37b84895e01c363fa2b0844d98d44340cf524c49017e15a0511126b89e3ef225b169f29351026230d65e19657883b
none         16c37b84895e01c363fa2b0844d98d44340cf524c49017e15a0511126b89e3ef225b169f29351026230d65e19657883b
rootfs-file  b3d63753de71d184a5c13efb7fe9a334debb44c4df9fa1da0cde8b7c927b43cdf37255102505521cc79f85ba5d0a54f1
rootfs-byte  218777e1b7d96f05ce288ce1b6de2e5b81b725792960c6b047b57196ca5dc640d82ad0a654633f788945de527a72100d
initrd       43213f81f1a9b592d9281c51848d732165090a32ab11f1881c46dfcd171271d088ccf6519ea381a81d07d88f73f32bbf
cmdline      62ad80bfb3ec63c6be5ab95a42b32ea7a4c2918c6d018c808919e5160e5c0d667b5c68b015d4a53bf3d8d939a551b86a
```

Four mutations, four different measurements. Not one shared "changed" value: the digest tracks
*which* byte changed, not merely that something did.

---

## The root filesystem is not hashed into the firmware, and saying otherwise misleads

This is the part a reader will get wrong if it is not stated plainly, and ticket 01's stack got
an adjacent thing wrong badly enough that `docs/snp-measured-image.md` had to correct it.

The hashes table QEMU writes into the measured firmware page holds SHA-256 of exactly three
things: the kernel, the initrd, and the command line. **`rootfs.img` is not one of them.** No
digest of the root filesystem appears anywhere in the launch measurement, and an operator who
goes looking for one will not find it and may conclude the root filesystem is not covered.

It is covered, transitively:

```
a byte of rootfs.img
  -> the dm-verity root hash over rootfs.img
  -> verity.roothash= on the kernel command line
  -> SHA-256 of the command line, in the hashes table
  -> the firmware page the table is written into
  -> M
```

The run shows each link rather than asserting it. For both rootfs mutations the harness prints
the two command lines side by side:

```
base         … rdinit=/init verity.roothash=0a39885f42df7f8ab2996be4e64047105489a162e5d842ac966236d8cb794f3b verity.salt=- …
rootfs-file  … rdinit=/init verity.roothash=6a1ce69ef2ee70c6f98521d9b2973e560f285874884b9a4eaa0a8a8721464cd9 verity.salt=- …
```

60 characters differ, all of them inside `verity.roothash=`, and the harness asserts it: strike
the root hash out of both command lines and what remains is identical. The command line's
SHA-256 goes from `a01ce3ff…` to `08005ac7…`, and that hash is what the firmware page carries.

Two consequences worth holding on to. First, the root filesystem is covered **only** because
the verity parameters are on the command line and the command line has no superblock to fall
back on — ticket 06's `--no-superblock` decision is what makes this work, not a detail of
packaging. Second, a mutation of the root filesystem and a mutation of the command line are
not independent phenomena down at the digest: the first is a special case of the second. They
are listed separately because they are separate things an attacker does, not because they take
separate paths into **M**.

---

## dm-verity catches none of this

An aside with consequences, because it is the reason the launch measurement is load-bearing
rather than belt-and-braces.

Ticket 06 recorded that flipping one byte of `rootfs.img` panics the guest:
`data block 200 is corrupted` → `dm-verity device corrupted`. That was a byte flipped *under a
root hash that was left alone*. An attacker who changes the root filesystem does not leave the
root hash alone. They re-derive the hash tree and put the new root hash on the command line —
which is exactly what every rootfs variant here does — and the image is then internally
consistent. dm-verity has nothing to complain about, and does not:

```
$ launch-measured-guest.sh -no-snp -image …/rootfs-byte
initrd: dm-verity mapping /dev/dm-0 active (panic_on_corruption)
initrd: root filesystem mounted read-only
init: running /usr/bin/tunneld
```

A modified root filesystem, mounting cleanly, with `panic_on_corruption` armed and silent. The
only thing that sees the change is the launch measurement, because the root hash itself is
measured.

The harness also boots a variant with the byte in a place the guest reads — inside a compressed
block rather than in the tail padding — to show that even there it is squashfs that objects and
not verity:

```
initrd: dm-verity mapping /dev/dm-0 active (panic_on_corruption)
initrd: root filesystem mounted read-only
SQUASHFS error: zstd decompression error: 70
SQUASHFS error: Failed to read block 0xcde9: -5
Kernel panic - not syncing: Attempted to kill init!
```

dm-verity is silent in both. It secures the root filesystem against a change made underneath a
fixed root hash; it cannot secure the root hash. Both of those variants were also predicted
offline, and both measurements moved.

---

## What was proven, and in what order

The order is what makes the acceptance mean anything.

**1. The baseline was built from pinned inputs and its measurement predicted offline.**
`build-image.sh` with ticket 01's pinned firmware and kernel, then `predict-measurement.sh` —
`sev-snp-measure` 0.0.13 over the four measured files plus the two launch parameters that are
not files — then `emit-refvals`, which signs that prediction into `reference-values.json` with
the reference value author's key. No platform, no `/dev/sev`, no report anywhere in that path.
Every verdict below is taken against that one set.

**2. Five variants were produced, and the mutator was controlled first.** `none` regenerates
`rootfs.img` and `initrd.img` from the same staging trees with nothing changed, and the harness
asserts all five measured files come back byte-identical and the prediction is the baseline's.
Without that, any difference below could have been the mutation tool's doing. Each mutation is
then a single byte, and the harness asserts that every file it did not target is byte-identical
to the baseline's — the mutations are isolated, or they prove nothing.

| variant | the byte | what it costs downstream |
|---|---|---|
| `rootfs-file` | 1 of the 65 bytes of `author.pub` | 15265 of 3571712 bytes of the squashfs data (zstd recompresses the block, metadata moves), 60 characters of the command line |
| `rootfs-byte` | 1 of 3571712 bytes of `rootfs.img`, at offset `0x367fff` | exactly 1 byte in the data region; 58 characters of the command line |
| `initrd` | 1 of the 3074 bytes of `/init`, in a comment | 1 byte of the 3119104-byte cpio archive; gzip then diverges from that byte on |
| `cmdline` | 1 byte appended | the measured string goes from 192 to 193 bytes |

**3. Every variant was booted as a confidential guest**, under the image's own
`OvmfPkg/AmdSev/AmdSevX64` firmware with `kernel-hashes=on`. That flag is not optional
scaffolding: without it QEMU never writes the hashes table, the kernel, initrd and command line
are not in **M** at all, and three of the four rows above would read *identical*. The QEMU
command line of every boot is recorded; `policy=0x30000,cbitpos=51,reduced-phys-bits=6,kernel-hashes=on`.

**4. Each guest reported the measurement predicted for it.** Six for six, exactly.

**5. The verdicts were taken outside the guests, in an empty network namespace**, by
`attest/cmd/verify-evidence` against the baseline's signed set and the AMD roots embedded in the
verification library. Accepted for `base` and `none`; refused for all four mutants with

```
REFUSED
  reason            : launch measurement not in the reference value set
  operator log      : verification refused: launch measurement not in the reference value set:
                      launch measurement matches none of the 1 reference values in the set
  a caller learns   : attest: verification failed
```

**6. The control was taken again after every refusal**, and the unmodified image was still
accepted. A refusal test that would also pass with the whole path broken is not evidence.

---

## What makes the refusals attributable

Only one thing differs between the accepted guest and each refused one, and the run is arranged
so that nothing else could be responsible.

- **The same reference value set** decides every verdict — the baseline's, signed once by the
  author key, never re-emitted per variant. So no verdict can be an artefact of a differently
  authored set.
- **The same config device** is attached to every boot: the provisioned certificate chain, the
  peer table, the baseline's set and its signature. It is outside the launch measurement by
  design (ADR-0004, ADR-0005), and using one device for all six boots makes that concrete —
  four guests were refused while carrying, on a device the verifier can see, the very set that
  admits the fifth.
- **The same chain**, provisioned for this chip at `bootloader=9 tee=0 snp=23 microcode=72`,
  came back in all six bundles, so no refusal is a chain problem. Every refusal names the
  measurement and nothing else.
- **The vendor is unreachable** while the verdicts are taken. Ticket 05 established that this is
  a property of the code; holding to it here costs nothing.

---

## The guest binary

The measured image has no shell, no writable storage that outlives the guest and no network, so
the only way a bundle leaves it is the serial console. `docs/snp/image/report-evidence/` is a
small Go program embedded as `/usr/bin/tunneld` in the six images this ticket boots and in
nothing else — ticket 08's analogue of ticket 07's `crosscheck-report.c`, and built for the
same reason. It acquires evidence exactly as `cmd/acquire-evidence` does (`attest/tsm`, the
chain from `/config`, a key generated a moment earlier and dropped at power-off), prints the
bundle base64-encoded between marker lines, and exits.

**It verifies nothing.** It does not read `reference-values.json`, it does not look at
`/etc/attested-tunnel/author.pub`, and it has no opinion about the measurement it is carrying.
A guest judging its own evidence would be judging a measurement it could not have influenced
anyway, and would prove nothing about the design. The verdict is taken on the host.

Setting `TUNNELD` is the one thing that differs between the baseline image here and the
canonical one at `$STACK/image`, and it is the parameter ticket 06 provided for exactly this.
Nothing in the default build path was changed, and `mutate-image.sh` is called by this harness
and by nothing else.

---

## Running it

The build, the mutations, the predictions and the verdicts need no privilege and no hardware.
Launching an SNP guest opens `/dev/sev` and needs root; that is the only step that does.

```sh
docs/snp/image/sensitivity-on-hardware.sh [-capture docs/snp/image/evidence/ticket08]
```

It exits 0 only if every assertion held, prints each `PASS`/`FAIL` with what it checked, and
writes the whole transcript to `$WORK/sensitivity-run.txt`. `-root-mode` says how to reach root:
`sudo` prompts, `spool` drops the job in `$STACK/root-spool` for ticket 01's `root-runner.sh`
(the operator starts it once and types the password once), `direct` assumes the shell is already
root, and the default picks among them.

`-no-boots` stops after everything that needs neither privilege nor silicon. That half runs in
about ten seconds and establishes that every mutation moves the measurement. It does not
establish that a guest booted from a mutated image is refused, which is the other half.

A rebuild reproduces all six predictions bit for bit — the six values above came out of a fresh
`-no-boots` run on the same host after the boots were done, which is what "rebuildable and
auditable" is for. So the measurements the six guests reported can be recomputed from source by
anyone with the pinned inputs, on any machine, with nothing confidential running.

The mutator is usable on its own:

```sh
docs/snp/image/mutate-image.sh -base IMAGE -out OUT -mutation rootfs-byte [-offset N]
```

---

## What is checked without a guest

`attest/measurementsensitivity_test.go` replays this run's artifacts on every `go test`: each
guest's report against AMD's real root, each reported measurement against the prediction written
before that guest booted, and each verdict against the baseline's signed set — with no hardware
and no network.

Those tests are a regression guard, not the proof. What milestone 2 asserts is that a *real
platform* reports a different measurement when a covered byte changes, and replaying captured
bytes cannot re-establish that. What the tests do is stop the conclusion rotting: a change that
stopped refusing a guest whose measurement is not in the set is found on the next test run
rather than the next time somebody books a machine.

---

## What this does not establish

- **That every covered byte moves M — only that these four do.** The claim is a property of
  SHA-384 over the launch digest chain, and no finite number of mutations proves it. What these
  four do is falsify the practical alternatives: that the measurement covers only the firmware
  (ticket 01's stack, where it did), that it is taken over something semantic that ignores
  padding and comments, or that the root filesystem is outside it.
- **The boundary from the other side.** That changing something on the config device does *not*
  move **M** is ADR-0004's design and ticket 06's record; nothing here re-tests it. The same
  device was attached to all six boots, so this run holds it fixed rather than varying it.
- **That `sev-snp-measure` is correct.** It is AMD's tool, pinned at 0.0.13, cross-checked once
  in ticket 07 against a booted guest. Six more agreements between its predictions and real
  reports are recorded here, which is a stronger check than ticket 07's single one, but the tool
  and the platform could in principle share a wrong model of the same computation.
- **Two guests, or a tunnel.** No tunneld ran, no handshake happened, and the control here is
  that verification accepts the unmodified image — not that anything talks to anything.
  Ticket 14.
- **That the refusal is what a peer would do.** `verify-evidence` asks for the verdict a
  tunneld would ask for, from the same code, but a peer also has a handshake to abort and a
  connection to drop. Ticket 14.
