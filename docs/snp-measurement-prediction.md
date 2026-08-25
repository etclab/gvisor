# Offline measurement prediction

Ticket 07. The expected launch measurement of the measured image, computed from the build
inputs alone before anything boots, and emitted by the build as the signed reference value
set. Builds on `docs/snp-measured-image.md` (ticket 06) and `docs/snp-host-stack.md`
(ticket 01, with its corrected account of what that stack measured); vocabulary is
`CONTEXT.md`; the artifact's format is ticket 03's (`attest/README.md`, ADR-0006).
Scripts are in `docs/snp/image/`.

---

## The rule this ticket exists for

**A measurement learned by asking the machine is not a prediction, and a reference value
built on one cannot fail.** If the reference value is whatever the platform last reported,
then verification tests only that the platform still reports it — a substituted firmware,
kernel or root filesystem is "expected" the moment it has booted once. Every value in
`reference-values.json` is therefore computed from files on disk plus two launch
parameters, by a tool that has no access to `/dev/sev`, no guest, and no way to be handed a
report.

Reading a measurement off a booted guest happens **exactly once**, in
`crosscheck-compare.sh`, and there it is *compared* with a prediction that was written to
disk before the guest existed. It is never written into a reference value. If the two ever
differ, the fix is to the model of the launch in `predict-measurement.sh` — a wrong vCPU
count, a wrong CPU model, a changed QEMU — and never to the reference value. Nothing in the
build reads `crosscheck.txt`, `console-snp.txt` or `report.bin`; the emitter (`emit-refvals`)
takes the measurement as a command-line argument and has no other way to obtain one.

Nobody should reintroduce the shortcut. The tell is any path from a report, a console log or
a `tsm/report` directory into `reference-values.json`. There is none, and a review that
finds one has found a regression.

---

## What is predicted, and how

For ticket 06's configuration — `OvmfPkg/AmdSev/AmdSevX64` firmware (BlobVerifierLibSevHashes)
launched with `kernel-hashes=on` — the SNP launch digest covers, in order:

1. **The firmware image**, 4 MiB, page by page, with the exceptions its own SEV metadata
   table declares (the secrets, CPUID and pre-validated pages are added with their page
   type, not their contents), and with **the hashes table written in**: QEMU fills the
   page the firmware advertises under GUID `7255371f-3a3b-4b04-927b-1da6efa8d454` with a
   `PaddedSevHashTable` holding SHA-256 of the kernel, of the initrd, and of the command line
   *including its terminating NUL* (`target/i386/sev.c`, `build_kernel_loader_hashes`), and
   `LAUNCH_UPDATE` measures the page with the table in it.
2. **One VMSA per vCPU**, the reset state of each vCPU as QEMU builds it — which is why the
   vCPU count and the `-cpu` model (its family/model/stepping signature sits in RDX at reset)
   are inputs even though they are not files.

The root filesystem enters through step 1: `verity.roothash=` is on the command line, the
command line's hash is in the table, the table is in the firmware page. Changing a byte of
`rootfs.img` changes the root hash, the command line, the table, the page, and **M**.
Disks, network, memory size and everything else on the QEMU command line are outside.

Not in ticket 01's stack: `OvmfPkgX64` links `BlobVerifierLibNull` and ticket 01 launched
without `kernel-hashes=on`, so there the table was never written and the kernel, initrd and
command line were not in **M** at all. A predictor for that firmware would silently cover
nothing but the firmware. The prediction here is for the image's firmware and only makes
sense with the image's launch script.

**Tool.** `sev-snp-measure` **0.0.13** (AMD's reference implementation of this computation,
`pip`), pinned by version and refused if another version is found, installed into a
virtualenv at `$STACK/sev-snp-measure-venv` — nothing system-wide. Invocation, from
`predict-measurement.sh`:

```
sev-snp-measure --mode snp --vmm-type QEMU --vcpus 4 --vcpu-type EPYC-v4 \
  --ovmf OVMF.fd --kernel vmlinuz --initrd initrd.img --append "$(cat cmdline.txt)"
```

`$(cat cmdline.txt)` drops the file's trailing newline, exactly as `launch-measured-guest.sh`
does, and the tool appends the NUL. Implementing the computation by hand was not chosen: the
value of a prediction is that it is independent of the machine, not that it is independent of
AMD's tool, and a second implementation of the PSP's digest chain is ticket 08's kind of
evidence if it is ever wanted. The tool's version is a modelling input and is recorded with
every prediction; bumping it means redoing the cross-check.

---

## What the build emits

`build-image.sh` now takes `AUTHOR_KEY` (the author's Ed25519 private key, PKCS#8 PEM)
instead of only the public key, and after writing the four measured files it:

1. runs `predict-measurement.sh` on them → `predicted-measurement.txt` (the measurement and
   the SHA-256 of every input, the command line verbatim, vCPU count, CPU model, tool
   version);
2. runs `emit-refvals` — a small Go program in `docs/snp/image/emit-refvals/` that calls
   `attest.MarshalReferenceValueSet` and `attest.SignReferenceValueSet`, so the document the
   build ships is rendered and signed by the same code that ticket 09's tunneld loads, then
   loads the two files back through `attest.LoadReferenceValueSetFile` with the public half
   of the key and fails the build if that refuses → `reference-values.json`,
   `reference-values.json.sig`;
3. writes `reference-values.inputs.txt`: the document's hash, the signing key, the policy
   and TCB floor chosen, and the whole of `predicted-measurement.txt`.

The reference value's fields other than the measurement are **authoring decisions**, taken
as build parameters and recorded: `POLICY` (default `0x30000`, the launch's own; the emitted
`guest_policy` permits exactly its bits — SMT allowed, debug, migration and single-socket
not) and `TCB_FLOOR` (default `9,0,23,72`, the level ticket 01 observed on this host; a floor
is a choice, and this default is the weakest one that admits this host). `VCPUS` and
`VCPU_TYPE` are measurement inputs and must equal what the launch script passes.

The author key for this deployment is `$STACK/image-inputs/author/reference-value-author.key`,
generated with `openssl genpkey -algorithm ed25519` on 2026-08-25 (its `README` says so);
public key `32ecdecef187bf48c7d7d3b0c61345d5fc85f8252a241f3f87c95bbfccf5947b`, which is the
line at `/etc/attested-tunnel/author.pub` in the image. It is not in git.

The canonical image at `$STACK/image` was rebuilt with it (placeholder tunneld, as ticket 06
left it). Its prediction: **`4835c9f3579e93ca787f1764ea32ecab0c7885efafd8718215d0b92a39eed27a3fa69f77b2e996a9aaa73d6997525db2`**.
The emitted set, its signature and its inputs are copied to `docs/snp/image/evidence/ticket07/`.

---

## The cross-check

The image has no shell and its `tunneld` is a placeholder that reports file presence, so a
guest that can hand its report back had to be built for the purpose: `crosscheck-report.c`,
static, embedded as `TUNNELD` in a second image at `$STACK/image-crosscheck`. It does what
ticket 01's by-hand procedure does — `mkdir` under `/sys/kernel/config/tsm/report`, one
64-byte write to `inblob`, read `outblob` — and prints the report as hex on the serial
console. Ticket 04's acquirer is not involved.

That image differs from the canonical one in exactly one root filesystem file, hence in the
root hash, the command line and **M**; its own prediction was written by its own build,
before any boot:

```
predicted: 448f0553567f49e22d4a776e92c9263d37c6b1223aa0926f6960f7fcaf5ed1d1e0d3e6e2f94bbd450f5728f9a7f66272
```

The boot needs root (`/dev/sev`) and was run once by the operator:

```bash
sudo bash docs/snp/image/launch-measured-guest.sh -image $STACK/image-crosscheck \
     -console $STACK/image-crosscheck/console-snp.txt
bash docs/snp/image/crosscheck-compare.sh $STACK/image-crosscheck
```

`crosscheck-compare.sh` recovers the report from the console, decodes it with
`docs/snp/parse-snp-report.py`, compares `MEASUREMENT` with `predicted-measurement.txt`, and
appends the verdict to `crosscheck.txt`. **Result: MATCH** (section below). If it had said MISMATCH, the candidates are, in order: `--vcpu-type` (QEMU's
`EPYC-v4` signature), `--guest-features` (QEMU 10.0 sets `SNPActive` only), and the VMSA
layout QEMU 10.0 hands KVM versus the one `sev-snp-measure` 0.0.13 models.

### Result

Prediction committed in `0189a4ab7` before the boot; boot on 2026-08-25, `crosscheck.txt`:

```
predicted (before boot, from build inputs): 448f0553567f49e22d4a776e92c9263d37c6b1223aa0926f6960f7fcaf5ed1d1e0d3e6e2f94bbd450f5728f9a7f66272
reported  (by the booted guest, once):      448f0553567f49e22d4a776e92c9263d37c6b1223aa0926f6960f7fcaf5ed1d1e0d3e6e2f94bbd450f5728f9a7f66272
RESULT: MATCH — the offline computation is validated
policy 0x30000, vmpl 0, reported_tcb bootloader=9 tee=0 snp=23 microcode=72
```

The guest reported `SEV: Status: SEV SEV-ES SEV-SNP`, `SNP running at VMPL0`, a 1184-byte
report, and powered off with status 0. Console, decoded report, QEMU command line and the
verdict are in `docs/snp/image/evidence/ticket07/crosscheck/`. The model — AmdSev firmware
with the hashes table, four `EPYC-v4` VMSAs, `guest_features=0x1`, `sev-snp-measure` 0.0.13
against QEMU 10.0 — is right for this stack, which is all this check establishes. The value
in `reference-values.json` for the canonical image remains the one its build computed; the
reported value above was compared and is not used anywhere.

---

## What this does not establish

- **That a covered byte moves the measurement.** The argument above says why it must; ticket
  08 demonstrates it.
- **That `sev-snp-measure` is correct.** It is AMD's tool, pinned; the cross-check is the one
  test of it here.
- **That the TCB floor is the right floor.** `9,0,23,72` admits this host and nothing older;
  a reference value author with a view on which firmware levels to refuse sets `TCB_FLOOR`.
- **The firmware's bytes still depend on the host's grub package** (ticket 06's finding);
  its hash is pinned in the build and recorded with every prediction, so a rebuilt firmware
  is a visibly different input rather than a silently different measurement.
