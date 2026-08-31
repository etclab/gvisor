# Intel TDX as a second hardware vendor: a feasibility study

**There is no TDX verifier in this branch and this study did not write one.** It is four probes
against Google Cloud's TDX offering, six throwaway VMs that lived a combined hour, and a reading
of this tree against Intel's requirements — done to answer whether TDX gives this design
something SEV-SNP on a provider structurally cannot, what a second vendor would cost, and
whether it is worth doing. The answer to the first is **yes, and more than expected**; to the
third, **not yet, and the thing that would change it is one day of offline work rather than a
verifier**.

Start with what was *not* established, because three of these bound every claim below.

- **No TDX evidence was verified.** Nothing here checked a quote's signature, chained one to
  Intel's root, or fetched a byte of Intel collateral. Every cost figure below is a reading of
  code and specification against recorded bytes, not a run. The quotes in
  `docs/snp/evidence/tdx/` are authentic in the sense that the platform produced them; nothing
  here proves they are authentic in the sense a verifier means.
- **Every RTMR value here was read off a booted guest.** `refvals.go` says a launch measurement
  "is a prediction computed offline from the image build inputs, not a value read off a booted
  guest — a measurement learned by asking the machine is not a prediction, and a check built on
  one cannot fail." Not one number in this document satisfies that. **This is the single largest
  gap and the recommendation turns on it.**
- **This is GCE's firmware, not Intel TDX.** Every behavioural finding is a property of Google's
  virtual firmware, their `c3` machine type and Ubuntu's boot chain on 2026-08-31. A different
  provider, or the same provider next quarter, may measure differently. The register *model* is
  Intel's and was checked against Intel's specification; the register *contents* are Google's.
- **No hostile guest was tried.** The mutations here were an honest operator changing their own
  machine. Whether an attacker can reach an honest guest's RTMR2 by a different route — the
  question that decides whether RTMR2 is a security control or a checksum — was not attempted.
- **No image was built, no reference value authored, no tunnel established.** The measured-image
  half of the design was not ported and nothing dialled anything.

## The four probes, and what they changed

`docs/snp/cloud/tdx/probe-tdx.sh` and its two companions took these from six `c3-standard-4` TDX
instances in `us-central1-a`, deleted as they finished (`docs/snp/cloud/tdx/RESOURCES.md`). The
shape is `probe-platform.sh`'s from the cross-network run, with Intel's five measurement
registers where AMD has one.

**1. Something in a TDX quote tracks the guest's disk, and SEV-SNP there has no equivalent.**
Two TDX VMs, one from Ubuntu 24.04 and one from 22.04, identical in every other respect:

| register | across two images | what it is |
|---|---|---|
| MRTD | **same**, `c1ee9c16…70a5` | built when the domain is built: Google's firmware |
| RTMR0 | different | firmware configuration |
| RTMR1 | different | the EFI boot chain |
| RTMR2 | different | grub, the kernel, the command line, the initrd |
| RTMR3 | same, all zero | never extended on this provider |

The SEV-SNP probe found Google's launch measurement byte-identical across exactly this pair of
images, which left the measured-image half of the design nowhere to live. MRTD reproduces that
result exactly — and Google publishes a signed launch endorsement for this MRTD at
`gs://gce_tcb_integrity/ovmf_x64_csm/tdx/<MRTD>.binarypb` (5,308 bytes, chaining to
`GCE-cc-tcb-root`, saved in `evidence/tdx/endorsement/`), which is the same statement from the
same direction: *this is a measurement of our firmware*. **The difference is that TDX has four
more registers, and three of them moved.**

**2. The acquisition half of the vendor seam works on Intel, unmodified.** `attest/tsm`'s package
comment claims the same four steps "yield an SEV-SNP report on AMD and TDX evidence on Intel."
Nobody had run it. In a stock GCP TDX guest, with no module loading:
`/sys/kernel/config/tsm/report` exists, `provider` reads **`tdx_guest`**, `outblob` returns
**8,000 bytes** that parse as a **v4 quote with `tee_type 0x81`**, the generation counter records
exactly one write, and the 64 caller-supplied bytes come back verbatim in `REPORTDATA` — the same
width as SEV-SNP's `REPORT_DATA`, so `CallerSuppliedBytesSize` needs no thought. `attest/cmd/
acquire-evidence`, built and run on the guest, refuses exactly where `seam.go` says it will:

```
tsm: the report interface is provided by "tdx_guest", which this acquirer does not implement;
a second vendor adds a case here and an implementation of attest.Verifier, and touches nothing else
```

That sentence is half right, and the half that is wrong is below.

One difference matters. On AMD at this provider `auxblob` held 4,763 bytes of VCEK, ASK and ARK.
On TDX **the attribute is absent entirely**, which is a different fact from "empty" and a
different fact again from the one ADR-0005 rests on.

**3. Exactly one register is usable, and only a control revealed which.** One disk, four boots,
each mutation asserted to have taken effect *before* its reboot
(`evidence/tdx/mutate/mutate.txt`):

| register | plain reboot, nothing changed | kernel command line | initrd |
|---|---|---|---|
| MRTD | same | same | same |
| RTMR0 | same | same | same |
| RTMR1 | **different** | different | different |
| **RTMR2** | **same** | **different** | **different** |
| RTMR3 | same | same | same |

**RTMR2 is the register.** It held still across a reboot that changed nothing, and moved
independently for a kernel command line change and for an initrd change. It is also reproducible
across machines: a guest with the marker file in its initrd produced byte-identical RTMR2
(`0375c957…`) on two different VM instances in two different runs.

**RTMR1 is not usable, and nothing but the control would have shown it.** It takes one value on a
VM's first boot ever (`02c7f19c…`) and a second, stable value on every boot after
(`3a446943…` — identical across all three later boots). It is not noise, but it is a function of
boot history rather than of the disk, so no author could write it into a reference value. The
first attempt at this probe had no plain-reboot control and reported RTMR1's movement as an
initrd effect; see "What this study got wrong" below.

**4. An RTMR is interpretable, not merely comparable.** This is the probe that changes what the
answer means. A bare RTMR is a 48-byte hash chain: you cannot say what produced it and you cannot
predict it, so its only use is comparison against another observation. The mechanism that lifts
that is the Confidential Computing Event Log, and on this provider it is **present, readable, and
exact**: `/sys/firmware/acpi/tables/data/CCEL` holds 112 records, and replaying every SHA-384
digest into its register reproduces **all four RTMRs bit-for-bit** (`evidence/tdx/eventlog/`).

```
register replayed == quote    quote value
rtmr0    YES                  c0b8b19ca6f51dc37435da45a61ab417…
rtmr1    YES                  02c7f19c862b3dae1592c737358d9bb1…
rtmr2    YES                  ecc9935861eba8e47817c10761468525…
rtmr3    YES                  0000000000000000000000000000000…
THE EVENT LOG REPLAYS TO THE QUOTE.
```

The log is untrusted input — it comes from the attester — and that is fine, because replaying it
against the RTMR in the signed quote is what authenticates it. 86 of the 112 records extend
RTMR2, and they are legible: `grub_cmd: linux /vmlinuz-6.17.0-1022-gcp root=PARTUUID=…`,
`kernel_cmdline: …`, `/vmlinuz-6.17.0-1022-gcp`, `(hd0,gpt16)/grub/grub.cfg`. So a verifier
holding the log can say *which components* produced RTMR2 and check them one at a time, rather
than matching one opaque digest.

## What TDX gives this design that SEV-SNP on a provider cannot

Precisely this: **on a provider-booted SEV-SNP VM there is one measurement register and it
contains the provider's firmware, so no statement about the workload is expressible at all. On a
provider-booted TDX VM there is a register that contains the guest's kernel, command line and
initrd, and an event log that says what went into it.** The cross-network run had to admit its
cloud peer by admitting "some two-vCPU SEV-SNP VM booted by Google's firmware," and recorded that
a mixed federation collapses to the weakest member's granularity. With RTMR2 that collapse is not
forced. That is a real structural difference and it is the reason this study did not stop at
probe 1.

It is also narrower than it first looks. RTMR2 covers what grub loaded and told the kernel; it
does not cover the root filesystem, so a guest that boots the same kernel and initrd and then
runs a different binary from disk measures the same. The design's own measured image on this host
covers the binary, because the binary is *inside* the launch measurement. TDX on a provider buys
back the boot chain, not the workload.

## What a second vendor would cost

Two claims are under test: the spec's "a second hardware vendor is a day's work rather than a
refactor" (line 150) and `seam.go`'s "touches nothing else in this package". **Both are false, and
the seam is still doing real work.** Below the seam and at the transport, the design is genuinely
vendor-neutral. The damage is concentrated in three types in one file, and it reaches the signed
trust root.

### What holds

`attest/ratls` carries `Vendor` as a string and `Bytes`/`Chain` as opaque — no change.
`Verification.Verify` reads only `Claims.CallerSuppliedBytes` and never touches a measurement or
a TCB — no change. Every refusal reason in `refusal.go` is vendor-neutral in wording and a TDX
verifier can reuse the taxonomy unchanged. `attest/verify/tdx.go` would be new code mirroring
`snp.go`, which is expected and is what the seam exists for.

One caveat on that last row, because ADR-0003 chose `go-sev-guest` partly on maturity. Its Intel
counterpart `google/go-tdx-guest` is a **new dependency this project does not currently have** —
not in `attest/go.mod`, not in the root `go.mod` — and it is pre-1.0 (v0.3.x) and carries the
"not an officially supported Google product" disclaimer. ADR-0003's reasoning ("hand-rolling this
would mean owning ASN.1 and AMD's certificate semantics inside the security boundary the whole
design rests on") applies with equal force to Intel's PCK and PCS semantics, so the library is
still the right call — but the argument that made it comfortable for AMD is weaker here, and a
second vendor inherits that risk.

### `ReferenceValue.LaunchMeasurement []byte` — cannot express TDX evidence

The field's own comment says its width is "deliberately checked nowhere" so that a vendor's digest
does not sit above the seam. That was the right instinct and it is not enough, because the problem
is not width but **arity and selectivity**.

- Naming only MRTD is type-compatible and worthless: probe 1 showed MRTD is byte-identical across
  images, so such a reference value admits any TDX VM Google boots. That is the SEV-SNP weakness
  this study set out to escape.
- Concatenating MRTD ‖ RTMR0-3 into 240 bytes loses which register is which, and — this is the
  empirical part — **does not work**. It forces an all-or-nothing match on five registers when
  RTMR1 changes between a VM's first boot and its second and RTMR3 is always zero. Every peer
  would be refused after its first reboot. A reference value has to say *match RTMR2, ignore
  RTMR1*, and a single opaque blob has no way to say "ignore".

So the type must change: a vendor discriminator plus named registers, or a map. **And it is not
only a Go type.** `refvalsfile.go` carries `launch_measurement` as a hex *string* in the signed
document that is this design's trust root, governed by ADR-0004 and ADR-0006. Changing it is a
format version bump on the artifact every peer's admission depends on — the one thing in the
design most expensive to change and most deserving of review.

### `TCB` — does not survive contact with Intel

`TCB` is four `uint8`s named `Bootloader`, `TEE`, `SNP`, `Microcode`: AMD's structure, sitting
above the seam, and mirrored field-for-field in `wireTCB`, where all four are **required** and a
missing `minimum_tcb` is a load error. Intel's TCB is a different object: a 16-byte `TEE_TCB_SVN`,
the SEAM module's own measurement (`MRSEAM`/`MRSIGNERSEAM` — observed `ab62561a…`), and a TCB
*level* resolved by looking the platform's FMSPC up in a signed, dated, revocable `TCBInfo`
document from Intel's PCS carrying a `tcbEvaluationDataNumber`. The shared concept — "at or above
a floor" — survives; the representation does not. A TDX reference value author has nothing to put
in `bootloader`, `snp` or `microcode`, and writing zeros means "no floor", which `wireTCB`'s own
comment calls the failure it exists to prevent. `TCB`, `wireTCB` and the loader's requirement all
change, and so do the two places that print AMD's field names
(`cmd/verify-evidence/main.go:243`, `cmd/tunneld/watch.go:98`).

`GuestPolicy` is not in the brief and is in the same position. Its fields are SNP policy bits;
Intel's counterpart is `TD_ATTRIBUTES` and `XFAM` (observed `0000001000000000` and
`e702060000000000`). Only `AllowDebug` has a counterpart. `wirePolicy` changes too.

### `attest/tsm` — more than "a case here"

The acquirer's own extension points are real but incomplete. `vendorOf` (`tsm.go:475`) and
`confirmEcho` (`tsm.go:406`) are designed switches and behave as advertised. These are not:

- `vendorProvider` (`tsm.go:388`) returns `""` for any non-AMD vendor, so the provider check at
  `tsm.go:315` fails on every `Acquire`.
- `Options.prepare` (`tsm.go:204`) *requires* a `ChainDir`, and `Acquire` calls
  `provision.LoadFor(ChainDir, evidence)` **unconditionally** (`tsm.go:370`), which parses the
  evidence as an SEV-SNP report. On TDX this fails after a perfectly good quote has been read. The
  chain step has to become vendor-conditional.
- `Observation.ChainTCB` is an `attest.TCB`, and `Observation.String` announces an empty
  certificate table "which is the expected state on this host" — a sentence already wrong on
  Google's SEV-SNP VMs and wronger on TDX, where the attribute does not exist.
- `importgraph_test.go`'s allowlist fails the moment a TDX parser is imported. That is the guard
  working as designed, but it is a file a second vendor touches.

### ADR-0005 — its premise and its mechanism both change

ADR-0005 is shaped end to end by how AMD distributes keys: a per-chip, per-TCB VCEK chain, fetched
once from KDS and provisioned onto the config device. Intel's model differs in both halves.

- **There is no per-chip chain to provision.** The PCK certificate chain is carried *inside the
  quote*, in its signature data. The artifact ADR-0005 provisions has no Intel analogue.
- **But verification needs something the quote does not carry**: `TCBInfo`, QE Identity and CRLs
  from Intel's PCS, per-FMSPC, dated and revocable. Intel's terms of use prohibit fetching this at
  runtime; caching it (the PCCS) is mandatory rather than an optimisation.

So ADR-0005's *spirit* — do not call the vendor on the critical path — is not merely preserved
under TDX, it is required by Intel. Its *mechanism* is replaced. And its failure mode inverts: an
AMD chain goes stale when the platform's TCB moves, which the design detects by comparing the
chain's TCB to the report's; Intel collateral goes stale **on a calendar**, independent of the
platform, and a TCB recovery event obsoletes it for reasons no local comparison can see.
`provision.Chain` (chip ID + TCB) cannot represent that. This is a new ADR, not an amendment.

### The honest total

Not a day. A working estimate, assuming `go-tdx-guest` carries the cryptography:

| | |
|---|---|
| new `verify/tdx.go` | ~1–2 days, the expected cost, and the part the seam genuinely earns |
| `tsm` acquisition changes | ~half a day, four edits beyond the two designed switches |
| `ReferenceValue`, `TCB`, `GuestPolicy` + their wire types + loader | **~3–5 days, and it changes the signed trust root's format** |
| collateral provisioning and refresh, replacing ADR-0005 | ~1 week, mostly operational design rather than code |
| offline prediction of RTMR2 | **unknown, and unsupported by the provider — see below** |

The first two are a second vendor behind a seam. The third is a refactor of the trust root. The
fourth is a new decision. The fifth is the one that decides whether any of it is worth starting.

## The gap that decides it

The design's requirement is not "a measurement that changes when the workload changes." It is a
measurement **predicted offline from build inputs**, because a value learned by asking the machine
cannot fail a check. RTMR2 satisfies the first and, today, not the second.

The event log makes prediction *conceivable* — 86 legible records — but nobody publishes the
answer. `google/gce-tcb-verifier` issue #73 asks exactly this question ("how to obtain reference
values for RTMR[0] and RTMR[1] for a given GCE OS image") and is open and unanswered; Google
documents how to get MRTD from the firmware and says nothing about RTMRs. Predicting RTMR2 from a
disk image means reproducing grub's execution order — and the log shows grub measuring its own
control flow, including `save_env recordfail` and `save_env initrdfail`, which write back to disk.
It held still across our reboot; whether it holds across a failed boot, a kernel upgrade or an
`update-grub` is untested.

**On a provider-booted VM you control neither the firmware nor grub, so this is a
reverse-engineering commitment against a moving target with no vendor support.**

## Recommendation

**No — do not build a TDX verifier now.** Two reasons, in order of weight.

1. **The prediction property is unestablished, and without it the second vendor buys a weaker
   version of what this project already has.** Admitting a peer on an RTMR2 read off a booted
   machine is the trust-on-first-use the design was built to avoid; `refvals.go` says so in the
   field's own comment. Until RTMR2 can be computed from build inputs, a TDX federation is
   "whatever that VM happened to boot", which is better than SEV-SNP's "whatever Google boots" but
   is not the design's claim.
2. **The cost lands on the trust root, not on the seam.** A second vendor was supposed to be
   additive. It is additive for acquisition, transport and verification — and it is a format
   change to the signed reference value set, plus a replacement for ADR-0005. That is worth doing
   deliberately, once, for a reason; it is not worth doing to find out whether it was worth doing.

**Do this instead, and it is about a day.** Take the CCEL already recorded in
`docs/snp/evidence/tdx/eventlog/ccel.bin` and the quote beside it, and try to recompute RTMR2's
86 digests from a mounted copy of the same Ubuntu image *without booting it*. No cloud, no
verifier, no new types — the bytes are already on disk in this branch. That experiment answers the
one question the recommendation turns on.

**What would change the answer.** Any one of these flips it toward building:

- RTMR2 proves predictable offline from a disk image, and stable across `update-grub` and a
  kernel upgrade. This is the big one, and the experiment above settles it.
- Google (or Intel) starts publishing RTMR reference values per image — watch issue #73.
- The project needs a peer on hardware it does not own *and* cannot ask to run a measured image.
  That is the scenario TDX is uniquely good for, and it is not today's scenario.
- The trust root's format is being revised anyway for some other reason, at which point the
  expensive third row above becomes nearly free and the calculus changes.

Conversely, if the offline prediction experiment fails, the answer hardens to a clear **no**, and
the finding worth keeping is the negative one: *provider-booted confidential VMs do not give this
design a measured image on either vendor — SEV-SNP because there is no register, TDX because
there is no prediction.*

## What this study got wrong, and what that is worth

The first mutation run (`evidence/tdx/probes-run1/`) is kept because the way it misleads is the
useful part.

**`sudo systemctl reboot` followed by `sleep 25` is not a reboot barrier.** One sample was taken
from the boot *before* the reboot it was labelled with — its quote's measurement fields are
byte-identical to the baseline's, differing only in the signature — and the ssh carrying the
second mutation landed while the machine was going down, so its output was lost. The run appeared
to show an initrd change moving RTMR1 and RTMR2. The rewrite waits for
`/proc/sys/kernel/random/boot_id` to change and asserts each mutation took effect before
rebooting.

**A mutation probe without a null control is not an experiment.** Run 1 had no plain reboot, and
RTMR1 moves across one. Everything run 1 attributed to the initrd, RTMR1 would have done on its
own.

**Run 1's first mutation never happened at all, and said nothing.** Editing
`/etc/default/grub` does nothing on a GCE Ubuntu image, because
`/etc/default/grub.d/50-cloudimg-settings.cfg` overrides `GRUB_CMDLINE_LINUX_DEFAULT` afterwards.
`/proc/cmdline` was identical across all three boots and proved it. "The command line moved no
register" was a null result from a change that was never applied — which is why the rewrite
asserts the marker is in `grub.cfg` and, after the reboot, in `/proc/cmdline`.

**The replay tool's first register mapping was wrong,** and it failed loudly rather than quietly,
which is the only reason it was caught. Reading the event log's first field as a TPM PCR index put
two registers' events into one; RTMR0 still replayed and RTMR1 and RTMR2 did not. The field is the
TDX `MrIndex` (0 = MRTD, 1–4 = RTMR0–3). Both wrong and corrected runs are kept
(`eventlog-wrongmap/` and `eventlog/`).

## What this does not establish

- **That any TDX quote here is authentic.** No signature was checked. See the top of this
  document.
- **That RTMR2 can be predicted.** The central gap, and the recommendation's hinge.
- **That RTMR2 is a security control.** No adversarial attempt was made to reach an honest
  guest's RTMR2 by another route. A measurement that only an honest operator can move is not yet
  a control.
- **What moved RTMR1 between first boot and later boots.** Observed four times, cause not
  isolated. It does not matter for the recommendation — the register is unusable either way — but
  it is unexplained.
- **Anything about TDX outside GCE.** No bare-metal Intel part, no second provider, one machine
  type, one zone, one day.
- **Anything about the root filesystem.** RTMR2 covers grub's loads. A different binary on the
  same kernel and initrd measures the same, so the criterion the measured image satisfies here
  (criterion 6 — a modified image refused) is *not* recovered by RTMR2.
- **Any cost figure above, as a measurement.** They are estimates from reading, and the estimator
  did not write the code.
- **The latency, handshake and federation behaviour of a mixed AMD/Intel deployment.** Untouched.

## Running it

```sh
docs/snp/cloud/tdx/probe-tdx.sh            # probes 1 and 2: two images, two VMs, deleted in minutes
docs/snp/cloud/tdx/probe-tdx-mutate.sh     # probe 3: one disk, four boots, with the controls
docs/snp/cloud/tdx/probe-tdx-eventlog.sh   # probe 4: CCEL present, and does it replay
```

TDX needs `gcloud beta`: the GA `--confidential-compute-type` in SDK 493 accepts only `SEV` and
`SEV_SNP`. The machine type is `c3-standard-4` (`n2d` is AMD-only and cannot boot a TD), the disk
must be `pd-balanced`, and `us-central1-a` serves both TDX and the SEV-SNP work's `n2d`, so one
zone covers both vendors. Recorded evidence is under `docs/snp/evidence/tdx/`; the inventory of
everything created and deleted is `docs/snp/cloud/tdx/RESOURCES.md`.
