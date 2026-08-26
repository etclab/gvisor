# Verifying evidence from real hardware

Milestone 1, ticket 05. The first point at which a report produced by a physical AMD
processor is checked against AMD's own root, outside the guest that produced it, against a
reference value set signed for that guest — with no network at any point. Until this, every
verification in this project had only ever seen evidence it minted itself.

It is the consumer half of what `docs/evidence-acquisition.md` (ticket 04) produces, decided
by ADR-0002, ADR-0003, ADR-0004, ADR-0005 and ADR-0006; vocabulary is `CONTEXT.md`. The code
is `attest` and `attest/verify`, driven by `attest/cmd/verify-evidence`; the harness is
`docs/snp/verify-on-hardware.sh` and its recorded run is
`docs/snp/evidence/ticket05/verify-run.txt`.

## Nothing here is new code

Everything this ticket needed already existed. `attest/tsm` acquires, `attest/provision`
loads the chain, `attest.LoadReferenceValueSetFile` loads the trust root, `attest/verify`
answers AMD's questions and `Verification.Verify` decides. What ticket 05 adds is a place to
stand outside the guest — `attest/cmd/verify-evidence`, which reads a bundle, loads a set,
asks for a verdict and exits 0 on acceptance and 2 on refusal — and the harness that puts
real bytes through it and records what came back.

That is deliberate. If the milestone had needed new verification code, it would have been
proving the new code rather than the design.

## What was proven, and in what order

The order matters more than the list, because it is what makes the acceptance mean
something.

**1. The measurement was predicted before the guest was asked anything.** A reference value
learned by asking the platform is not a prediction and cannot fail
(`docs/snp-measurement-prediction.md`). AMD's `sev-snp-measure` 0.0.13 computed the stock
guest's launch measurement from the firmware image and the two launch parameters that are
not files — 4 vCPUs, `EPYC-v4` — with no guest, no `/dev/sev` and no report in reach:

```
84aaf62f431f0a943944e10b0569c7c899bf5e9cfd0c6176af3f70033e241ac1e9d807f5605fd7dd08bf1bf1f09b5da5
```

The stock guest of ticket 01 runs `OvmfPkgX64` without `kernel-hashes`, so **M** covers the
firmware image and one VMSA per vCPU and nothing else (`docs/snp-host-stack.md`). That is
exactly what makes it the right guest here and the wrong one for ticket 08: the measurement
is genuine and predictable, and it attests nothing about a workload.

**2. The set was authored and signed from that prediction**, together with a second set
differing from it in one byte of the measurement and in nothing else — same floor, same
policy, same author, signed by the same key, so the loader accepts both and the only thing
that can account for a different verdict is the measurement.

**3. A live confidential guest produced the evidence**, bound to an Ed25519 key generated a
moment earlier, bundled with the chain provisioned on its config device. The chain that came
back is `docs/snp/evidence/certificate-chain.bin` byte for byte.

**4. The verdicts were taken in an empty network namespace.** One `unshare -rn`, in which
the same shell first failed to resolve `kdsintf.amd.com`, failed to open a socket to it, and
failed to reach it over HTTPS — and which had no interface up at all, not even loopback.

| Presented | Verdict |
|---|---|
| evidence, provisioned chain, the authored set | **accepted** |
| evidence, provisioned chain, the set with one measurement byte changed | refused: launch measurement not in the reference value set |
| evidence, no chain | refused: evidence does not chain to the vendor root — *no certificate chain presented with the evidence* |
| evidence, a genuinely stale chain | refused: evidence does not chain to the vendor root — *report signature verification error* |
| evidence, provisioned chain, the authored set, again | **accepted** |

The last row is not a formality. A refusal test that would also pass with the whole path
broken is not evidence, so every refusal above is bracketed by the same evidence being
accepted on the same wiring.

**5. The provisioned chain, removed and staled, fails closed at the acquirer too** — which
is where it should be caught, before a peer ever sees it:

```
acquire-evidence: provision: certificate chain refused: reading .../certificate-chain.json:
no such file or directory; no certificate chain is provisioned here — provision one, do not
fetch (ADR-0005)

acquire-evidence: provision: certificate chain refused: the provisioned chain was issued for
TCB bootloader=9 tee=0 snp=23 microcode=71 but this platform reports TCB bootloader=9 tee=0
snp=23 microcode=72: the chain is stale, which peers would refuse as malformed evidence;
re-provision the chain after any TCB update (ADR-0005)
```

**6. The refusals are the code's, not the namespace's.** Every refusal above was produced
with the vendor unreachable, so in principle a refusal could have been a failed fetch rather
than a decision. The two chain cases were therefore repeated on the host's ordinary network,
with AMD answering `HTTP 200` one round trip away, and produced the same refusals with the
same exit status. The structural guards behind that are `attest/verify`'s `offlineGetter`,
which refuses every URL so that a re-enabled fetch fails loudly, and `attest/tsm`'s import
allowlist test, which fails if a fetch is ever written into the acquirer.

## The stale chain is real, and it was fetched on purpose

A chain goes stale when the platform's TCB moves and nobody re-provisions. That cannot be
staged by editing a file: the metadata is checked against the VCEK's own extensions, so a
doctored metadata file is caught as two provisioning runs mixed, not as staleness. The
harness therefore asks AMD's key distribution service for a VCEK for **this same chip at
microcode 71**, one level below what the platform now reports, and rebuilds the certificate
table around it with the ASK and ARK untouched. The result is exactly the artifact a host
has after a firmware update it did not re-provision for: real, AMD-signed, and for a level
this platform has moved off.

That fetch is a provisioning-time operation by construction — the same public service ticket
15 provisions from, asked about a chip whose identity it already knows. Verification never
reaches it. That is the whole point.

## What this run corrected

**A stale chain does not surface as malformed evidence.** ADR-0005,
`docs/provisioning-certificate-chain.md` and the comment in `attest/verify/snp.go` all say
it does, on the reasoning that the verification library compares the reported TCB against
the one the chain was issued for. On real silicon that comparison never runs.

AMD derives the VCEK from the chip secret **and** the TCB, so a chain for another TCB
endorses a *different key*, not the same key with a different number written on it:

```
provisioned (microcode 72)  VCEK public key sha256 6f6da88d1b3f0fa91b01f6747026fa7afad26cc55d80e47750862257bfd5e293
stale       (microcode 71)  VCEK public key sha256 5887430b44eb7195933037cd4b82f5c8e9a913214063b735163584cdb9523d27
```

The report's own ECDSA signature therefore fails under the stale chain, and the verdict is
`ReasonChainNotRooted` — decided in `checkAuthentic`, before the coherence pass that would
have called it malformed ever runs.

Nothing about this is unsafe: the refusal is closed, nothing is fetched, and a stale chain is
never mistaken for a good one. What is wrong is the operator-facing story. Three things say
to look for "malformed evidence" about a healthy platform, and an operator will not find it;
and `ReasonChainNotRooted`'s detail — unlike the malformed one's — does not name ADR-0005,
so it points at a forged report rather than at re-provisioning. The places that would have to
change are ADR-0005's *Consequences*, the *stale-chain symptom* section of
`docs/provisioning-certificate-chain.md`, the table in `docs/evidence-acquisition.md`, the
comment above the coherence pass in `attest/verify/snp.go`, and the sentence
`provision.CheckFor` prints. They are left alone here, because the first of them is an ADR.

The local check is unaffected and is where a stale chain is actually caught: `LoadFor` refuses
it before the acquirer will produce a bundle at all, naming ADR-0005 and the remedy.

## Running it

Needs the running stock guest of `docs/snp-host-stack.md`, reachable through `$STACK/gssh`,
and no root on the host — the guest's own `sudo` does the one privileged thing, since
`inblob` is root-only, and the network namespace is an unprivileged user namespace.

```sh
docs/snp/verify-on-hardware.sh [-capture docs/snp/evidence/ticket05]
```

It exits 0 only if every assertion held, prints each `PASS`/`FAIL` with what it checked, and
writes the whole transcript to `$WORK/verify-run.txt`. `-capture` copies the artifacts into
the repository.

To take a single verdict by hand:

```sh
export PATH=/usr/local/go/bin:$PATH
cd attest && go run ./cmd/verify-evidence \
  -bundle   /path/to/bundle \
  -refvals  /path/to/reference-values.json \
  -author   /path/to/author.pub
```

Exit 0 is acceptance, 2 a refusal, 3 a refused reference value set. `-vendor-root` and
`-product-line` substitute a root for a test signer; leaving them out uses the AMD roots
embedded in the verification library, which is the production path and reaches no network.

## What is checked without a guest

`attest/hardwareevidence_test.go` replays this run's artifacts on every `go test`: the
acceptance, the substituted-measurement refusal with its control, the missing-chain refusal
and the stale-chain refusal — against AMD's real root, with no hardware and no network. The
whole suite, that file included, passes inside `unshare -rn`.

Those tests are a regression guard, not the proof. What milestone 1 asserts is that a live
guest's evidence verifies outside it, and that needs a live guest; replaying captured bytes
cannot re-establish it. What the tests do is stop the conclusion rotting quietly — a change
that stopped accepting real silicon's evidence, or stopped refusing a substituted
measurement, is found on the next test run rather than the next time somebody books a
machine.

## What this does not establish

- **That changing a covered byte moves the measurement.** This guest's **M** covers only its
  firmware, and nothing was changed. Ticket 08.
- **Anything about the measured image.** The set here names a stock guest's firmware
  measurement, which attests nothing of interest about a workload. Ticket 07 predicts the
  measured image's; ticket 08 proves it is sensitive.
- **Two guests, or a tunnel.** No tunneld ran and no handshake happened; `verify-evidence`
  takes a bundle off the filesystem. Ticket 14.
- **Revocation.** The KDS CRL is not consulted, deliberately
  (`docs/provisioning-certificate-chain.md`, *Revocation is out of scope*).
- **Who authors reference value sets.** The author key here is a throwaway generated by the
  harness. Key custody and rotation are out of scope (`spec.md`, *Out of Scope*).
