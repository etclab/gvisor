# A TDX verifier beside the SNP one

Ticket 17. A second implementation of the `attest.Verifier` seam, for Intel TDX quotes from
Google Cloud VMs, verified entirely offline against the quotes already recorded on this branch,
and the trust-root format change that lets one signed reference-value set name peers on either
vendor. This is ticket 02 for TDX: a verifier that refuses fakes for the right reasons before any
tunnel uses it. Builds on `docs/tdx-rtmr2-prediction.md` (ticket 16), which made RTMR2 a
predicted value, and on `docs/tdx-as-a-second-vendor.md`, whose costing of this work turned out
to be right. No guest-side code, no live run, no policy hash; those are tickets 19 and 18.

**In one sentence:** `attest/verify/tdx.go` accepts all eight recorded boots of
`ubuntu-2404-noble-amd64-v20260826` against Intel's real collateral and a reference value whose
RTMR2 came from ticket 16's prediction, refuses each of them against every other boot's
prediction, and reaches every reason in the refusal taxonomy on a re-signed copy of a recorded
quote — with nothing under `attest/tsm/`, `attest/tunneld/`, `pkg/` or `runsc/` changed.

---

## What was built

**The verifier.** `verify.NewTDX(verify.TDXOptions{CollateralDir, VendorRootPEM, Now})`
implements `attest.Verifier` for `attest.VendorIntelTDX`. Its checks run in this order, and the
first failure is the verdict:

1. Vendor and presence, as the SNP verifier does them.
2. Parse (`ReasonMalformedEvidence`).
3. Load Intel's collateral for the quote's FMSPC and certificate authority from the directory —
   never from the network; a missing file refuses with a detail naming ADR-0005, and the getter
   handed to the library refuses every URL it was not provisioned for.
4. Judge the collateral's own dates against the injected clock. Collateral past its `nextUpdate`
   refuses as `ReasonChainNotRooted` with a detail that says the peer may be fine, the
   verifier's own provisioning has lapsed, and names ADR-0007. The same reason an expired AMD
   certificate already gets, for the same fact: the chain cannot be judged rooted *now*.
5. The library's gate: `go-tdx-guest` walks the PCK chain embedded in the quote to Intel's root,
   checks the quote's and the quoting enclave's signatures, verifies the TCB info's and enclave
   identity's signatures and revocation lists, matches FMSPC, PCEID, the TDX module's signer and
   attributes, and requires Intel's status to be UpToDate. Any failure is `ReasonChainNotRooted`.
6. Claims are read only now: MRTD, RTMR0–3, TD attributes, report data, and the TCB status and
   evaluation number, the last two recomputed by Intel's published matching algorithm on the
   TCB info the library has just verified, because the library resolves the status only to
   refuse and does not report it.
7. Per reference value of this vendor: MRTD, RTMR0 and RTMR1 must each be in the value's
   observed list and RTMR2 must equal the predicted one (`ReasonMeasurementNotInSet`, the detail
   naming the register); status at or above the floor and evaluation number at or above the
   floor (`ReasonTCBBelowFloor`); TD_ATTRIBUTES.DEBUG clear unless permitted
   (`ReasonPolicyMismatch`). Any one value admits, and a value that matched on registers but
   refused for another reason outranks the generic answer, as in `snp.go`.

The user-data binding is untouched and is checked where it always was, above the seam in
`Verification.Verify`, for both vendors.

**Dispatch.** `attest.Dispatch(snp, tdx)` is a `Verifier` that routes on the evidence's vendor
and refuses an unknown one as `ReasonUnsupportedVendor`. `Verification` did not change: it calls
one verifier, and the dispatcher is one. `tunneld` and `verify-evidence` build the TDX verifier
when `-tdx-collateral-dir` is given and dispatch both; without it a tunneld admits no TDX peer.

**Collateral on the config device** (`verify/tdxcollateral.go`, ADR-0007). A directory of raw
HTTP bodies and raw response headers, exactly as `curl -D` writes them, with names fixed by what
they answer for:

```
tcbinfo-<fmspc>.body  tcbinfo-<fmspc>.headers     fmspc: 12 lowercase hex digits
qeidentity.body       qeidentity.headers
pckcrl-<ca>.body      pckcrl-<ca>.headers         ca: platform | processor
rootcrl.body          rootcrl.headers
```

The headers matter: Intel puts the issuer chains in them, and the library reads them from
there. `docs/snp/evidence/tdx/collateral/` is that directory for the recorded platform, fetched
once on 2026-09-08 (`FETCH.txt` is the transcript, `collateral.txt` what it says); every test
uses it and nothing else. The FMSPC and CA come from the peer's certificate and are
shape-checked before they become a path.

**Format version 2 of the signed reference-value set** (`refvalsfile.go`, ADR-0006 addendum).
Every entry carries `"vendor"`. AMD entries keep their three fields unchanged. A TDX entry:

```json
{ "vendor": "intel-tdx",
  "observed_mrtd":  ["c1ee9c16…70a5"],
  "observed_rtmr0": ["c0b8b19c…896d"],
  "observed_rtmr1": ["02c7f19c…913b", "3a446943…d691"],
  "predicted_rtmr2": "ecc99358…11df9",
  "td_attributes_policy": { "allow_debug": false },
  "minimum_tcb": { "status": "UpToDate", "tcb_evaluation_data_number": 20 } }
```

The names say what each value is. The three *observed* registers are the provider's — the
firmware Google boots, its configuration, its boot chain — pinned as constants seen on real
hardware, each a list because RTMR1 has two values on every Google VM on record: one on the
first boot, before the root partition is grown, and another on every boot after. A list means
"any of these" and never "ignore". The *predicted* one is the image's, from
`predict-rtmr2.py`. Version 1 documents are refused with a message saying they carry no vendor
tag and must be re-emitted and re-signed; the loader does not read them as AMD, because a
reader that fills in what a document did not say is the failure ADR-0002 names. `emit-refvals`
now writes version 2 for AMD, and `docs/snp/cloud/tdx/emit-tdx-refvals` writes it for TDX from a
predicted RTMR2 and the observed constants; the set it emitted for the recorded image is in
`docs/snp/evidence/tdx/refvals/`. Ticket 14's recorded evidence was not regenerated: the two
tests that read its version-1 document re-author it in-process under a test key and say so.

**The fake** (`attest/tdxfake`). A TDX quote is too heavy to mint from nothing, so the fake
re-signs a recorded one: it generates an Intel-shaped chain (root, PCK Platform CA, a PCK leaf
carrying the recorded certificate's SGX extensions, a TCB signing certificate), lets a test
change any body field, rebuilds the quoting-enclave report over a fresh attestation key, signs
report and quote under the test chain, and mints matching collateral — the real TCB info and
enclave identity re-signed by the test key, with the status, evaluation number and dates the
test asks for. Like `snpfake`, it is excluded from the packaged binary by the import guard.

---

## What the fakes proved

Every reason in the taxonomy, each reached by a mutation of a recorded quote or of the
collateral it is judged against (`attest/tdxevidence_test.go`):

| mutation | reason |
|---|---|
| no bytes | `NoEvidence` |
| SEV-SNP evidence to the TDX verifier; TDX evidence through a dispatcher that knows only AMD | `UnsupportedVendor` |
| the quote truncated | `MalformedEvidence` |
| one byte of a recorded quote's TD report flipped | `ChainNotRooted` |
| a fake under another fake's root; a recorded quote judged against a fake root; a fake judged against Intel's | `ChainNotRooted` |
| collateral signed by a stranger | `ChainNotRooted` |
| collateral that calls the platform OutOfDate | `ChainNotRooted` — Intel's gate, see below |
| the collateral file missing | `ChainNotRooted`, detail names ADR-0005, and no fetch is attempted |
| the real quote and the real collateral, three months later | `ChainNotRooted`, detail names ADR-0007 |
| MRTD, RTMR0 or RTMR1 changed; RTMR1 outside the observed list | `MeasurementNotInSet`, detail names the register |
| RTMR2 of a different recorded boot | `MeasurementNotInSet` |
| collateral from evaluation number 19 against a floor of 20 | `TCBBelowFloor` |
| TD_ATTRIBUTES.DEBUG set | `PolicyMismatch` |
| a recorded quote presented with any key | `BindingMismatch` (the recordings are over `00..3f`) |

## What the recorded boots proved

All eight quotes — probe 4 runs 1 and 2, the mutate control reboot, and the five boots of the
ticket-16 probes — are accepted at a clock inside the collateral's validity against a set holding
that boot's predicted RTMR2 (read out of `predict/predict-*.txt` at test time, never out of a
quote), the observed MRTD and RTMR0, both RTMR1 values, and a floor of UpToDate at evaluation
number 20. Each is refused with `MeasurementNotInSet` against every other boot's prediction
(36 pairs), which is the update-grub and kernel-upgrade "different image" case the ticket asked
for, and also the recordfail case. A mixed set with one AMD value and one TDX value admits TDX
evidence through the dispatcher.

## What the library's shape decided

Three behaviours of `go-tdx-guest` at the pinned commit are recorded in ADR-0003's amendment and
shaped the code:

- **Intel's gate is UpToDate-only, and it runs first.** The reference value's floor accepts
  `SWHardeningNeeded`, as the 2026-09-08 decision asked, but a platform at that status is refused
  at step 5 as `ChainNotRooted` before the floor is consulted; a test asserts this so the
  limitation cannot be forgotten. The floor still does work today through the evaluation number,
  which is what stops a host provisioning pre-recovery collateral, and will do its status work
  after a library bump that exposes the status. The recorded platform is UpToDate, so nothing on
  this branch is affected.
- **Every library failure is one flat error**, wrapped with `%v`, so nothing is classified by
  matching its text. The verifier classifies by *where* it asked — the local date check before
  the gate, the gate itself, and its own register and floor comparisons after — which is why
  expiry is judged locally first.
- **The library resolves the TCB status only to refuse it**, so the ~40-line matching algorithm
  is reimplemented on the verified TCB info to fill the claims, with the library's file and
  lines cited beside it.

---

## What a verifier on real hardware may assume

- **Reference values are predicted, not enrolled**, for the register that names the image.
  RTMR2 for a Google TDX VM is `predict-rtmr2.py`'s output and nothing else goes in that field.
- **The provider's three registers are observed constants.** For Google's current stack:
  MRTD `c1ee9c16…70a5`, RTMR0 `c0b8b19c…896d`, RTMR1 `02c7f19c…913b` on a first boot and
  `3a446943…d691` after. A live VM that does not match them is either a changed provider boot
  stack or not the provider's; a verifier cannot tell which, and refuses.
- **The collateral directory above is what the config device must carry**, for FMSPC
  `00806f050000` and CA `platform` on the hardware Google has used for every quote on record,
  and it is valid until 2026-10-08. After that date every TDX peer is refused until it is
  re-provisioned; before a TCB recovery is honoured the reference value's evaluation-number
  floor must be raised.
- **Intel's root** is the one embedded in the library unless `-tdx-root` says otherwise.

## What this does not establish

- **That a live tunnel can be built on it.** The acquirer has two SEV-SNP-only shortcuts
  (`attest/tsm/tsm.go:370` loads an AMD chain unconditionally; `:388` returns no provider name
  for any other vendor), left for ticket 19 as the ticket directs.
- **The policy hash in user data** as this verifier saw it when it was written. Ticket 18 has since
  made the binding version 2 and added the per-entry `policy_digest`, above the seam and without
  touching `verify/tdx.go`: the recorded quotes are still judged by the same code, and a peer
  presenting a policy is tested against the fake TDX platform, because a recording's report data is
  fixed and cannot be bound to a policy chosen afterwards.
- **RTMR0 and RTMR1 as predictions.** They are pinned, not derived; `gce-tcb-verifier` issue #73
  is still where that question lives.
- **Behaviour on a SWHardeningNeeded platform**, until the library is bumped.

## Running it

```sh
export PATH=$PATH:/usr/local/go/bin
cd attest && GOPROXY=off go test ./... -count=1

# a recorded quote against the recorded collateral and a signed version-3 set
# (the recorded reference-values.v20260826.json is version 2 and no longer loads;
#  re-emit it with an egress section — docs/snp/cloud/tdx/emit-tdx-refvals)
go run ./cmd/verify-evidence -vendor intel-tdx \
    -evidence ../docs/snp/evidence/tdx/eventlog/quote.bin \
    -tdx-collateral-dir ../docs/snp/evidence/tdx/collateral \
    -refvals reference-values.json -author <author.pub> -key <peer key> -now 2026-09-09T00:00:00Z
# the recordings are over caller-supplied bytes 00..3f, so this stops at the binding check, as it must
```
