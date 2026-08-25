# Provisioning the certificate chain

Ticket 15. How the VCEK certificate chain for a host's chip gets onto the config device, why it
has to, and what goes wrong when it is out of date. The decision is ADR-0005; vocabulary is
`CONTEXT.md`.

## Why this is a provisioning step at all

A peer verifying this platform's evidence needs the chain that signed it — the VCEK for this
chip at this TCB, and AMD's ASK and ARK above it. On this host the platform does not supply it:
`auxblob` is empty and no operator action fills it (`docs/snp-host-stack.md`, *The certificate
chain is absent*). The only other source is AMD's key distribution service (KDS), and fetching
from it at handshake time would put an outbound call to AMD on the critical path of every tunnel
and let AMD observe which chips are talking. So the chain is fetched **once, here, by the
operator**, validated, and delivered on the read-only config device beside the reference value
set. Nothing in a tunneld fetches it, ever; a tunneld that finds it missing or wrong refuses to
proceed and says so.

That is sound for the same reason the reference value set can travel on an untrusted device: the
chain is public, self-validating against the AMD root, and worthless to forge.

## The artifact

Two files, written into the config device's directory by `provision-chain`:

| File | What it is |
|---|---|
| `certificate-chain.bin` | VCEK, ASK and ARK in AMD's certificate table format — the same bytes `auxblob` would have carried. An acquirer puts these into `Evidence.Chain` verbatim. |
| `certificate-chain.json` | Which chip and TCB the chain was fetched for, so that staleness is detectable rather than inferred from a failure. |

```json
{
  "format": "gvisor.dev/gvisor/attest/certificate-chain",
  "version": 1,
  "vendor": "amd-sev-snp",
  "product_line": "Genoa",
  "chip_id": "9b371644…5243",
  "tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
  "fetched_at": "2026-08-25T15:04:05Z"
}
```

The metadata is not trusted on its own: a consumer checks that the chip and TCB it records are
the ones in the VCEK's own extensions, so a metadata file left behind from another provisioning
run cannot vouch for a chain it does not describe. The chain is not signed by the reference value
author; it is validated to AMD's root at every handshake, which is a stronger check than any
signature of ours.

## Procedure

Run on any machine with a copy of a report from the platform and access to `kdsintf.amd.com`.
It does not have to be the host: the fetch is keyed only by what the report says.

1. **Obtain a current report from the platform.** Any report will do — it is read for its
   `CHIP_ID`, `REPORTED_TCB` and CPUID family/model/stepping, nothing else. Ticket 01's procedure
   in `docs/snp-host-stack.md` reads one out of a confidential guest by hand; the captured one is
   `docs/snp/evidence/report.bin`. The report must be version 3 or later (it carries the CPUID
   that names the product line) and VCEK-signed, which is what this host produces.

2. **Fetch and validate.**

   ```sh
   export PATH=/usr/local/go/bin:$PATH
   cd attest
   go run ./cmd/provision-chain fetch -report /path/to/report.bin -out /path/to/config-device/
   ```

   This asks the KDS for exactly two things — the VCEK at
   `/vcek/v1/<product>/<chip_id>?blSPL=…&teeSPL=…&snpSPL=…&ucodeSPL=…` and the product's
   `cert_chain` — then hands the report and the fetched chain to the same verifier a peer uses
   (`attest/verify`) with the report's own measurement, TCB and policy as the reference value.
   Only a chain that makes this report verify against AMD's root is written. A bad fetch,
   a certificate for another chip, or a chain that does not root all fail **here**, with the
   verifier's refusal in the error, and nothing is written.

   AMD rate-limits the KDS to roughly one request per ten seconds per argument set; the tool
   retries with backoff for up to five minutes (`-timeout`).

3. **Check what was written**, against the same or a fresh report:

   ```sh
   go run ./cmd/provision-chain check -report /path/to/report.bin -dir /path/to/config-device/
   ```

   Exit 0 means the chain on the device is the one for this platform at its current TCB.

4. **Build the config device** with the two files beside the reference value set and its `.sig`
   and the peer table (ticket 06 defines the device; only the file names above are this
   procedure's).

5. **Record it.** For this host, the captured chain lives beside the captured report in
   `docs/snp/evidence/`, and `attest/provision`'s tests verify that pair against AMD's real root
   offline — so the fact that provisioning was done, and that its output verifies, is checked on
   every test run without touching the network.

## A TCB update requires re-provisioning

The chain is per chip **and per TCB**. Updating the platform's firmware or microcode changes
`REPORTED_TCB`, and the provisioned VCEK — issued for the old TCB — no longer matches. Repeat
steps 1–4 after any TCB update, with a report taken *after* the update. Treat it as part of the
update, in the same family as rolling out reference values: the platform is not back in service
until its chain is.

## The stale-chain symptom, and why it points the wrong way

Locally, a stale chain is caught before it is used: an acquirer loads the chain through
`provision.LoadFor` with the platform's current report, and a recorded TCB that differs from the
reported one is refused with

```
provision: certificate chain refused: the provisioned chain was issued for TCB bootloader=9 tee=0
snp=23 microcode=72 but this platform reports TCB bootloader=9 tee=0 snp=24 microcode=72: the
chain is stale, which peers would refuse as malformed evidence; re-provision the chain after any
TCB update (ADR-0005)
```

If a stale chain nonetheless reaches a handshake — an acquirer that skipped the check, or a chain
that went stale while a tunneld was already running — the failure appears **at the peer, not
here**. The verification library compares the report's TCB against the one the VCEK was issued
for and rejects the pair, and the peer logs it as `malformed evidence`, which is the confusing
direction: the platform is healthy, its evidence is genuine, and the operator reading the peer's
log is told the evidence is broken. That is why the verifier's refusal detail names ADR-0005
explicitly (`attest/verify`), and why an operator seeing `malformed evidence` about a platform
they know is fine should check that platform's chain first:

```sh
go run ./cmd/provision-chain check -report <fresh report from that platform> -dir <its config device>
```

There is no fallback. A tunneld or acquirer that cannot load a good chain does not fetch one — a
silent fetch would reinstate exactly the dependency ADR-0005 removes, invisibly — and the loader
(`provision.Load`) refuses a missing chain with an error that does not match `os.ErrNotExist`, so
that the "there is no chain here, carry on" branch cannot be written by accident.

## Status on this host

The chain for this host has **not** yet been captured. On 2026-08-25 (15:30–16:10 UTC)
`kdsintf.amd.com` (165.204.91.78/.79) was unreachable at the TCP level on 443 from four
independent vantages — this host, a GCP VM in us-central1, a GCP VM in europe-west1, and a
third-party fetcher — while `download.amd.com` and `kds-dev.amd.com` answered. That is an
AMD-side outage of the KDS, not a property of this host's network. The tool was run from the
GCP VM (`kds-fetch`, us-central1-a, project `nsf-2348130-428843`) with the static binary and
`report.bin` copied over `gcloud compute scp`; it failed exactly at the dial.

Everything up to the network call is exercised offline — `attest/provision`'s tests run the fetch
against a fake KDS, and drive ticket 01's real report through the tool to show it asks for
exactly `Genoa/9b3716…5243?blSPL=9&teeSPL=0&snpSPL=23&ucodeSPL=72`. When the KDS is back, step 2
with `-out docs/snp/evidence/` (from any machine that reaches it) completes the record and
un-skips `TestTheCapturedPlatformsProvisionedChainVerifiesItsReport`.
