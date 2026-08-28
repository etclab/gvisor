# Attestation and transport across two confidential hosts

This is not the measured-image gate on two machines, and it should not be read as one. It is
this host's measured guest — the image whose launch measurement was predicted offline from
inputs under our control — dialing one confidential VM in Google Cloud that we did not build,
across a NAT and the public internet, through an attacker that carried every datagram. The
cloud peer boots Google's firmware from a disk Google's firmware does not measure, so its launch
measurement says which firmware ran and nothing about what ran after it; three of ticket 14's
eleven criteria (packaged into the measured image, checked before measuring, refused when
modified) are therefore absent for that peer and cannot be recovered on a provider-booted VM.
And because a reference value set is a list, the measured guest admits the cloud peer only by
admitting *some two-vCPU SEV-SNP VM booted by Google's firmware* — **a mixed federation collapses
to the weakest member's granularity**, and the measured side's rigour buys it nothing when it
talks to a peer that has none. What the run does establish is the half ticket 14 could not: two
chips, two AMD product lines, two certificate chains, a real network path, a middlebox, and a
latency figure a deployment would recognise. Ticket 14's numbers are kept beside the new ones.

The plan is `.scratch/attested-secure-tunnel/gcp-two-vms.md`; the code change is one optional
field in `attest/cmd/tunneld`; the scripts are `docs/snp/cloud/`; the recorded runs are
`docs/snp/evidence/cloud/`. Everything below was produced on 2026-08-28 against the image whose
predicted measurement is
`0ecf8f328899123781da8e800d57aaf6813581d1a3856d97c7b2a6b0bb1caac9551da44b498d81d4f85d1e427e0a98a5`
and a listener whose measurement is Google's
`2d24cf9624ee36449e50c6c84042540b05898f6559f02741b7b354e0cc2ed18d108352ade7dfc4cecce4fa974e51c773`.

## The three probes, and what they changed

The plan asked for three answers before anything was built, because two of them change what the
rest should be. `docs/snp/cloud/probe-platform.sh` took them from two throwaway VMs
(`evidence/cloud/probes/`), deleted three minutes later.

**1. The launch measurement does not cover the boot disk.** Two n2d-standard-2 SEV-SNP VMs, one
from Ubuntu 24.04 and one from Ubuntu 22.04, reported the same `MEASUREMENT`, `2d24cf96…`. Google
publishes a signed launch endorsement for exactly that value
(`gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/<M>.binarypb`), which verifies to their root with
`gcetcbendorsement`: it is a table of measurements of one OVMF build keyed by vCPU count, and
key 2 is this number. So on this provider, membership means *runs Google's firmware at SVN 2 with
two vCPUs*, which is ticket 01's stock-guest finding on somebody else's hardware — the
measurement is genuine and predictable, and it attests nothing about a workload. Criterion 6 is
unreachable for the cloud peer, and this is why the reference value for it is authorised by
Google's signature rather than by a prediction (`docs/snp/cloud/refvals/PROVENANCE.md`).

**2. `auxblob` is populated: 4,763 bytes, three entries.** Ticket 01 found it empty on this
host and established that no operator action fills it; ADR-0005 rests on that finding. On Google
Cloud the host fills it with the VCEK, the ASK and the ARK. The ASK and ARK are byte-identical
to what AMD's key distribution service returns; the VCEK carries the same public key in a
*different certificate* (issued 2026-04-09 versus a fresh 2026-08-27 issuance from KDS —
`evidence/cloud/listener/auxblob-vs-kds.txt`). **Ticket 01's finding is host-specific, and so is
ADR-0005's premise**: on a host that provisions the chain, the design's own provisioning step
is redundant rather than necessary. The decision still stands on its second leg — a chain
fetched at provisioning time keeps AMD off the critical path of every handshake and keeps AMD
from observing which chips talk — but the ADR's opening sentence is a statement about one host,
and it should say so. (Reported, not edited.) The tunneld on the listener bundled the chain from
its config directory as it does here, and its console line says its "certificate table is
empty (auxblob, 4763 bytes)", which is the observation text in `attest/tsm` assuming the answer
to a question it had just asked; also reported.

**3. Two VMs landed on two chips.** Distinct `CHIP_ID`s in one zone. The listener used for the
run is on chip `9ca4af44…b9dc`, a Milan part at TCB 4/0/29/222, firmware 1.58; this host is a
Genoa part at 9/0/23/72. Two product lines, two AMD intermediates, and `attest/verify` keying
its roots by product line was exercised for the first time with two of them in one process.

## What is new code, and what is not

One field. `link` in the run configuration may name a `gateway`, and `cmd/tunneld` adds a
fourth ioctl (`SIOCADDRT`) after the three ticket 14 needed, because a guest behind QEMU's
user-mode NAT has to be told the way out and the image's init cannot be asked to (it is inside
the measurement). It is validated on-link and applied last, since the kernel refuses a gateway
it has no route to yet. It changes the binary inside the launch measurement, so it was done
once, first, and the image repackaged: the new measurement is `0ecf8f32…`, and ticket 14's
evidence describes `06c6007a…`, an image nothing here runs. That evidence stands as recorded.

Everything else is scripts. `nat-guest.sh` is `tunnel-guest.sh` with the netdev changed back to
user-mode and one thing added, `-object filter-dump`: every frame the guest emits or receives,
before NAT, to a pcap. `udprelay.py` is `l2relay.py` one layer up — an IP header where the
ethernet one was and a return mapping per dialer — running on an ordinary VM with a public
address that the measured guest's peer table names *instead of the listener*, which is the whole
point of the peer table not being security-critical. `provision-vms.sh` holds the provider's
flags and nothing else does. `tunnel-across-the-network.sh` is the harness: one guest spooled
locally as ticket 14 spools it, the cloud side brought up first and driven over ssh.

## What the topology is, and why it is weaker on one side

```
  shs1 (Genoa, this host)                             Google Cloud us-central1-a
  ┌──────────────────────────────┐                    ┌──────────────────────────┐
  │ measured guest 10.0.2.15     │  UDP out through   │ relay: e2-small, public  │
  │ M predicted offline          │  QEMU NAT and the  │ 34.30.253.16, udprelay.py│
  │ dials "gcp-listener" =       │ ─────────────────► │ + unattested-peer        │
  │ the relay's public address   │  campus egress     └────────────┬─────────────┘
  │ every frame → filter-dump    │  128.239.2.78                   │ 10.128.0.0/9 internal
  └──────────────────────────────┘                    ┌────────────▼─────────────┐
                                                      │ listener: n2d-standard-2 │
                                                      │ SEV-SNP Milan, 10.128.0.18│
                                                      │ tunneld, holds 6 h       │
                                                      └──────────────────────────┘
```

In ticket 14 "no egress to the vendor" was a property of a segment with no gateway. Here the
guest has a gateway, this host has unrestricted egress, and there *is* a path to AMD. What
replaces the wiring is the capture: `filter-dump` sees the guest rather than constraining it,
and the census over it (`pcap-census.py`) either lists exactly one IPv4 destination or does not.
That is a stronger observation and a weaker guarantee, and both halves should be read. On the
cloud side the listener has no ingress rule at all — the relay reaches it over the VPC's
internal range — and the relay accepts UDP 4433 from this host's egress address only.

## The order things were done in

1. The gateway change, its unit tests, and a real-kernel test of the four ioctls in a network
   namespace. 2. The image repackaged (`package-tunneld.sh`: guard, build, measure), its own
   virtualenv. 3. A local rehearsal of the NAT shape with a peer nothing answers
   (`evidence/cloud/rehearsal/`): the measured guest applied the gateway, ARP'd only for it, and
   the capture showed 30 datagrams leaving and ICMP unreachables coming back from an upstream
   router. 4. The probes. 5. The cloud side provisioned: a raw report read by hand, the chain
   fetched from KDS against it, the two-value set signed with the image's author key, tunneld
   started under root with a six-hour hold. 6. `unattested-peer` from the relay against the
   listener, refused. 7. The harness, in the order `live nat-gap tamper modified tcbfloor
   live-again`, with live at both ends as the control.

## What each criterion is evidenced by

The harness ran `live nat-gap tamper modified tcbfloor live-again`, 74 assertions, no failures
(`evidence/cloud/tunnel-run.txt`, whose one recorded failure was a wrong assertion in `tcbfloor`,
corrected and re-run alone: `tcbfloor/tunnel-run-rerun.txt`; the correction is itself a finding,
below). Ticket 14's criteria, in its order:

| Criterion | Here |
|---|---|
| 1. packaged into the measured image, M recomputed offline, reference value re-emitted | **shs1 side only.** `evidence/cloud/packaging.txt`, `manifest.txt`; the listener wrote down exactly the predicted `0ecf8f32…` in its `PEER key=… measurement=` line. **Absent for the cloud peer**: its binary is on a disk its measurement does not cover. |
| 2. the packaged binary checked before M is computed | shs1 side, unchanged from ticket 14 (`package-tunneld.sh`). The same guard-passing binary (`b9d7fae6…`) was copied to the listener, where it guards nothing measured. |
| 3. two attested guests connect, each with its own chain | **Stronger than ticket 14.** The `live` scenario: 33 passes over 1000 s; the guest's `PEER SEEN` names the listener's chain and the listener's names the guest's, and they differ — one Genoa chain at 9/0/23/72, one Milan chain at 4/0/29/222, two chips, two AMD intermediates, verified by one `attest/verify` in each process. |
| 4. egress to the vendor blocked | **Weaker in kind, and observed rather than wired.** The guest has a route to the internet. The census of every frame it emitted in `live` (4,515 frames): ARP for `10.0.2.2` and `10.0.2.15` only; IPv4 UDP only between `10.0.2.15` and `34.30.253.16:4433` (2,174 out, 2,294 in); two ICMP to the relay after it stopped; nine IPv6 link-local. No other destination. On the cloud side, the listener has no ingress rule and the relay accepts UDP 4433 from `128.239.2.78/32` only. |
| 5. TCB change / stale chain | Not re-run here; ticket 14's simulation stands and this run adds nothing to it. Milan's TCB (4/0/29/222) and Genoa's (9/0/23/72) are different number lines, which is why the set carries a floor per value. |
| 6. modified image refused, naming the measurement | **shs1 side only, and it still works across the network**: the mutated image (`d2a04e8a…`) dialed the cloud listener and was refused 55 times with `launch measurement not in the reference value set: launch measurement matches none of the 2 reference values in the set`; its exercise exited 2 and it had admitted the listener. Absent for the cloud peer: a modified cloud boot disk measures the same. |
| 7. below the TCB floor refused | `tcbfloor`: the guest's set carries a floor of microcode 255 on the cloud value; the guest refused the listener 57 times with `platform below the TCB floor … UcodeSpl:222 is lower than the policy minimum … UcodeSpl:255`. The listener's console for the scenario is empty — see the finding below. |
| 8. non-confidential VM presenting no evidence refused | `evidence/cloud/unattested/`: `unattested-peer` on the relay VM — an ordinary e2-small, a better stand-in than a `-no-snp` boot — dialed the listener over the VPC and was refused: `no evidence presented: peer's envelope carries no attestation payload`; the peer saw `CRYPTO_ERROR 0x12a tls: bad certificate` and exited saying REFUSED, not unreachable. |
| 9. relay reads nothing, with a control | The relay on a public address carried every datagram of `live` — 4,468 of them, 341,581 bytes — and found no plaintext; `tamper` flipped a bit in 16 of 326 datagrams, every exchange completed and none took a changed datagram for its answer. The control on the control is the rehearsal and `relay-selftest.sh` from ticket 14; the marker was sent, since the exercise sends it and the relay counted the exchanges that carried it. |
| 10. latency table | below, beside ticket 14's. |
| 11. the harness records its output | `docs/snp/evidence/cloud/`: per scenario the guest console, the listener's console slice and its startup lines, the guest's `filter-dump` pcap and its census, the relay's pcap and summary, the job file, and the run configuration. |

## The latency table

Measured by the dialing guest, over the relay, on the 1000-second `live` run: 33 passes, 660
sequential exchanges and 792 concurrent ones, over a tunnel that was attested exactly twice —
at pass 1 and at pass 31, when it reached its maximum age. **Taken while Google's 2026-07-28
SEV-SNP notice was open** (boot time and performance changes, August to November 2026); the
numbers are a property of this campus-to-us-central1 path on this date, not of the design.

| | n | shs1 → cloud min | median | max | ticket 14, one host (min / median / max) |
|---|---|---|---|---|---|
| cold establish — dial, both verifications, one round trip | 2 | 125.457 ms | — | 134.060 ms | 16.312 / — / 33.284 |
| warm establish — `Peer(name)` on a tunnel already held | 31 | 0.011 ms | 0.011 ms | ~0.02 ms | 0.008 / 0.012 / 0.042 |
| warm exchange — request and response on that tunnel | 660 | 32.857 ms | 33.585 ms | 39.804 ms | 0.476 / 0.835 / 6.194 |
| concurrent — 24 exchanges, 8 in flight, one tunnel | 33 rounds | 99.954 ms | 101.903 ms | 119.677 ms | 3.270 / 4.405 / 9.937 |
| … per exchange within those | 792 | 32.473 ms | 33.604 ms | 43.207 ms | 0.807 / 1.058 / 1.582 |

Read the two columns together. The warm exchange is one round trip on this path — about 33 ms,
which is the network and nothing else — and the concurrent wall is three rounds of it, so eight
in flight cost the same as one, which is what one exchange per stream buys and it survives the
distance. **The cold establishment is about four round trips plus the verification**: every
cold handshake in this evidence set is between 114 and 145 ms — `live` 134.060 and 125.457,
`nat-gap` 145.016 / 114.451 / 118.611 / 116.340 / 127.027, `tamper` 133.082, `live-again`
138.503, the smoke run 134.909 — nine handshakes across four scenarios, all on the first
attempt, against ticket 14's 16–252 ms on one box. The spread ticket 14 warned about (ARP,
contention) is gone here because the path dominates: **about 130 ms is what admission costs
between this host and a confidential VM in another region, and about 16 ms of it is the
attestation.** The re-attestation at pass 31 is the second cold figure and costs the same as the
first; the peer already held the mapping and nothing was booting.

## The NAT

`tunnel.Limits` has warned since ticket 12 that nothing holds the path open, so a middlebox that
drops an idle flow sooner than the idle timeout closes the tunnel first, and in a trace it looks
like a lost tunnel rather than a NAT. This run has a middlebox by construction — QEMU's user-mode
NAT — and the `nat-gap` scenario asked for a peer every 120 s against a 60 s idle timeout, for
600 s. Five passes; **every one cost a verification** (`verifier_calls=1` on all five) and
**none failed a first attempt** (`attempts=1`). The tunnel was gone each time — torn down at
60 s of idleness, before any mapping question arose — and re-dialed transparently on a fresh
source port with a fresh mapping. So the question the design has carried is answered narrowly:
with these defaults the idle timeout closes the tunnel before a NAT mapping can expire under it,
and a NAT's lifetime is irrelevant unless the idle timeout is raised past it. What the run
cannot say is what a mapping lifetime shorter than 60 s would do, because this NAT's is not.
The `live` pcap shows exactly two dialer source ports: the first tunnel and the one that
replaced it at pass 31.

## What this run corrected, and what it found

**Which side refuses decides whether the other side ever gets to judge.** Ticket 14 recorded
that refusal is one-sided: the modified guest admitted its refuser fifty-nine times over. That
held again here in `modified`, where the *listener* refused, and the guest had admitted it. In
`tcbfloor` the *dialer* refused, and the listener's console for the scenario is empty — no
`PEER`, no `REFUSED`, nothing. A TLS 1.3 client judges the server's certificate before it sends
its own, so a listener refused by a dialer sees only an aborted handshake and never sees the
dialer's evidence. The harness's first assertion expected the listener to have admitted the
guest; it was wrong, and the corrected one is that the listener saw nothing. Ticket 14's
sentence is true of a refusing listener only.

**`auxblob` is a property of the host, not of SEV-SNP.** Above. The ADR reads as if the
platform cannot supply the chain; on this provider it does, and it supplies a VCEK certificate
that is not the one KDS hands out today (same key, different issuance). A verifier keyed on
certificate bytes would call two endorsements of one key two chains.

**A reference value set for a mixed federation carries one floor per member.** Milan and Genoa
number their TCB components differently, so "minimum TCB" is per value and a set with one floor
admits nobody on the other product line. Already expressible; now exercised.

**Google's endorsement expects policy `0x70000`; the VMs report `0x30000`.** The endorsement
additionally allows a migration agent; the instances do not. The floor in the set is the
stricter one and the discrepancy is recorded in `refvals/PROVENANCE.md`.

**The observation text in `attest/tsm` assumes an empty `auxblob`.** The listener's console
says "its own certificate table is empty (auxblob, 4763 bytes) … which is the expected state on
this host" — a sentence written for one host, printed on another. Reported, not edited; the
harness asserts on the byte count, not the sentence.

**`us-east1-b` cannot place an N2D SEV-SNP instance**, and says so only at create time as
`ZONE_RESOURCE_POOL_EXHAUSTED`. `provision-vms.sh` defaults to `us-central1-a`.

**The relay is the only public thing, and the listener never needed an address.** The peer
table names the relay; the listener is reachable from the relay over the VPC's internal range
and from nowhere else. That is the topology the plan recommended and it needed no change to the
listener's tunneld — no `link`, `listen 0.0.0.0:4433`, an ordinary directory as `-config`.

## Running it

```sh
docs/snp/image/package-tunneld.sh                              # OUT=$STACK/image-cloud
docs/snp/cloud/probe-platform.sh -zone us-central1-a           # three answers, two VMs, deleted
docs/snp/cloud/provision-vms.sh create|chain|deploy|start      # the cloud side, in that order
docs/snp/cloud/tunnel-across-the-network.sh -relay-ip … -listener-ip … -capture docs/snp/evidence/cloud
docs/snp/cloud/provision-vms.sh stop                           # money is real
```

`us-east1-b`, the project's configured zone, cannot place an N2D SEV-SNP instance; the run is
in `us-central1-a`. Google's 2026-07-28 notice — SEV-SNP instances may boot slower and perform
differently from August to November 2026 during a guest-kernel migration — was open while every
number here was taken.

## What this does not establish

- **The measured-image gate on the cloud peer.** Its measurement is Google's firmware; a boot
  disk with a different tunneld, or no tunneld, measures the same. Criteria 1, 2 and 6 are
  absent for it and no provider-booted VM can recover them.
- **That the federation is narrower than "any two-vCPU SEV-SNP VM Google boots from OVMF at SVN
  2".** It is exactly that wide, by the reference value it had to carry. The trust root is
  still one public key inside shs1's measurement, but one of the two values that key signs is
  authorised by Google's signature over Google's firmware, not by a prediction from inputs we
  control (`refvals/PROVENANCE.md`). Anyone reading this run as the stronger of the two should
  read that sentence first.
- **A NAT mapping shorter than the idle timeout.** The NAT here outlived 60 s; the warning in
  `tunnel.Limits` is about one that does not.
- **A TCB rollover, re-provisioning, revocation, replay on a fresh connection, the agent-facing
  path, an honest image builder, key custody** — as ticket 14 lists them, unchanged.
- **Two measured images on two hosts.** The single most valuable run is still two SNP-capable
  boxes on one switch both booting the measured image; this run shows what a cloud pair can and
  cannot add to it, and the answer is transport and chains, not the gate.
- **A latency figure that outlives Google's notice.** Every number here was taken during an
  open provider notice about SEV-SNP boot and performance; the table is dated for that reason.
