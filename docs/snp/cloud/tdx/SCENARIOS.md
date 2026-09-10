# Running ticket 19's three scenarios

What the smoke boot left in place, and the exact steps from here to two guests
talking. Everything below has been run except the two-guest part itself.

## What already exists

Two Compute Engine images, both labelled `purpose=attested-tunnel-t19`, both
kept on purpose so nobody has to upload ten gibibytes again:

| image | kernel | predicted RTMR2 | policy digest of the build's own policy |
|---|---|---|---|
| `attested-tdx-d5ddcc423b1a` | 6.17.0-1022-gcp | `d5ddcc423b1aed530237a6c43b3005d317464a94217dd9477f113007379dbf0fc7601cac8fa69bb48a4efd4322c73e0d` | `d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b` |
| `attested-tdx-640de950bbdd` | 7.0.0-1011-gcp | `640de950bbdde9300d2092da28885ec6455acdc3b6df99ea847d02d5cf7c99d86724bb4dff41bb037c4f212f33414be7` | `a642ab1aca91e3b00f86c6b31a22c016d33c85117319e51b8774a91db3fd885e` |

One config-device image, `attested-config-tdx-smoke-a-20260910214749`, kept as a
worked example rather than because a scenario needs it; each guest gets its own.

The reference value author's key — the one whose public half is inside both
images at `/etc/attested-tunnel/author.pub`, and therefore inside RTMR2 — is at
`.scratch/attested-secure-tunnel/host-stack/image-ticket19-tdx/author.key`.
Public half `665053d10032f5b9a46394a65b022c0bd7007392b8f445fe4ace5b0e5ed4c5a2`.
Signing with any other key means rebuilding the images, which means new
measurements.

## The three constants a set has to pin, and the one that surprised us

```
mrtd   c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5
rtmr0  c2fc12a52db868515eff7c657e42ce04b0b7363fa6ddf7c1cca87aa8e6a061a11f9981924a600ad6d2232f75182a850a
rtmr1  02c7f19c862b3dae1592c737358d9bb13f8f0a34d3b3eca67c39bf7941a12c347635b8a291d68d9cace45b16ec25913b   (first boot)
       3a446943925fef7f1682fd54e1b6697df864692e28592ec373860d1868582ac14ca3029c48282eb964868a785bafd691   (every boot after)
```

**RTMR0 is a function of the machine's shape.** `c2fc12a5…850a` is what a
c3-standard-4 with one 20GB boot disk and one 10GB config disk reports; a VM
with one disk reports `c0b8b19c…896d`, which is what every earlier run in this
repository recorded and what the first smoke guest was refused for. Change the
number of disks and the value changes; it has been observed on two separate
instances with two separate config disks and was the same both times.
`probe-tdx-rtmr0.sh` is the experiment and `docs/snp/evidence/ticket19/rtmr0/`
its record. Keep the shape fixed and the constant holds; change the shape and
observe it again.

**RTMR1 stays at its first-boot value forever in these guests**, which is not
what a stock Ubuntu VM does. The two values exist because Ubuntu's initramfs
grows the root partition on the first boot and the GPT then changes. This guest
never runs Ubuntu's initramfs, so nothing grows anything; the smoke guest
reported the first-boot value. Both are pinned anyway, because a set that names
one and meets the other refuses its own peer for no reason.

## Authoring one guest's two documents

```sh
docs/snp/cloud/tdx/emit-tdx-documents.sh \
    -out /some/dir/guest-a \
    -key .scratch/attested-secure-tunnel/host-stack/image-ticket19-tdx/author.key \
    -forward-to <measurement this guest will dial> \
    -admit       <the peer's predicted RTMR2> \
    -admit-policy <the peer's policy digest>
```

It writes `policy.json(+.sig)` and `reference-values.json(+.sig)` and prints the
digest of the policy it wrote — the number the *other* guest passes as
`-admit-policy`. Run it once per guest with `-admit-policy` left out to learn the
two digests, then again with them filled in; the policies come out
byte-identical both times, because a policy names no digests. That is the whole
point of the split (`docs/policy-binding.md`).

Scenario by scenario:

- **one** — both guests from `attested-tdx-d5ddcc423b1a`. A's set admits that
  measurement paired with B's policy digest and B's set admits it paired with
  A's. If both policies are identical the two digests are the same number and one
  pair of documents serves both guests; making them differ (a second
  `-forward-to`, say) is closer to ticket 18's mutual run and proves more.
- **two** — same image, and B's `-forward-to` list differs so its policy digest
  differs from the one A's set lists. A refuses B as a policy mismatch, B admits
  A. One direction only.
- **three** — B boots `attested-tdx-640de950bbdd`, whose predicted RTMR2 is
  `640de950…14be7`. A's set names `d5ddcc42…73e0d` and nothing else, so A refuses
  B as measurement not in the set.

## The config device

One per guest, seven files and a directory, exactly as the smoke run built them
(`docs/snp/evidence/ticket19/smoke/config-src/` is a complete worked example):

```
reference-values.json   reference-values.json.sig
policy.json             policy.json.sig
peers.json              {"format":"gvisor.dev/gvisor/attest/peer-table","version":1,
                         "peers":{"guest-b":"10.128.0.41:4433"}}
tunneld.json            format gvisor.dev/gvisor/attest/tunneld-run, version 1;
                        sandbox_id, listen "<own ip>:4433", limits, exercise, hold.
                        NO "link" section — the initrd brings the interface up.
network.conf            interface=eth0 address=<own ip> prefix=32
                        gateway=10.128.0.1 mtu=1460
collateral/             a copy of docs/snp/evidence/tdx/collateral (valid to
                        2026-10-08; re-provision after that or every TDX peer is
                        refused as ChainNotRooted)
```

```sh
docs/snp/cloud/tdx/mkconfigdev-tdx.sh /some/dir/guest-a /some/dir/guest-a.raw
docs/snp/cloud/tdx/publish-tdx-image.sh /some/dir/guest-a.raw attested-config-guest-a
```

`publish-tdx-image.sh` makes a bucket, uploads, creates the image and deletes the
bucket. A 1 GiB config device tars down to about twelve kilobytes.

## Creating the pair

```sh
gcloud beta compute instances create guest-a --zone us-central1-a \
  --machine-type c3-standard-4 \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image attested-tdx-d5ddcc423b1a \
  --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
  --create-disk name=guest-a-config,image=attested-config-guest-a,size=10GB,\
type=pd-balanced,device-name=attested-config,auto-delete=yes \
  --private-network-ip 10.128.0.40 \
  --labels purpose=attested-tunnel-t19
```

and the same for `guest-b` at `10.128.0.41` with its own config image. Two disks
and two disks only: a third would move RTMR0 again. `--private-network-ip`
matters because the address has to be known before the guest boots — the guest
runs no DHCP client, and `network.conf` names the address the instance is
created with. Intra-VPC UDP is already open: the `default-allow-internal` rule
covers `10.128.0.0/9`, and the port is 4433 because that is what the project's
existing `attested-tunnel-udp-4433` rule opens.

## Collecting

The console is the whole record, and it must be fetched **incrementally**:
Compute Engine returns an empty body for an instance that has stopped, so a loop
that re-fetches the buffer each pass erases the transcript at the moment the
guest finishes writing it. `smoke-tdx-guest.sh`'s watch loop does it correctly —
`--start=<byte offset>`, appending, taking the next offset off gcloud's own
stderr hint. Reuse that loop rather than writing another.

What to read out of it:

```
initrd: config device /dev/nvme0n2 found by the ext4 label
initrd: link eth0 up: 10.128.0.40/32 mtu 1460, gateway 10.128.0.1
tunneld: EGRESS RULES INSTALLED; as the kernel holds them:   (and the listing)
tunneld: EGRESS PROBE PASSED: every attempt was refused before it left
tunneld: policy digest <hex>
tunneld: SELFCHECK VERDICT ADMITTED / REFUSED reason=…
tunneld: SELFCHECK EVIDENCE BEGIN … END          (the quote, base64)
tunneld: PEER key=… measurement=… rtmr2=… tcb=…
tunneld: REFUSED verification refused: …          (the line scenarios two and three exist for)
tunneld: LATENCY pass=… kind=… ms=…
tunneld: EXIT status=N
```

The quote comes off the console with

```sh
awk '/SELFCHECK EVIDENCE BEGIN/{f=1;next} /SELFCHECK EVIDENCE END/{f=0} f' console.txt \
  | sed -n 's/^tunneld: SELFCHECK EVIDENCE //p' | tr -d ' \r\n' | base64 -d > quote.bin
```

and is judged on the workstation exactly as a peer would judge it:

```sh
cd attest && GOPROXY=off go run ./cmd/verify-evidence -vendor intel-tdx \
    -evidence quote.bin -key public-key.der -refvals reference-values.json \
    -author <author public key hex> -policy-digest <the guest's policy digest> \
    -tdx-collateral-dir ../docs/snp/evidence/tdx/collateral
```

`public-key.der` is the 44 bytes the guest printed after `SELFCHECK PUBLIC KEY`,
`xxd -r -p`'d into a file.

## Re-attestation

Scenario one asks for an exchange lasting longer than the re-attestation age so
that one re-attestation is captured. The age is `limits.max_age` in
`tunneld.json` and the binary clamps it to `tunnel.DefaultMaxAge`, 15 minutes,
so either set a shorter one and run past it, or run the pair for a quarter of an
hour. The smoke run used `"max_age": "15m"` and ran for two minutes, so nothing
re-attested there.
