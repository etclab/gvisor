# Two attested guests on TDX

Milestone 3b, ticket 19. The same claim as ticket 14, on somebody else's hardware: two tunneld
guests on Google Cloud TDX, each running from an initrd grub measures into RTMR2, each admitting
the other only on a measurement predicted offline and paired with the digest of the other's
signed policy, with everything that is not the tunnel refused by a netfilter rule before it
leaves the guest.

Vocabulary is `CONTEXT.md`; the decisions are ADR-0002 (the v2 binding), ADR-0004 (the signed set)
and ADR-0007 (provisioned Intel collateral, never fetched). The verifier is ticket 17's,
unchanged. The harness is `docs/snp/cloud/tdx/run-tdx-scenario.sh` over `build-tdx-image.sh`,
`mkconfigdev-tdx.sh` and `publish-tdx-image.sh`, and its recorded runs are in
`docs/snp/evidence/ticket19/`, which every relative path below is under. Everything was produced
on 2026-09-10 against two images whose predicted RTMR2 are `d5ddcc42…73e0d` and `640de950…14be7`
— in full in `images/image-*/predicted-measurement.txt` — and every guest reported exactly the
value predicted for the image it booted.

**In one sentence.** Six confidential guests on Google TDX booted images whose RTMR2 was computed
from the disk bytes before any of them existed; two of them admitted each other because each
carried a signed reference value naming the other's measurement *and* the digest of the other's
signed policy; change either half of that pair and the admission stops, in the direction the
documents say it should; and in all six the only packet that left was the tunnel.

## What is new code, and what is not

Nothing in `pkg/` or `runsc/` changed, and neither did the verifier: `verify/tdx.go` and
`verify/snp.go` are where tickets 17 and 09 left them, byte for byte. Three things are new, and
only the first is design.

**The policy is now its own signed document.** Ticket 18 made the policy part of the sandbox's
signed allow-list, and its run showed the consequence: an allow-list carries its peers' policy
digests, so two peers could never both pin each other and constrained admission was
one-directional per pair (`docs/policy-binding.md`). `policy.json` is therefore its own document,
signed under its own domain prefix, carrying `version`, the `egress` section and `forward_to` —
measurements this sandbox will dial, with no digests in it — while `reference-values.json` is
version 4, keeps its `(measurement, policy_digest)` pairs and has lost its `egress` section. The
policy digest is SHA-256 over the signed bytes, not `sha256sum` of the file, and `forward_to` is
enforced on the dialing side. The split was proved before any TDX work started, on ticket 14's
SEV-SNP harness: scenario `mutual`, D_A ≠ D_B, each set naming only the other's digest, 41
assertions passed and 0 failed, both guests `EXIT status=0`
(`docs/snp/evidence/ticket18/mutual/`). What ticket 18 could not author at all is the thing every
scenario here rests on.

**tunneld learned to render, install and probe its own egress rules, and to judge its own platform
out loud.** `attest/cmd/tunneld/egress.go` turns the signed policy's refusal of unattested egress
plus the peer table into an `nftables` rule set, prints it, installs it and reads it back out of
the kernel; `selfcheck.go` runs this guest's own evidence through this guest's own set and prints
the verdict, the registers, and the quote in base64 so a workstation can judge the same evidence
again. Both live in the command rather than the packages, for the reason ticket 14 gave for the
exercise.

**The acquirer answers on Intel.** `attest/tsm/tsm.go` had SEV-SNP-only shortcuts in it, and there
were three rather than the two ticket 17's handoff named: `provision.LoadFor`, which loaded an AMD
chain unconditionally; the provider-name resolution, which named no provider for any other vendor;
and `confirmEcho`, which read the caller-supplied bytes back out of an SNP report and had to learn
a version-4 quote's `REPORTDATA` instead. On TDX the provider resolves to `tdx_guest` and
`Evidence.Chain` is left `nil`, because the quote carries the chain that roots it; the platform's
own certificate table is absent (`auxblob: … no such file or directory`), which every console here
prints and which is the expected state on this host rather than an error. It was tested against
real configfs-tsm on the step-zero VM before any image existed — twice, once with no `-chain-dir`
and once with one holding nothing, which must be ignored rather than read — and the bundle it
wrote was carried back and ACCEPTED here (`step-zero/acquire-evidence.txt`,
`step-zero/verify-evidence.txt`).

## What the topology is, and what it costs in evidence

Two Confidential VMs in one VPC, `10.128.0.40` and `10.128.0.41`, talking QUIC over UDP 4433
directly. No relay, nothing in the middle that this project controls, and no capture: the
datagrams cross Google's virtual network and nothing in this ticket can tap it.

That is a real loss against ticket 14, where the relay *was* the network and therefore the
evidence — every frame written to a pcap and searched for the exchange's plaintext, the on-path
attacker and the legitimate exchange being one run. Nothing here replaces it. Each console carries
what its guest did, not what crossed the wire: the exercise names the peer that answered it
(`answered_by="guest-b"`) and reports its own passes and failures. The on-path criterion below is
therefore recorded as not exercised rather than as satisfied by construction.

What the topology buys instead is the opposite of ticket 14's egress argument. On the relay
segment there was no route off the network, so "egress blocked" was blocking by absence. Here
there is a gateway one hop away, a metadata server every cloud guest can reach and a default route
to the internet — and the refusals are refusals.

## What the image is, and how its measurement is predicted

The guest is an initrd, and the initrd is the whole guest: `busybox-static` 1.36.1 with 22 applet
symlinks, the `tunneld` binary, the operator's public key at `/etc/attested-tunnel/author.pub`,
and seven modules out of the image's own `/lib/modules` — `tdx-guest`, `gve`, `nf_tables`,
`nf_reject_ipv4`, `nf_reject_ipv6`, `nft_reject`, `nft_reject_inet` — 49 entries in all
(`images/image-a/initrd.list`). It never pivots, and the manifest records Ubuntu's root, the ESP
and the GPT unchanged byte for byte, which is why RTMR1 keeps the values ticket 17 observed.

The boot configuration is a fixed 272 bytes, nine lines carrying seven grub commands, generated
whole rather than edited and installed with the immutable flag set on the inode through `debugfs`
(`images/image-a/grub.cfg`). It reads `grubenv` nowhere — no `load_env`, no `save_env`, no
`recordfail`, no `initrdfail` — so grub measures 25 records where the stock image measures 86, and
RTMR2 cannot depend on how a previous boot ended, which is the one way
`docs/tdx-rtmr2-prediction.md` found for a pristine image's RTMR2 to move. The immutable flag is
the second line of defence; the first is that there is no userspace in this image to run
`update-grub` at all.

RTMR2 is predicted by ticket 16's `predict-rtmr2.py` from the disk just built, offline, no machine
asked: 25 records for each image, one on the provider's own 6.17.0-1022-gcp kernel and one on the
7.0.0-1011-gcp package (image-b's configuration is 271 bytes, one character shorter, because the
kernel's name is). Both were rebuilt at least twice and predicted the same register each time
(`README.txt`). The `disk.raw` is *not* bit-reproducible — ext4 puts the rewritten files in
different blocks — and it does not need to be: what grub opens is identical, so the register is.

**Step zero came first, because the predictor's initrd path had never been exercised.** One
throwaway TDX VM, two boots of one disk, each predicted from bytes captured off the guest before
that boot: the pinned image untouched gave 86 records and RTMR2 `ecc99358…11df9`, MATCH; the same
disk with one `initrd` line added to the branch grub actually takes gave 88 records and
`d8f247b4…b1aa5`, MATCH. The two records gained are the `grub_cmd: initrd
/initrd.img-6.17.0-1022-gcp` string and the SHA-384 of the initrd file itself. Nothing in the
predictor was changed to make either comparison come out (`step-zero/`).

**What the initrd does, in order** (`docs/snp/cloud/tdx/init.tdx`, and every line of it is on every
console): mounts its pseudo-filesystems including configfs, `insmod`s the seven modules, checks
that `/sys/kernel/config/tsm/report` is there, prints its block-device inventory, finds the config
device and mounts it `ro,noexec,nosuid,nodev` and lists every file on it with a digest, brings
loopback up, brings `eth0` up from `network.conf` — parsed field by field, never sourced, because
nothing on that device may execute — installs the egress rule set, proves it, remounts the
initramfs read-only, and starts tunneld. tunneld runs three times and only the third serves:
`-egress install`, `-egress probe`, then `-tdx-collateral-dir /config/collateral -self-check`;
rules before attestation is deliberate, since the other order leaves a window in which the guest
is attested and unconstrained. When tunneld exits the initrd powers the machine off.

One phrase in the ticket needs qualifying. It asks that the initrd "mounts the config device by
Google's device name", and init does try: it looks for `attested-config` as an NVMe serial, which
is what `--device-name` produces — and that is exactly what fails, because the name arrives
through udev running `google_nvme_id` and there is no udev here. With none running, both disks
report the serial `nvme_card-pd` and differ only by namespace (`step-zero/guest-facts.txt`,
`rtmr0/two-disks/disks.txt`), so init falls back to the ext4 label `mkconfigdev-tdx.sh` wrote —
the same name — and says which: `initrd: config device /dev/nvme0n2 found by the ext4 label`. The
label is the weaker identifier and need not be stronger, since nothing on that device is trusted:
a misidentified one fails to mount or fails to parse, and both stop the guest rather than admit
anybody. The requirement holds in the sense that matters and not in the sense the phrase says.

## The order things were done in

**1. The policy was split from the allow-list and proved on SEV-SNP**, then **2. step zero** ran
on a throwaway VM, which also carried the acquirer's first run against real configfs-tsm. Its
first attempt aborted itself rather than guessing: the stock image's `/boot/grub/grub.cfg` is mode
0600 root, the probe read it unprivileged, found no filesystem UUID and stopped after the baseline
boot. That is why step zero has two rows in `RESOURCES.md` and only the second has an answer.

**3. The two images were built and their registers predicted**, with the signed documents emitted
by the same script from the same inputs. **4. One guest was booted from image-a as a smoke test —
and the first was refused by its own reference value**; that refusal is kept
(`smoke/run1-rtmr0-mismatch/`) because it is the observation the RTMR0 probe went and explained,
below. The smoke boot that counts is the whole path in one guest: rules installed and probed,
self-check ADMITTED because that set names its own pair, a tunnel established to itself through
attestation, and the quote off its console judged again here — `ACCEPTED` (`smoke/smoke-run.txt`,
`smoke/verify-evidence.txt`).

**5. The three scenarios ran**, each from one script invocation that authors four documents,
builds and publishes two config devices, creates two guests, watches both consoles, tears
everything down and states its assertions; afterwards the egress captures were cut out of the
consoles into `egress/`, where all six guests' rule sets sit side by side.

## The three scenarios

| | guest A boots | guest B boots | set A admits | set B admits | outcome | assertions |
|---|---|---|---|---|---|---|
| one | image-a | image-a | d5ddcc42… + D_B | d5ddcc42… + D_A | both admit, both exchange, both re-attest | 55 passed, 0 failed |
| two | image-a | image-a | d5ddcc42… + D_A | d5ddcc42… + D_A | A refuses B on the policy digest; B admits A | 48 passed, 0 failed |
| three | image-a | image-b | d5ddcc42… + D_B | d5ddcc42… + D_A | A refuses B on RTMR2; B admits A | 49 passed, 0 failed |

D_A is `d47dce59…ee92b`, the digest of the policy the image build itself emitted; D_B is
`444a4aa8…61f28`, a policy differing from A's in the only way that is also true — it forwards to
one more measurement, `d79409cc…39592`, which is SHA-384 of an ASCII sentence and names no image
anybody has. Each digest was read three times and agreed three times: printed by `emit-refvals`
when it wrote the document, read back off the delivered document by `emit-refvals -digest-of`, and
read again off the console of the guest carrying it (`scenario-*/digests.txt`).

**Scenario one is the mutual pinning ticket 18 could not author.** Both guests admitted the other,
neither logged a single refusal, each answered the other's exchanges by name, and the run was long
enough — eleven passes over eight minutes at a maximum age of three — that each tunnel expired
under a caller still using it and was re-attested (`scenario-one/`).

**Scenario two changes one thing: the document on B's config device.** Both guests run the same
image and the same binary, and A's set names A's *own* policy digest, which B does not present. A
refused B 180 times, naming the digest B presented and telling it nothing else; B refused nothing;
no tunnel formed in either direction and nothing was exchanged either way. The 180 is worth
decomposing, because it is the whole asymmetry: A's own dials failed 91 times on A's own verdict
(`CRYPTO_ERROR 0x12a (local): attest: verification failed`) and B's dials failed 89 times on the
verdict A sent it (`CRYPTO_ERROR 0x12a (remote): tls: bad certificate`). TLS 1.3 sends the
server's certificate first, so A judges B in both directions. This is ticket 18's finding with the
roles swapped (`scenario-two/`).

**Scenario three changes one thing: the kernel package B's image was built from.** Everything else
is scenario one — the same two policies, the same two sets, the same addresses, the same author
key. A refused B 151 times (61 of A's own dials plus 90 of B's), and the refusal names the
register that disagreed and the value the reference value predicts:

```
tunneld: REFUSED verification refused: launch measurement not in the reference value set: the
TD's RTMR2 is 640de950bbdde9300d2092da28885ec6455acdc3b6df99ea847d02d5cf7c99d86724bb4dff41bb037c4f212f33414be7,
and this reference value predicts d5ddcc423b1aed530237a6c43b3005d317464a94217dd9477f113007379dbf0fc7601cac8fa69bb48a4efd4322c73e0d
```

Guest B admitted guest A on the same handshake, which is this scenario's local control: the
wiring, the collateral, the binding and the author key are demonstrably working at the moment A
refuses B. The two images differ in the kernel, in the seven modules that come out of that
kernel's package, and in the one `grub.cfg` line that names it — and MRTD, RTMR0 and RTMR1 are
identical on the two guests. RTMR2 is the only register that noticed (`scenario-three/`).

**Every refusal was remade on this workstation**, by `attest/cmd/verify-evidence` reading the
guest's own quote off its console against the set the other guest carried, with none of the
guests' machinery trusted: four verdicts per scenario, each matching the corresponding console
(`scenario-*/verify-evidence-*.txt`).

**Three of the six pairs launched were superseded**, and are in the ledger anyway
(`RESOURCES.md`): two to harness faults that changed no evidence, and one to an authoring mistake
worth naming, because it is how a scenario like this fails silently. Guest A's set had been
written from the measurement its peer *actually reports* rather than the one it is supposed to
expect, so A admitted the 7.0 guest and scenario three tested nothing. A set written from the
peer's observed measurement can never refuse anybody.

### The self-checks are refused, and that is the arrangement working

In scenarios one and three each guest's self-check prints `SELFCHECK VERDICT REFUSED reason=guest
policy or policy digest not permitted by the reference value`. A set says whom a guest *admits*;
in a mutual arrangement that is the peer's `(measurement, policy digest)` pair and not the guest's
own, so a guest judging its own evidence against its own set is refused on the digest while the
measurement matches. This workstation reaches the same verdicts from the same quotes. Scenario two
is where a self-check is ADMITTED — A's set names A's own pair — and that is deliberate: A's set
and A's platform agree at the same moment A's set refuses B, so the machinery is demonstrably
intact when the refusal happens.

### What the consoles do not carry

Each console ends a few lines early. tunneld prints its peer summary (`PEERS`, `PEER SEEN`) and
then `EXIT status=`, the initrd prints its own and calls `poweroff -f`, and those lines are written
milliseconds before the machine stops; Compute Engine serves an empty body for an instance that
has stopped, so an incremental capture ends there and a re-fetch adds nothing. The same truncation
is on the smoke boot's console. Nothing here rests on those lines — the exercise's own `LATENCY`,
`FAILED` and `answered_by` lines are inside the capture, and the workstation verdicts do not
depend on the console at all — but ticket 14 made a point of a harness asserting on a program's
exit status as well as on its log line, because "refused" and "never reached" are different
answers, and that half of the technique is unavailable here. The transcripts were also meant to
print the byte counts of the two reads and do not: the line that would have carried them is a
shell `bad substitution` in all three runs (`scenario-*/tunnel-run.txt`, under *5. watching both
serial consoles*), so the truncation is evidenced by the missing lines rather than by a measured
zero.

## Egress

The rule set is one `inet` table, `attested_tunnel`, with all three base chains at policy drop and
forward left empty because the guest routes for nobody. The exceptions are loopback and four rules
per peer: dialing the peer's listener, answering from this sandbox's own, and the same two
inbound. The output chain ends in two refusals rather than one, because the kernel turns them into
an answer at the socket by two different routes — a TCP reset, so `connect()` fails at once
instead of retransmitting for a minute, and an ICMP administratively-prohibited (`reject with
icmpx code 3`) for everything else. tunneld prints the set it intends and then the set the kernel
hands back (`egress/`).

Five attempts per guest, six guests, thirty attempts, thirty refusals, and the errno is the point:
`EPERM` (`write: operation not permitted`) or `ECONNREFUSED` (`connect: connection refused`) is a
rule refusing, while `ENETUNREACH` would be the routing table having nothing to say and would
prove nothing about the rule. All thirty were the former. The refused set includes
`169.254.169.254:80`, the provider's metadata server — the one address every cloud guest can reach
and the first an exfiltrating guest would reach for — a public resolver over TCP and over UDP, and
the guest's own VPC gateway `10.128.0.1`, one hop away and genuinely reachable had the rule not
been there. The contrast the ticket asks for is on one guest in one minute: scenario one's guest A
excepted exactly one address, `10.128.0.41` on udp/4433, and that is the peer it went on to attest
and exchange with eleven times over eight minutes. The difference between the two is not
reachability. It is the rule.

**Loopback has to be up first, and that is not a formality.** With `lo` down netfilter still builds
the refusal but the kernel cannot deliver it to the local socket, so every attempt times out
instead — and "timed out" does not distinguish a firewall from a black hole. The initrd brings
loopback up before it touches the network for exactly this reason, and the microsecond refusals
are what that buys.

**The limitation, plainly.** The rules are generated from the peer table and the listen port
(`attest/cmd/tunneld/egress.go`), not from the signed policy, because a policy's `forward_to`
names measurements and a measurement is not an address — and `peers.json` is an unsigned file the
host delivers. So the ticket's phrase "a netfilter rule the policy generates" holds for the
*default drop* and for the shape of the rules, which follow from the signed policy's refusal of
unattested egress and would differ if it permitted it, but the excepted addresses are not covered
by the policy digest. Two things follow. An out-of-policy dial from tunneld's own dialer cannot be
produced at all: it dials peers by name, a name not in the table is refused before a socket opens
(`ErrUnknownPeer`), and an address in the table is excepted by construction — scenario three put
the question directly with a third peer, `outsider` at `10.128.0.42`, that no machine has, and the
dial died of silence after 11 attempts (`timeout: no recent network activity`) rather than of a
rule. And the two mechanisms are disjoint rather than redundant: the peer table decides where the
tunnel may be carried, the rule set stops everything else in the guest reaching the network at
all. Milestone 4 will have to say what the policy should express once an agent runs inside and the
peer table is no longer the only thing that opens a socket.

## Re-attestation, and what an establishment costs here

Scenario one ran a maximum age of `3m` and an exercise of eleven passes over eight minutes, 45
seconds apart. A pass that finds the tunnel still live costs no verifier call and establishes in
single-digit microseconds; a pass that finds it expired re-dials, re-attests and costs a real
handshake. Measured by each dialing guest, on `scenario-one/console-*.txt`:

| | pass | guest A | guest B |
|---|---|---|---|
| cold establish, moments after boot | 1 | 84.901 ms | 70.848 ms |
| re-attestation at the maximum age | 5 | 10.795 ms | 13.220 ms |
| re-attestation at the maximum age | 9 | 10.354 ms | 9.902 ms |
| warm establish, tunnel already held | the other 8 | 0.007–0.008 ms | 0.006–0.008 ms |
| warm exchange, per pass (n=5) | all 11 | 0.184–2.923 ms | 0.174–4.624 ms |
| concurrent, 8 streams in one round | all 11 | 0.404–30.658 ms | 0.455–2.844 ms |

**About 10 ms is what a handshake between two attested guests costs here**, and it is the figure to
quote: passes 5 and 9 are the same two guests, the same evidence, nothing else happening, and the
only work in them is a QUIC handshake plus both sides verifying a TDX quote against provisioned
Intel collateral. Pass 1 is not a measurement of attestation but of two machines that have just
booted finding each other, and the concurrent row's 30.658 ms on guest A is in that same pass for
the same reason. As on ticket 14's hardware, the cost is per tunnel and not per exchange.

The ticket asks for one re-attestation captured; there are two apiece, and the lines that prove it
are `verifier_calls` going back above zero at passes 5 and 9 on both consoles while the
establishment cost jumps from microseconds to milliseconds. The counts differ between the guests —
1, 1, 2 on A and 2, 2, 2 on B — because the counter is the wrapped verifier's and a listener
verifies its dialer on the same handshake it is verified on; what the assertion turns on is that
three of the eleven establishments on each guest cost a verification and eight cost none.

## What the registers did across the run

MRTD was `c1ee9c16…70a5` on every boot of this ticket, and RTMR2 was the predicted value on every
boot — quoted, printed on the console, and compared against a prediction made before the machine
existed (`scenario-*/measurements.txt`). RTMR1 was `02c7f19c…913b`, ticket 17's *first-boot* value,
on every boot of every guest here, and that is the expected one: the guest never runs Ubuntu's
initramfs, so nothing grows the root partition and the GPT never changes. Intel reported this
platform `UpToDate` at evaluation data number 20 throughout; nothing was refused for being below
the TCB floor, and nothing was clamped, so the maximum age in force was the one each config device
asked for.

**RTMR0 is the finding.** Every record on this branch before this ticket is `c0b8b19c…896d`, and
every one was taken on a VM with exactly one disk. The first guest with a config device attached
reported `c2fc12a5…850a` and was refused by its own signed set — `SELFCHECK VERDICT REFUSED
reason=launch measurement not in the reference value set`, with the register that disagreed
printed beside it out of the quote's own bytes (`smoke/run1-rtmr0-mismatch/console.txt`). The probe
that explains it changed one thing on one instance: it attached a second disk to a running
stock-image guest and rebooted, and watched RTMR0 move from `c0b8b19c…896d` to `a5e39b27…2b79`
(`rtmr0/rtmr0-probe.txt`).

That third value is not the one this ticket's guests report, and the difference is the lesson: the
probe's shape is a stock boot disk with a config disk attached to a running instance and rebooted,
this ticket's is a custom image with both disks present at creation, and two disks each gave two
different RTMR0s — so the disk *count* is not what names the value, and nothing here isolates what
else does. What the run establishes is the useful half: `c2fc12a5…850a` on every two-disk boot of
this ticket, the smoke guest and all six scenario guests, against `c0b8b19c…896d` on every
one-disk boot before it. (RTMR1 moved in the probe too, to `3a446943…d691`, for the ordinary
reason: its second boot was not a first boot.) **RTMR0 is a constant per machine shape, not per
provider**, and a reference value has to pin the value the shape it is authored for reports — an
author who copies one recorded on another shape writes a set that refuses its own guests, which is
exactly what happened here. `docs/tdx-verifier.md` carries a dated correction to this effect.

## Ticket 14's eleven criteria, here

Ticket 14's record lists eleven criteria in *What each criterion is evidenced by*. Taken one at a
time, in its own words:

| Ticket 14's criterion | Here | Why |
|---|---|---|
| "tunneld packaged into the measured image, the measurement recomputed offline, the reference value re-emitted" | **holds, with a caveat** | `build-tdx-image.sh` builds the binary into the initrd, predicts RTMR2 from the built disk with no machine consulted (25 records), and emits the signed version-4 set and the signed policy (`images/*/packaging.txt`). The caveat is that only RTMR2 is predicted; MRTD, RTMR0 and RTMR1 are pinned from observation, because they are the provider's and not the image's. |
| "the packaged binary confirmed free of the fake platform before the measurement is computed" | **holds** | The build runs `go test ./cmd/tunneld` — ticket 14's import-graph and packaged-artifact guards — and stops otherwise: the `guard passed: the packaged graph reaches no fake platform and no test support` line in `images/image-a/packaging.txt` step 2, before step 4 puts the binary in the initrd. It also refuses a binary that is not static or that embeds the checkout path. |
| "two attested guests connect and a legitimate exchange succeeds, each with its own provisioned chain" | **holds, with a caveat** | Scenario one: both admit, both exchange, both re-attest, 55/0. The caveat is "its own provisioned chain": on TDX nothing is bundled — `chain=none` on every `PEER` line — because the quote carries the chain that roots it. What each guest carries of its own is the provisioned Intel collateral on its config device (ADR-0007), byte-identical between the two, as the chains were in ticket 14 and for a related reason. |
| "the exchange completes with egress to the vendor blocked" | **holds, and more strongly than on the relay** | Ticket 14's was blocking by absence; here there is a route off the segment and a rule refuses it, 30 attempts for 30 refusals with the errno recorded each time, and no fetch of Intel collateral is possible during the run in any case (ADR-0007). `egress/`. |
| "re-provisioning after a TCB change, and a stale chain failing at the peer rather than locally" | **does not hold** | Not exercised. No TCB changed under these guests, no collateral was re-provisioned, nothing stale was substituted in. The provisioned collateral is valid to 2026-10-08; ticket 17 recorded that expiry surfaces as `ChainNotRooted`, which is a statement about a code path and not a run. |
| "a guest booted from a modified image is refused, naming the measurement internally" | **holds, with a caveat** | Scenario three, 151 refusals, and the refusal names both the register the guest reported and the one the reference value predicts — more than ticket 14's said, and still only on the refusing side's console; the refused peer gets `CRYPTO_ERROR 0x12a` and nothing else. The caveat is that "modified" here is a second image built from a different kernel package, not one byte flipped in the first; nothing in this ticket mutates an image in place. |
| "a guest below the TCB floor is refused" | **does not hold** | Not exercised. Google's platform was `UpToDate` at evaluation 20 for every boot and no scenario authored a floor it does not meet; the assertion in every run is the negative one, "nothing was refused for being below the TCB floor". |
| "a non-confidential VM presenting no evidence is refused" | **does not hold** | Not exercised. There is no non-TDX control boot here and no unattested dialer on the wire. The nearest thing is descriptive: tunneld prints that the report interface is present and that "a platform driver that does not answer it is what a non-confidential VM looks like from inside". |
| "an attacker relaying datagrams reads nothing, with a control" | **does not hold** | Not exercised, and not exercisable in this topology: the datagrams cross Google's virtual network, and there is no relay and no capture. The exchanges carry the same plaintext marker ticket 14 searched for, and nobody searched. |
| "a latency table" | **holds** | Above, from `scenario-one/console-*.txt`: cold, re-attested, warm, warm exchange and concurrent, per guest. |
| "the harness records its output for every property" | **holds** | `docs/snp/evidence/ticket19/`: three transcripts with 55, 48 and 49 named assertions and no failures, six consoles, six quotes and their parses, six rule sets, twelve workstation verdicts, both images' manifests and predictions, and the two probes. |

Ticket 14 also ended by insisting that a harness assert on a program's exit status and not only on
what it logged. That surface is gone here (*What the consoles do not carry*), so every assertion
above rests on a line the exercise printed while it was still running, or on a verdict this
workstation reached afterwards from the guest's own quote.

## What it cost

Every instance is in `docs/snp/cloud/tdx/RESOURCES.md`, one row each with the hour it was created
and the hour it was deleted: eighteen `c3-standard-4` TDX instances in `us-central1-a` — two for
step zero, four for the three smoke boots and the RTMR0 probe, twelve for six scenario pairs — all
deleted the same hour they were created, the longest-lived at about thirteen minutes, and the
project's instance listing is empty of this ticket's names at the end. The ledger's own figure is
about 106 instance-minutes for the scenarios; step zero and the image work bring it to 126. Well
under a dollar either way.

Three images were kept, because the alternative is uploading ten gibibytes again to get back to
where this ticket left off: `attested-tdx-d5ddcc423b1a`, `attested-tdx-640de950bbdd` and
`attested-config-tdx-smoke-a-20260910214749`. Every per-run config-device image and staging bucket
was deleted inside the run that made it. Nothing pre-existing was touched: no firewall rule,
network, IAM or org policy was created or changed, and the tunnel's intra-VPC UDP rides the
pre-existing `default-allow-internal` rule (priority 65534, source `10.128.0.0/9`). The port is
4433 because that is what the project's older `attested-tunnel-udp-4433` rule opens; that rule was
neither used nor touched.

## Running it

The whole thing is unprivileged on the workstation; the only things that run as root are the
guests. `gcloud auth login` first.

```sh
docs/snp/cloud/tdx/probe-tdx-initrd.sh                      # step zero, before any image exists

AUTHOR_KEY=$K BASE_IMAGE=$SCRATCH/img/base-disk.raw OUT=$SCRATCH/image-a \
    docs/snp/cloud/tdx/build-tdx-image.sh
AUTHOR_KEY=$K BASE_IMAGE=$SCRATCH/img/base-disk.raw OUT=$SCRATCH/image-b \
    KERNEL_SOURCE=$SCRATCH/kernel7/x IMAGE_LABEL=b docs/snp/cloud/tdx/build-tdx-image.sh

IMAGE_DIR=$SCRATCH/image-a docs/snp/cloud/tdx/smoke-tdx-guest.sh
docs/snp/cloud/tdx/probe-tdx-rtmr0.sh -config-image attested-config-tdx-smoke-a-20260910214749

docs/snp/cloud/tdx/run-tdx-scenario.sh one
docs/snp/cloud/tdx/run-tdx-scenario.sh two
docs/snp/cloud/tdx/run-tdx-scenario.sh three
```

That is the reading order and not quite the run order: `probe-tdx-rtmr0.sh` ran between the first
smoke boot and the last, because the first smoke boot is what raised its question. Two notes for
anyone repeating it: `build-tdx-image.sh`'s header says `BASE_IMAGE` has a default and it does
not, and everything else is defaulted — the boot image's name comes from the predicted register
(`attested-tdx-${RTMR2:0:12}`), and `publish-tdx-image.sh` and `mkconfigdev-tdx.sh` are called by
the two runners rather than by hand. `SCENARIOS.md` says what each scenario means and asserts;
`RESOURCES.md` is the ledger every script appends to. Each script creates what it needs, watches
the consoles it created, deletes everything it made and prints its own assertion count; a scenario
that fails an assertion still tears down.

## What this does not establish

- **Two hosts, or two of anything.** Both guests are VMs in one zone, and TDX evidence does not say
  which machine a TD is on. Nothing here distinguishes two guests on two hosts from two on one.
- **That a peer can tell two guests apart.** As in ticket 14: membership is "runs the measured
  image", and a host that redirects a name from one guest to the other gets a successful handshake
  with the wrong party.
- **Anything on the wire.** No capture, no on-path attacker, no tamper, no replay, no reorder. The
  plaintext-marker exchange runs and nobody looks at the segment.
- **A peer with no evidence, or one below the TCB floor.** Neither was staged on TDX.
- **A TCB rollover or a re-provisioning.** The collateral was provisioned once, on 2026-09-08, and
  was valid throughout; no platform moved under a guest, and no guest was shown recovering.
- **That the egress rules follow the signed policy's addresses.** They follow the peer table, which
  is unsigned and host-delivered; the policy decides that unattested egress is refused and what
  shape the rule set takes, and cannot decide which addresses are excepted. Milestone 4.
- **A policy that changes under a live tunnel.** Scenario one re-attests twice under a caller that
  kept asking, and that is not the same thing: both guests presented the same policy on every
  handshake, and nothing here swaps a document while a tunnel is up.
- **What else RTMR0 depends on.** Three shapes gave three values and the cause is not isolated
  here; what is pinned is the value this shape reports.
- **That the image builder is honest.** The build is rebuildable and auditable; `disk.raw` is not
  bit-reproducible, and what is reproducible is the register, which is the claim
  (`docs/snp-measured-image.md`).
- **Key custody.** The author key is a throwaway generated for this ticket, as in every run so
  far, and its public half is inside both measurements — so re-signing with another key would need
  new images.
- **Anything about the agent-facing path.** There is no agent and no sentry here; the exercise in
  `cmd/tunneld` stands in for one, and Milestone 4 replaces it.
