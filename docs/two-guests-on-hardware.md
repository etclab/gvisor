# Two attested guests

Milestone 3, ticket 14. The whole thing on real hardware: tunneld inside the measured image,
on two confidential VMs, connecting only because both proved they booted that image. Every
property in the memo's verification list that a unit test cannot reach gets its evidence here,
and the ones that could not be reached even so are named at the end rather than left implied.

Vocabulary is `CONTEXT.md`; the decisions are ADR-0002 through ADR-0006. The code is
`attest/cmd/tunneld` over the packages ticket 09 through 13 built; the harness is
`docs/snp/tunnel-on-two-guests.sh` with `docs/snp/l2relay.py` and `docs/snp/tunnel-guest.sh`,
and its recorded runs are in `docs/snp/evidence/ticket14/`. Everything below was produced on
2026-08-27 against the image whose predicted measurement is
`06c6007ab2339f9930fdd20e5f1c8ee164d0ea2ffa70f80d2940b5ea1391bff92af0c90ead345b40bde6f10478a1a1b0`,
and both guests reported exactly that measurement in their evidence.

## What is new code, and what is not

Ticket 05 needed no new verification code, and said so, because a milestone that needs new code
is proving the code rather than the design. This one needed exactly one thing that did not
exist: the process itself. `attest/tunneld` was a package with no `main`, and the measured image
embedded a placeholder written in C.

`attest/cmd/tunneld` is that `main`, and it is composition and nothing else. It reads the author
key from inside the measurement and the set, the peer table and the provisioned chain from the
config device outside it; it builds a real acquirer (`tsm`) and a real verifier (`verify`); it
starts one tunneld and lets it serve. It decides no reference value, judges no peer, and holds
no key. Three things in it are worth naming because they are not obvious from that description:

- **It configures its own network interface.** The guest's init is inside the launch
  measurement and cannot be asked to do it: a guest whose address was set there would be a
  different image per address, and the entire claim is that both guests ran the *same* image.
  The address arrives on the config device like everything else that differs between two
  guests, and three ioctls apply it.
- **It carries the caller a Milestone 3 guest does not have.** The image has no agent and no
  shell — init runs this binary and powers the machine off when it exits — so a tunneld that
  only listened would establish nothing and measure nothing. The exercise asks for the peers the
  run configuration names and produces the figures user story 50 wants. Milestone 4 replaces it
  with the sentry (user story 46). It lives in the command, not the package.
- **It writes down what each peer presented**, by wrapping the vendor seam's `attest.Verifier`
  with a recorder that decides nothing. A tunneld's key is observable nowhere but at the peer it
  is presented to — `ratls.Identity` exposes no accessor and should not — so a run that has to
  record "these two guests presented distinct keys" has to record it at the far side.
- **It puts a ceiling on one number the config device carries.** The run configuration may ask
  for a shorter maximum age and may not ask for a longer one than `tunnel.DefaultMaxAge`. That
  file is outside the launch measurement and delivered by a host this design does not trust, and
  the maximum age is the only bound on how long a verdict about a peer is relied on while
  traffic still flows; unclamped, a host writing `max_age: 8760h` onto both guests' devices gets
  two tunnelds that admit each other once and never look again, with nothing forged, nothing
  substituted and no line in any log. CONTEXT.md does put the operator outside the threat model
  and this file is configuration — but the same sentence would excuse delivering the reference
  value set unsigned, and ADR-0004 refuses to for exactly this adversary. The ceiling therefore
  lives inside the measurement, where the host cannot reach it, and a clamp that bites says so
  on the console. The stock-guest run exercises it on hardware: a year is handed in, 15m0s is
  what runs.

## What the topology is, and why it is evidence

The two guests' only network is `docs/snp/l2relay.py`. Each guest's QEMU holds one TCP
connection to it (`-netdev socket,connect=`) and it copies ethernet frames between them. There
is nothing else on the segment: no gateway, no resolver, no route off it, and no host stack in
the middle.

Two of the criteria are properties of that picture rather than of anything the harness asserts
afterwards. Egress to the vendor is *absent* during the run rather than filtered — there is no
path to AMD's key distribution service to block, and a guest that tried would have to ARP for a
gateway that does not exist, which the relay would record. And because every frame passes
through the relay, the relay is the on-path attacker: it writes every frame to a pcap and
searches each one for the plaintext an exchange carries. There is one capture per scenario —
`evidence/ticket14/<scenario>/segment.pcap`, seven of them — kept whether or not a claim rests on
that scenario's, because a rule that captures everything does not drift the way one that captures
what somebody thought would matter does. Two of them are the largest: `modified` and `tcbfloor`
are mostly a refused dialer retrying about once a second, which is itself the record of what a
refusal costs a peer that keeps asking. A re-run replaces this directory rather than adding to
it, so every number here comes from one binary. The legitimate exchange and the
attacker's failure to read it are the same run, which is what user story 49 asks for.

A relay that carried nothing would report no plaintext too, and a scanner that never matched
would report the same, so `docs/snp/relay-selftest.sh` establishes both before either claim is
made: two guests ping each other across it, and a frame carrying the marker in the clear is put
on the segment by hand and must be both seen and delivered unchanged.

## The order things were done in

**1. The binary was checked before the measurement was computed.** `snpfake` reaches
go-sev-guest's test signing, which reaches `testing`; ticket 14 puts a binary inside the launch
measurement, and a measurement over a binary nobody checked is a measurement of whatever was
there. The guard that had lived in package `tunneld` moved to `cmd/tunneld`, where the binary
is, and gained a second half that reads the built artifact rather than a graph beside it — no
forbidden package path in the file, and no `PT_INTERP`, because the image's root filesystem
carries no dynamic loader and such a binary fails at exec inside the guest with the measurement
already fixed. `docs/snp/image/package-tunneld.sh` is that order made mechanical: test, build,
`build-image.sh`.

**2. The image was rebuilt with `TUNNELD` set and nothing else set.** Every byte of the image is
a byte in the measurement, so the build is ticket 06's, unchanged.

**3. The measurement was predicted from the build inputs, offline**, by ticket 07's
`predict-measurement.sh`, and emitted as the signed reference value set. No platform was
consulted. Both config devices carry that set and nothing else authorises either guest.

**4. Two confidential guests were launched from it**, each with its own config device, through
the operator's root-runner spool — `/dev/sev` is root-only here and `sudo` needs a password, so
every privileged step is a `.job` file a human can read before it runs.

**5. The verdicts came from the guests themselves**, on their serial consoles, which is the only
diagnostic surface a measured guest has (user story 48).

## What each criterion is evidenced by

| Criterion | Established by |
|---|---|
| tunneld packaged into the measured image, the measurement recomputed offline, the reference value re-emitted | `docs/snp/image/package-tunneld.sh`, recorded in `evidence/ticket14/packaging.txt` and `manifest.txt`. Both guests then reported that measurement in their evidence, and the peer wrote it down: the `PEER SEEN … measurement=` line on each console equals `predicted-measurement.txt` exactly. |
| the packaged binary confirmed free of the fake platform before the measurement is computed | `attest/cmd/tunneld/importgraph_test.go` (both the command's graph and the package's) and `packaged_test.go` (the artifact: no forbidden package path in the file, no dynamic loader), run by the packaging script before the build. Both were mutation-checked: adding an `snpfake` import to the command fails both. |
| two attested guests connect and a legitimate exchange succeeds, each with its own provisioned chain | the `live` scenario. Both consoles show evidence acquired from the platform and the chain read from their own config device; guest B establishes, exchanges and is answered by guest A by name. "Its own" is its own device: the two devices carry the same chain bytes, because both guests are on one chip (see *What this does not establish*). |
| the exchange completes with egress to the vendor blocked | the topology: the guests' only link is the relay, which has no uplink, and the relay's ARP census records every IPv4 address either guest resolved — `10.14.0.2` and `10.14.0.3` and nothing else. This is blocking by construction: no guest attempted to reach the vendor and was refused, and the census is IPv4-only. The pcap holds what it leaves out, and it points the same way: 16 IPv6 router solicitations, every one to a link-local multicast address, and not a single router advertisement in reply. |
| re-provisioning after a TCB change, and a stale chain failing at the peer rather than locally | **simulated, and it does not surface where the criterion expects.** See *What a stale chain actually does* below. |
| a guest booted from a modified image is refused, naming the measurement internally | the `modified` scenario: ticket 08's `mutate-image.sh` changes one byte of `rootfs.img` — byte 9,093,119, inside the padding, which nothing in the guest ever reads — and the guest boots and attests perfectly. Its own predicted measurement is `9b17cf11…` (`modified/mutated-measurement.txt`) against the base image's `06c6007a…`: one inert byte, and the two share no prefix. Guest A refuses it with `launch measurement not in the reference value set` and tells it nothing. The refusing side logs the reason rather than the value it saw. |
| a guest below the TCB floor is refused | the `tcbfloor` scenario: guest A holds a set with the same measurement, the same author and a floor this platform does not meet. |
| a non-confidential VM presenting no evidence is refused | two halves, both live. The `nosnp` scenario boots the same image without SEV-SNP: it has no evidence, refuses to start, and never listens. `docs/snp/unattested-peer` is the other half — a peer that does present a certificate, with no attestation payload in it, refused on the wire by a real tunneld. |
| an attacker relaying datagrams reads nothing, with a control | the relay carries every frame of the `live` scenario — 4,940 frames, 565,593 bytes — and finds no plaintext in any of them, while the same run's 680 sequential and 816 concurrent exchanges all succeed. The `tamper` scenario is the active half: the relay changes a bit in every twentieth datagram, 18 of them, and no exchange takes a changed datagram for its peer's answer while the exchanges complete anyway. `relay-selftest.sh` is the control on the control. |
| a latency table | below. |
| the harness records its output for every property | `docs/snp/evidence/ticket14/`. |

## The latency table

Measured by the dialing guest, over the relay, on the two-guest run recorded in
`evidence/ticket14/live/`: 1000 seconds, 34 passes, 680 sequential exchanges and 816 concurrent
ones, over a tunnel that was attested exactly twice — once at the start and once at pass 31,
when it reached its maximum age.

| | n | min | median | max |
|---|---|---|---|---|
| cold establish — dial, both verifications, one round trip | 2 | 16.312 ms | — | 33.284 ms |
| warm establish — `Peer(name)` on a tunnel already held | 32 | 0.008 ms | 0.012 ms | 0.042 ms |
| warm exchange — request and response on that tunnel | 680 | 0.476 ms | 0.835 ms | 6.194 ms |
| concurrent — 24 exchanges, 8 in flight, one tunnel | 34 rounds | 3.270 ms | 4.405 ms | 9.937 ms |
| … per exchange within those | 816 | 0.807 ms | 1.058 ms | 1.582 ms |

All figures are milliseconds as the dialing guest measured them, over the relay, on the
1000-second run in `evidence/ticket14/live/`. The warm-exchange row is the per-pass minimum,
median and maximum across 34 passes of twenty exchanges each; the concurrent row is the wall
time of eight-in-flight × three rounds, and the row under it the individual exchanges inside
them.

**Cold establish** is the whole cost of admission: a QUIC handshake, both sides' certificates
carrying an SEV-SNP report and its chain, both sides verifying the other against AMD's root, and
one empty application round trip before the tunnel counts as established. It happens once per
tunnel.

**Warm establish** is the same call — `Peer(name)` — on a tunnel the cache already holds. It
costs no handshake and no verification, which is what makes the cold figure a startup cost
rather than a per-exchange one, and the harness asserts it by counting the verifier's calls
rather than by reading the clock.

**Warm exchange** is one request and one response on that tunnel: a stream opened, four bytes of
length, the payload, end of stream. No attestation is anywhere in it.

**Concurrent** is twenty-four exchanges in flight eight at a time on the one tunnel. That the
wall time is close to the slowest exchange rather than the sum of them is what one exchange per
stream buys (user story 40), and it is the only figure here that would change if the transport
had been chosen differently.

**And the re-attestation.** The run is longer than the fifteen-minute maximum age, so partway
through it the tunnel is torn down and both guests judge each other again, under a caller that
did nothing but keep asking for the same peer. It appears in the table as a second cold figure
with a verification behind it.

**The two cold figures are 33.284 ms and 16.312 ms, and only the second is a measurement of
attestation.** The first is pass 1, moments after both guests booted: the pcap shows guest B's
ARP for `10.14.0.2` going out before guest A had finished bringing its interface up, and the
handshake beginning when a second ARP is answered 133 ms later. The second is pass 31, the
re-attestation forced by the maximum age — same two guests, same evidence, peer already in the
ARP cache and nothing else happening on the machine. **About 16 ms is what a handshake between
two attested guests costs on this hardware**, and it is the figure to quote.

Every cold handshake in `evidence/ticket14/` is worth listing, because the spread is the point
and the mean would hide it: 16.312 (`live`, pass 31), 33.284 (`live`, pass 1), 50.162 (`tamper`)
and 252.785 ms (`live-again`), against 22.686 ms for two tunnelds inside the stock guest over
loopback (`stock-guest-run.txt`). The attestation work is identical in all five. What differs is
address resolution, whatever the transport had to retransmit, and how much else was running on
the host at that instant — `live-again` follows five other scenarios and pays 133 ms of ARP plus
a contended CPU for it.

A deployment should take that spread seriously rather than the 16 ms. The first dial after a
cold boot costs whatever it costs to find a peer that may not be answering yet, and on Linux one
ARP retransmission is between a tenth of a second and a whole one.

## What a stale chain actually does

The criterion asks for a guest left with a stale chain to be shown failing *at its peer* rather
than locally, on the grounds that this is the confusing direction and worth seeing before it
happens in anger. Two things are true and neither is quite that.

**It fails locally first, and that is the design working.** `tsm` acquires the report, loads the
chain the config device holds, and checks the chain against the report before it will bundle the
two (ADR-0005). A guest whose chain is for a TCB the platform has moved off therefore never
starts, never listens and never presents anything:

```
tunneld: refusing to start: ratls: acquiring evidence: provision: certificate chain refused: the
provisioned chain was issued for TCB bootloader=9 tee=0 snp=23 microcode=71 but this platform
reports TCB bootloader=9 tee=0 snp=23 microcode=72: the chain is stale, which peers would refuse
as malformed evidence; re-provision the chain after any TCB update (ADR-0005)
```

So the confusing direction is not reachable from a tunneld: the local check is in front of it.
What a peer *would* say, if evidence and a stale chain reached one, is recorded beside it by
running `verify-evidence` on ticket 05's captured bundle — and it is not what ADR-0005 says:

```
reason      : evidence does not chain to the vendor root
operator log: verification refused: evidence does not chain to the vendor root:
              report signature verification error: x509: ECDSA verification failure
```

AMD derives the VCEK per TCB, so a chain for another TCB endorses a *different key*: the
report's own signature fails before the coherence check that would have called it malformed ever
runs. Ticket 05 established this on real silicon and this run reproduces it. It is the same
correction, reported again and not applied, because the places that would have to change are an
ADR and three documents outside this ticket's territory — including the sentence in the refusal
above, which tells an operator to expect "malformed evidence" at their peers.

**And no firmware was rolled over.** The TCB-change criterion is satisfied by *simulation*: the
stale chain is a real one, fetched from AMD's key distribution service for this same chip at
microcode 71 during ticket 05, one level below what the platform reports. A real PSP firmware
rollover would invalidate every recorded measurement baseline on this host and is not cleanly
reversible. Nothing here shows the operational sequence of a TCB update — only the state a host
is left in by one it did not re-provision for.

## The same command without a guest launch

`docs/snp/tunnel-in-stock-guest.sh` runs `cmd/tunneld` inside the stock SEV-SNP guest ticket 01
left running, where the only privileged step is the guest's own `sudo`. It builds its own binary
rather than taking the packaged one, and since both are now built with `-trimpath` the two are
the same file: `stock-guest-run.txt` and `packaging.txt` both name
`c3eb66f2af1f542ba1009d5d447c69966f0b16bb4d24285e12e611c103ff2ac9`, from two builds in two
directories. That agreement is itself the reproducibility fix working — before it, the same
source in two places produced two binaries and two measurements. It needs no launch and no
spool, which is why it exists: it is
the way to exercise the whole path on real silicon when the operator's runner is not up, and it
is where two things were established that the two-guest run does not reach.

**A peer with no evidence, on the wire.** `docs/snp/unattested-peer` dials a real tunneld with
an ordinary self-signed certificate — no attestation payload — and is refused, with a peer that
does present evidence admitted by the same listener in the same run as its control. It is
deliberately not built from `ratls`: a peer built from this design's own certificate code and
refused by this design's own reading of it proves less than one written the way a stranger would
write it.

**Two tunnelds on one chip.** They present distinct keys over one identical chain, which is the
same shape the two-guest run produces and for the same reason — and it is why chain *equality*
is what the two-guest run asserts.

## The controls

A refusal that would also happen with the tunnel broken is not evidence, so the `live` scenario
runs at both ends of the list, on the same wiring, and the refusals sit between them. Both
passed: 30 assertions on the 1000-second run and 29 on the 150-second one that followed the
refusals, both stated by the transcript this time. The whole set is 85 assertions and no
failures. Each refusal scenario carries its own local control as well — in `modified` and
`tcbfloor` the refused guest *admits* the other, on the same handshake it is refused on, so the
wiring is demonstrably intact at the moment of the refusal.

The relay carries its own two controls (`relay-selftest.sh`), and the `tamper` scenario is a
control in the other direction: an attacker that does change the datagrams it carries still
changes nothing a peer accepts.

## What this run corrected, and what it found

**"Refused" and "never reached" are different answers, and a harness must be able to tell
them apart.** `unattested-peer` exited 0 on every failure, so a peer it could not reach read
exactly like one that refused it — and that distinction is the only thing the program exists to
report. It now separates them: once the dial returns a connection the peer has proved it is
there and every later failure is its decision, while at the dial itself a close the peer *sent*
is a refusal and a timeout that heard nothing is not evidence about anybody. The stock-guest
harness asserts on its exit status as well as on the tunneld's log line, because those are two
claims and only one of them was being made.

**A peer with no evidence is admitted by TLS and refused by the application.** `unattested-peer`
dials a real tunneld with an ordinary self-signed certificate carrying no attestation payload.
Its dial *succeeds*: TLS 1.3 lets a client finish before the server has processed its
certificate, so a peer with nothing to say gets a connection object back. Only the application
round trip tells it otherwise — `CRYPTO_ERROR (remote): tls: bad certificate`, which names
neither the check that refused it nor what would have satisfied it, while the tunneld's own
console says `no evidence presented`. This is exactly why `tunnel.Dial` completes a round trip
before calling a tunnel established (user story 38, and `attest/README.md`'s first bullet about
establishment), and it is now something observed rather than reasoned about. A harness that
stopped at the successful dial would have recorded the opposite of what happened.

**Refusal is one-sided, and the modified-image run shows it plainly.** The guest booted from the
mutated image admitted its peer fifty-nine times over while being refused fifty-nine times by
it — it retried once a second for a minute, and every retry was a complete handshake in which it
verified the good guest's evidence, accepted it, and was then refused itself. Ticket 13 warned
that a harness counting verifications on the far side of a refusal is counting a race; the
figure that means something is each side's own log, and both are recorded.

**Two guests on one host share a chip, so they share a chain.** A certificate chain is per chip
and per TCB (ADR-0005), and these two guests are on one machine. Their chains are byte-identical
and only their keys differ, which the harness asserts in that direction: distinct keys, equal
chains. The handoff into this ticket expected two guests to carry two chains, and that is true
of two guests on two machines and false here. Nothing in this run distinguishes two guests on
one host from two tunnelds in one guest by anything a peer can see — which is the spec's
documented non-goal, not a defect (*Reference values and naming*).

**An on-path attacker that corrupts datagrams achieves nothing but loss.** The `tamper`
scenario had the relay flip a bit in every twentieth datagram — 18 of them over a minute — and
the run completed with every exchange answered correctly. QUIC authenticates each packet, so a
changed one is discarded and retransmitted, and the exchange never sees it. The check that
would have caught it if anything had got through is in the exercise itself: a response must be
the peer's echo of the exact request that was sent.

**`mkconfigdev.sh` reports the five files it knows and packages whatever is there.** The run
configuration this ticket adds, `/config/tunneld.json`, is packaged correctly and named nowhere
in the script's output. Not a defect — the script says it packages a directory — but a reader of
its output will not see the file that decides what the guest does.

## Running it

The privileged half needs the operator's runner, once, in a tmux session:

```sh
sudo bash docs/snp/root-runner.sh        # in the primary checkout, not a worktree
```

Then, unprivileged:

```sh
docs/snp/image/package-tunneld.sh                    # guard, build, measure
docs/snp/relay-selftest.sh                           # the controls on the relay
docs/snp/tunnel-on-two-guests.sh -capture docs/snp/evidence/ticket14
docs/snp/tunnel-in-stock-guest.sh                    # no guest launch, no root
```

`tunnel-on-two-guests.sh` writes one `.job` per scenario into the spool and waits for its `.rc`.
`-no-snp` runs the same scenarios as control boots and needs only `/dev/kvm`; nothing attests in
that mode, so it exercises the harness rather than the design. `-scenario NAME` selects; the
default is the whole list with `live` at both ends.

## What this does not establish

- **Two hosts.** Both guests are on one machine, one chip, one certificate chain. Nothing here
  exercises two platforms, two chains, or a network between two hosts — including the middlebox
  that `tunnel.Limits` warns about, which on a segment this short cannot exist.
- **That a peer can tell two guests apart.** It cannot, and no run could show otherwise:
  membership is "runs the measured image", both guests run it, and a host that redirects a name
  from one to the other produces a successful handshake with the wrong party (spec, *Reference
  values and naming*).
- **A real TCB rollover**, as above.
- **Revocation.** The KDS CRL is not consulted, deliberately
  (`docs/provisioning-certificate-chain.md`).
- **Anything about the agent-facing path.** There is no agent and no sentry here; the exercise in
  `cmd/tunneld` stands in for one, and Milestone 4 replaces it.
- **That the image builder is honest.** The build is rebuildable and auditable, not
  bit-reproducible, and that limitation is load-bearing in the threat model
  (`docs/snp-measured-image.md`).
- **Key custody.** The reference value author key is a throwaway the packaging script generates,
  as in every run so far.
- **Replay, drop or reorder on the segment.** The relay's active half flips bits; it does not
  re-inject a recorded datagram on a later connection, drop, or reorder. The memo's "replayed
  exchange on a fresh connection" item is not exercised here.
- **A refusal of no evidence over the segment.** The `unattested-peer` half ran inside the stock
  guest over loopback; on the two-guest segment the no-evidence case is a guest that never
  listens.
- **An attempt at egress.** No guest tried to reach the vendor and failed; egress is absent by
  construction, and the census that says so is IPv4-only.
- **Re-provisioning.** The stale chain was substituted in; no guest was re-provisioned and
  shown to recover.
