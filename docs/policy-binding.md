# A policy bound into the evidence

Tickets 18 and 19. A sandbox's policy is a signed document delivered on its config device; its
digest is folded into the hardware evidence under ADR-0002's binding version 2, and every
verifier checks that digest against a per-entry allow-list of measurement and policy pairs
before it recomputes the binding. All of it lands above the vendor seam: neither `verify/snp.go`
nor `verify/tdx.go` changed, and nothing under `attest/tsm/`, `pkg/` or `runsc/` did either. It
builds on ticket 14 (`docs/two-guests-on-hardware.md`), whose image and harness both runs
rebuild, and on ticket 17 (`docs/tdx-verifier.md`), whose vendor-tagged document is the version
this extends. Proven live twice, on that harness's two SEV-SNP guests. No cloud, no TDX
hardware.

**In one sentence:** ticket 18 made the policy the sandbox's own signed reference value set and
its run proved that could not stand — a set that is also a policy has a digest taken over a
document that names peers' digests, so two peers can never both pin each other — and ticket 19
split the policy into its own document, `policy.json`, after which two guests differing in
nothing but which policy digest their reference value names admit each other in both directions
at once.

---

## What was built

**The policy is its own signed document** (`policy.json`, format version 1,
`attest/policyfile.go`). It carries a top-level `egress` section — `{"version": 1, "unattested":
false}` — and `forward_to`, the launch measurements this sandbox will dial. The egress section
is what makes the file a statement about behaviour rather than a list. Both its fields are
required: a document that does not say whether unattested egress is permitted has not said it is
forbidden, and a loader supplying the answer would be deciding policy on the author's behalf. A
document claiming `"unattested": true` is refused on load, because nothing here enforces
permitting it and a digest a peer vouches for should not vouch for a promise no code keeps. The
section versions separately from the document around it, since it is what a netfilter allow-list
would grow.

`forward_to` names measurements and never digests, and the absence of digests is the whole
point of the file. Empty means the sandbox dials nobody, which is a legitimate deployment;
absent does not load, because an author who said nothing has not said "nobody". It is signed
with the reference value author's key under its own domain separation prefix
(`gvisor.dev/gvisor/attest policy signature v1\0`), so a signature over a set can never be
presented as a signature over a policy or the reverse, and the digest of the same bytes differs
between the two domains.

**The set is the allow-list and nothing else** (format version 4, `attest/refvalsfile.go`).
Version 3 gave a reference value an optional `policy_digest` — the policy a peer running the
named image must present — and also gave the document an `egress` section, on the theory that
the set was the sandbox's own policy as well as its guest list. Version 4 keeps the pairs and
takes the section back out. A version 3 document is refused with a sentence saying to move the
section into `policy.json` and re-emit, and so is a version 4 document that still carries one:
the strict decode would refuse the field anyway, as unknown, but the sentence an author needs
says where the section went rather than that a parser met something it did not recognise.
Version 2 documents, which could name no policy at all, are refused as before.

**Its digest is over the signed bytes** (`attest.PolicyDigestOf`). A policy digest is SHA-256
over exactly the region the author's signature covers: the policy's domain separation prefix and
the document. It names what somebody authorised rather than what is on disk, and the consequence
is worth saying out loud because it would otherwise be discovered by hand — `sha256sum
policy.json` is a different number and the wrong one. `emit-refvals -digest-of PATH` exists so
that nobody computes it another way; it needs no key and does not load the policy.

**The binding carries it** (ADR-0002's amendment, `attest/binding.go`). `report_data` under
binding context v2 is `SHA-512(pubkey ‖ ctx ‖ policy_digest)`, where `ctx` is version byte `0x02`
and fifteen zero bytes. The context is the same sixteen bytes wide it always was: the digest
travels *beside* it in the certificate payload rather than inside it, because widening the
context would move a byte a v1 reader already reads. The payload is version 2 for the same
reason, and its new field is `OPTIONAL` for exactly one: a v1 payload is five fields where this
reader wants six, and it must parse far enough to be refused on its version rather than
complained about as DER. `ratls.NewIdentityForContext` is still the seam a later version grows
through. None of this changed in ticket 19 — the split is about which document the digest names,
not about how it travels.

v1 is now refused, and that is the amendment's substantive decision. ADR-0002 wrote its
consequence about a version from the *future*, which may bind something a verifier cannot see.
A version from the past binds nothing, and admitting one would let any peer skip the policy
check by claiming the older context — the reservation would have bought a version bump and
nothing else. `ratls.Open` refuses a version 1 payload as `ReasonUnknownBindingContext` before
it reads a field that payload never had, because a peer speaking it is running yesterday's
tunneld and its operator has a build to redo, not a corrupt certificate to debug.

**The check, and where it sits** (`attest/verification.go`). `Verify` runs five checks and the
first failure is the verdict: evidence and a public key were presented at all; the binding
context is one this verifier understands; the evidence is authentic and satisfies a reference
value, which is the vendor's half behind the seam; **the policy the peer presents is one a
reference value for its measurement lists**; and the caller-supplied bytes match the presented
key and that digest.

The new check is the fourth, and both of its neighbours are chosen. It is after the vendor's
questions because it is a claim about a peer whose evidence has already been found authentic.
It is before the binding because the binding is the expensive half of the same statement, and
because the two refusals are different sentences: "your policy is not one I admit" is
something an operator acts on by editing a set, while "your evidence was not acquired over the
policy you claim" is a sentence about a peer that is lying, and it should not be reachable by
anyone who merely presented an unlisted digest. Both orders refuse the same peers.

The candidates are every value of the peer's vendor naming its launch measurement, not only
the one the vendor's verifier happened to pick, because a set may name one image twice under
two policies while a deployment moves between them. One candidate listing the presented digest
is enough, and so is one listing none: `policy_digest` is a pointer, nil is unconstrained, and
unconstrained admits any policy. That is the one place this design reads an absent field the
weaker way. It is deliberate — the alternative refuses every set authored before the field
existed, including every one under `docs/snp` — and it is deliberately loud:
`ReferenceValueSet.Unconstrained` lists those entries and `cmd/tunneld` prints one line per
entry at every start.

**And one check that is not the verifier's** (`attest/tunneld/tunneld.go`,
`ratls.WithAdmission`). `forward_to` is enforced by the side that *dials*, after the peer's
evidence has verified and its policy digest has been admitted: the peer's launch measurement —
the one the verifier's claims name — must be in this sandbox's own policy, or the dial is
refused as a `PolicyMismatch` whose detail says `not in forward_to`. Only the client
configuration is built with the hook; a listening tunneld holds no opinion about who calls it.
The asymmetry is the point. Whether a peer may be dialed is a fact about the dialer's policy, so
no allow-list entry of the peer's could carry it and no verifier could decide it.

**What an operator does.** A tunneld loads two documents off the config device — the set it
enforces and the policy it presents — and prints the policy's digest at start on the serial
console, the only diagnostic surface a measured guest has (user story 48):

```
tunneld: policy digest ee222553…de74 (sha256 over the signed policy; put it in a peer's
policy_digest)
```

That number is what goes into a peer's `policy_digest`. It is followed by one line per
measurement the policy forwards to, or by a line saying it forwards to nobody. `emit-refvals
-emit-policy -forward-to HEX…` writes a policy and prints its digest, `emit-refvals
-policy-digest HEX` writes one into a set, `build-image.sh` emits both documents beside the
image and records the policy's digest in the manifest, and `verify-evidence` still takes
`-policy-digest` so a bundle can be judged from outside the guest that produced it. The harness
does not trust any single one of them: for every policy it authors it asserts that the digest
`emit-refvals` printed when it wrote the document equals `emit-refvals -digest-of` on the
document as delivered, and equals the line the guest holding that policy printed at start. Those
three agreeing is the operator's workflow closed end to end.

The memo is updated where it describes any of this: `report_data`, the reference value fields,
the new policy section, the verification list, and open question 2 — "binding runsc's
configuration to the evidence" — which these tickets answer rather than defer.

## What the tests proved

| claim | test |
|---|---|
| a signed policy loads and says what its author wrote: the egress section, and the images it will dial | `TestASignedPolicyLoadsAndSaysWhatItsAuthorWrote` |
| an egress section that is missing, of another version, or permissive is refused | `TestAnEgressSectionThatIsNotAPolicyIsRefused` |
| a policy of a version this loader does not read is refused, and told to re-emit | `TestAPolicyOfAnUnknownVersionIsRefused` |
| an empty `forward_to` dials nobody; an absent one does not load; an entry that names no image is refused | `TestAPolicyForwardingToNobodyLoadsAndForwardsToNobody`, `TestAPolicyThatDoesNotSayWhomItForwardsToIsRefused`, `TestAForwardToEntryThatNamesNoImageIsRefused` |
| the loaded policy's digest is over the signed bytes and not over the file | `TestALoadedPolicyCarriesTheDigestOfTheBytesItsAuthorSigned` |
| the two documents are separated by domain: neither signature verifies as the other's, and neither digest is the other's over the same bytes | `TestAPolicyDigestIsNotASetDigestOverTheSameBytes`, `TestAReferenceValueSetPresentedAsAPolicyIsRefusedByName` |
| a policy is parsed as strictly as a set, renders back to a document that loads, and loads off disk with its signature beside it | `TestAPolicyIsAsStrictlyParsedAsASet`, `TestAPolicyRendersBackToADocumentThatLoads`, `TestAPolicyOnDiskLoadsFromItsDocumentAndSignature`, `TestAPolicySignatureOfTheWrongShapeIsRefused` |
| a version 2 document, which can name no policy, is refused | `TestAVersionTwoDocumentIsRefusedAsNamingNoPolicy` |
| a version 3 document, which was its own policy, is refused and told where the egress section went | `TestAVersionThreeDocumentIsRefusedAsBeingItsOwnPolicy` |
| a version 4 set still carrying an egress section is refused by name | `TestASetStillCarryingAnEgressSectionIsRefused` |
| `policy_digest` survives the document, and one of the wrong shape is refused | `TestAPolicyDigestOnAValueSurvivesTheDocument`, `TestAPolicyDigestOfTheWrongShapeIsRefused` |
| a listed digest is admitted; an unlisted one refuses as `PolicyMismatch` naming what was presented; an entry listing none admits any | `TestAPeerPresentingAListedPolicyIsAccepted`, `TestAPeerPresentingAnUnlistedPolicyIsRefused`, `TestAnEntryWithNoPolicyDigestAdmitsAnyPolicy` |
| a digest swapped in flight, with both policies listed so the peer reaches the binding, refuses as `BindingMismatch` | `TestAPolicyDigestSwappedInFlightIsRefusedAsABindingMismatch` |
| a v1 context, and a v1 payload on the wire, refuse as `UnknownBindingContext` | `TestAVersionOneBindingContextIsNoLongerAdmitted`, `TestAPeerSpeakingPayloadVersionOneIsRefused` |
| the same allow-list at the second vendor, with nothing in `verify/tdx.go` knowing a policy exists | `TestATDXPeerIsAdmittedOnlyByASetListingItsPolicy` |
| genuine recorded AMD evidence over a genuine v1 binding is refused today, with the v1-speaking stand-in as its control | `TestARecordingMadeBeforeBindingVersionTwoIsRefusedAsAnUnknownContext` |
| one dialer and two listeners differing in nothing but which digest they name | `TestATunneldAdmitsAPeerOnlyIfItsSetListsThatPeersPolicy` |
| **two tunnelds whose sets each name only the other's policy, neither unconstrained, both admitting and exchanging in both directions** | `TestTwoTunneldsPinningEachOtherBothAdmit` |
| a peer whose measurement is not in the dialer's `forward_to` is refused by the dialer, with a control on the same wiring that carries traffic | `TestAPeerNotInForwardToIsRefusedOnTheDialingSide` |
| a sandbox whose policy forwards to nobody dials nobody, and still answers those who dial it | `TestASandboxThatForwardsToNobodyDialsNobody` |
| a tunneld starts with neither document missing, refused or swapped for the other | `TestRefusesToStartWithoutAnAcceptedSetOrPolicy` |

Both vendors are covered, and which artefact carries which half is not the split the ticket
expected. AMD's acceptance path is `snpfake`, ticket 02's platform, which can be handed any
binding. Intel's is the fake TDX platform of ticket 17, and it has to be: the recorded quotes
were taken over fixed caller-supplied bytes, so their binding cannot be chosen and no peer
presenting a policy of its own can be built out of one. What a recording can still show is a
refusal, and it shows two — a recorded TDX quote presented with any key is a binding mismatch,
and the recorded SEV-SNP bundle from ticket 05, acquired over a real v1 binding, is now
refused as an unrecognised context with the v1-speaking stand-in beside it as the control.

## The live runs

Two images, one per ticket, both ticket 14's build around a new tunneld: same build script, same
author key `3f27c388…ec72` whose public half is inside the measurement, same TCB floor `9,0,23,72`
and the same guest policy bits. A different binary is a different measurement, so ticket 18's
image measured `a60effde…50b2` where ticket 14's was `06c6007a…`, and ticket 19's measures
`a234bfa3…7723` — each predicted offline from the build inputs and never read off a guest
(`predicted-measurement.txt`, `manifest.txt`).

### Ticket 18, on the image measuring `a60effde…50b2`

The set the build emitted lists no `policy_digest` and its own digest is `c7294dec…e1b4`, the
number every guest carrying that stock set printed at start. There was no `policy.json` on those
config devices: a guest's policy was the set it held.

| scenario | what the consoles say |
|---|---|
| `live` | ticket 14's run, unchanged except that both guests now carry a version 3 document. Both print `policy digest c7294dec…e1b4` and each reports one unconstrained value, since the emitted set names no peer policy. Tunnel established, exchanges in both directions, `EXIT status=0` on both, 1,521 frames through the relay and no plaintext in any of them. Ten passes over 300 s, of which one cost a verification. |
| `policy-pinned` | A's set names B's digest and no other: `D_A = 4f6ba312…0a40`, `D_B = c7294dec…e1b4`, B's own value unconstrained. Both guests printed the digest of the document on their own config device; B reported exactly one unconstrained value and A none. Neither refused the other, the tunnel was established and exchanged over, both `EXIT status=0`, no plaintext on the wire. Cold establish 294.168 ms. |
| `policy-mismatch` | `D_A = 8bf8b2a3…cf0b`, `D_B = 85c03a82…f1e7`, and B's value names `4ece5584…35d6` = sha256 of the ASCII string `not the policy guest A presents`, which is the digest of no document at all. Both guests dial. A admits B — `PEER SEEN … times=57`, and A refuses nothing. B refuses A 116 times with `REFUSED verification refused: guest policy or policy digest not permitted by the reference value: peer presents policy digest 8bf8b2a3…cf0b; no reference value for the measurement it is running lists that policy`. No tunnel in either direction, both `EXIT status=2`, nothing exchanged either way, and the relay found no plaintext in 2,225 frames. |

The two dial counts are worth reading together with the two refusal counts. A's exercise
failed after 57 attempts with `CRYPTO_ERROR 0x12a (remote): tls: bad certificate` — a refusal
the peer sent — and B's after 59 with `CRYPTO_ERROR 0x12a (local): attest: verification
failed`, its own. B verified A's evidence 57 + 59 = 116 times because it is the party that
judges A in both directions, while A only ever reached B's certificate on its own 57 dials:
TLS 1.3 puts the server's certificate first, so B refuses and aborts before A is asked for
anything.

That run is 96 assertions and no failures (`evidence/ticket18/tunnel-run.txt`), with
`relay-selftest.sh`'s 5 of 5 as the control on the relay. `policy-pinned` is the positive
control between the plain `live` run and the refusal, and `policy-mismatch` carries its own
local control in that A admits B on the same handshake B refuses A on, so the wiring is
demonstrably intact at the moment of the refusal.

### Ticket 19, on the image measuring `a234bfa3…7723`

The set the build emitted lists no `policy_digest`; the policy it emitted beside it forwards to
the image's own measurement and its digest is `ee222553…de74`. The `mutual` scenario authors four
documents of its own with the image's author key, and both config devices carry a set and a
policy.

| scenario | what the consoles say |
|---|---|
| `mutual` | `D_A = ee222553…de74`, `D_B = 5410bc5b…abe3`. A's value names `D_B` and no other; B's value names `D_A` and no other; neither guest reports an unconstrained value. Both guests printed the digest of the policy on their own config device and one `policy forward_to` line per measurement in it. Both dial. **Both admit each other** — `PEER SEEN … times=2` on each console, `PEERS verifier_calls=2 accepted=2 refused=0` on each, and neither guest logged a single `REFUSED`. Tunnels established in both directions, warm and concurrent exchanges both ways, `answered_by="guest-b"` on A's console and `answered_by="guest-a"` on B's, `EXIT status=0` on both. Ten passes each over 300 s, of which one apiece cost a verification. 2,975 frames through the relay, 368,719 bytes, and no plaintext in any of them. Cold establish 76.624 ms on A and 251.632 ms on B. |

The two digests differ because the two policies do, and they differ in the only way that is also
true: `policy-a.json` forwards to the image's measurement, `policy-b.json` forwards to that and
also to `7426bf87…ea5b`, which is sha384 of the ASCII string `an image this sandbox would also
dial, which nothing on this segment boots`. It is a launch measurement of the right width naming
no image anybody has, so guest B's policy is a different document from guest A's while both still
say the true thing about this segment: each guest will dial the image the other is running.
Guest A's policy is byte-identical to the one the image build emitted, which is why `D_A` is the
image's own policy digest.

`D_A` and `D_B` were each written by `emit-refvals`, read back off the delivered document by
`emit-refvals -digest-of`, and read a third time off the console of the guest holding it — the
three-way agreement the harness asserts for every document it authors, now on the policy rather
than on the set. The run is 41 assertions and no failures (`evidence/ticket18/mutual/tunnel-run.txt`),
with `relay-selftest.sh`'s 5 of 5 as the control on the relay
(`evidence/ticket18/mutual/relay-selftest.txt`). Unlike ticket 18's run this one has no separate
positive control, and does not need one: `mutual` *is* the positive result, and every assertion
about a refusal in it is an assertion that there was none.

## What the ticket 18 run found, and what was done about it

**A sandbox's policy was its own signed set, so two peers could not both pin each other: A's set
would have to name the digest of B's set while B's named the digest of A's, and each digest is
taken over a document that would then already have to contain it.** Nobody can author that pair,
on that design or on any other that makes a policy the digest of the document stating it.
Constrained admission was therefore one-directional per pair — one side pins, and the entry the
other side holds is unconstrained, which is exactly what `policy-pinned` is and why the
unconstrained line on B's console is the price of it. A pair in which *both* entries name a
digest could only ever name at least one digest nobody presents, so `policy-mismatch` was not one
scenario among many: it was the shape of every fully constrained pair, and it admits nothing in
either direction. That is why the ticket's own sentence, "B dials A and is admitted", is a
statement about A's verdict on B's evidence and not about a connection. A admits B, B refuses A,
and the handshake carrying both fails.

**That finding is the whole reason for the split.** The cycle is not a bug in the format; it is
what happens when one document has to be both the thing whose digest is fixed and the thing that
names other digests. Ticket 19 takes the policy out into a document that names no digests at
all — measurements only — so the two digests in a pair are fixed independently and neither has
to exist before the other. The `mutual` scenario is that pair, running: both entries name a real
policy, neither is unconstrained, and both sides admit. Nothing else about the design moved. The
binding, the payload, the check and its position in the order are exactly what ticket 18
shipped.

**The `PEERS` counter counts the vendor seam, which is below the policy check.** `cmd/tunneld`
wraps `attest.Verifier` — step 3 — with a recorder, and the policy digest is checked at step 4
on the certificate payload, not in the report. So guest B's console read `PEERS
verifier_calls=116 accepted=116 refused=0` in the scenario where it refused every one of those
peers: what `accepted` means there is that A's evidence was genuine, its image was the one B's
set names and its platform was above B's floor — everything the platform can vouch for was
right. The harness therefore does not assert that the counter reports refusals. It asserts
that B's verification count equals its policy refusal count and that its accepted count equals
both, which is the positive statement that the policy and nothing below it was what refused.
`modified` and `tcbfloor` in ticket 14 are the contrast: there the same counter does report
refusals, because what was wrong was something the reference value set could see. The
`forward_to` check sits one step further out still — above `attest.Verification` entirely — so
it is invisible to the counter for the same reason and more so.

**Cold establish figures are one figure each, and ticket 14's caveat applies to all of them.**
Ticket 18's `policy-pinned` cost 294.168 ms from the first dial after a cold boot, and ticket 14
measured that same handshake anywhere between 16.312 ms and 252.785 ms with the attestation work
identical in all of them; what differs is address resolution, what the transport retransmitted,
and what else the host was doing. No run here outlives the fifteen-minute maximum age, so there
is no second cold figure with nothing but attestation behind it, and none of these numbers
should be quoted as the cost of verifying a policy. What the policy check adds is a 32-byte
comparison against a list already in memory, and what `forward_to` adds is a walk of a list with
one or two entries in it.

## What the version bumps cost

Every bundle recorded under `docs/snp` predates binding v2, and a recording whose report data can
no longer be recomputed is a recording nobody can check again. So `BindingContextV1` stays
exported and still hashes two inputs rather than three, and `verify-evidence` gained
`-binding-version` (default 2) to judge those bundles. Asking for a policy digest at binding
version 1 is an error rather than a silently ignored flag, since a v1 binding covers no policy
and pretending otherwise would compute bytes no platform ever echoed.

Recorded documents no longer load. `evidence/ticket14/reference-values.json` is format version 1
and `evidence/tdx/refvals/reference-values.v20260826.json` is version 2; ticket 18's own four
recorded sets, under `evidence/ticket18`, are version 3 and are refused by the loader ticket 19
ships. The tests that read the first two re-author them in process under a test key and say so.
Nothing was regenerated to hide any of it, and the live guests are unaffected because the image
build emits their documents every time it builds an image.

`attest/tsm/tsm_test.go` changed by two lines in ticket 18: its binding fixture claims v2 and
carries a digest, because the control test at the end of that file drives `Verification` and
would otherwise be refused for speaking a version this verifier dropped. What package `tsm` does
is unchanged — the acquirer writes the 64 bytes it is handed and reads back what the platform
echoed — and no production file under `attest/tsm/`, `pkg/` or `runsc/` was touched by either
ticket.

## Running it

```sh
export PATH=$PATH:/usr/local/go/bin
cd attest && GOPROXY=off go test ./... -count=1

# a bundle recorded before ticket 18, judged as what it is
go run ./cmd/verify-evidence -binding-version 1 -evidence <bundle> -refvals <set> ...
```

The live half needs the operator's runner, once, in a tmux session, exactly as ticket 14:

```sh
sudo bash docs/snp/root-runner.sh        # in the primary checkout, not a worktree
```

Then, unprivileged. The image directory is per ticket, because a second image run into the first
one's directory would overwrite a record of a different measurement, and the author key is named
explicitly because `package-tunneld.sh` clears its own working directory and would otherwise
generate a fresh one — which would move the measurement for a reason that has nothing to do with
the code:

```sh
export STACK=<primary checkout>/.scratch/attested-secure-tunnel/host-stack
OUT=$STACK/image-ticket19 AUTHOR_KEY=$STACK/image-ticket14-packaging/author.key \
    docs/snp/image/package-tunneld.sh   # guard, build, measure, emit both documents
IMAGE=$STACK/image-ticket19 docs/snp/relay-selftest.sh
IMAGE=$STACK/image-ticket19 docs/snp/tunnel-on-two-guests.sh -run-for 300 \
    -scenario mutual -capture <somewhere>
```

`-capture` writes one directory per scenario plus the transcript and the image's own records.
The ticket 19 run was captured into a scratch directory and its `mutual/` contents copied flat
into `docs/snp/evidence/ticket18/mutual/`, so that ticket 18's three recorded scenarios and its
own transcript are left exactly as that run produced them.

`PEER_POLICY_DIGEST` on `build-image.sh` puts a peer's digest into the image's own emitted set,
and `FORWARD_TO` puts measurements into its emitted policy; the ticket 19 image was built with
neither, so its set is unconstrained and its policy forwards to the image's own measurement,
which is what lets two guests booted from it call each other. The `mutual` scenario authors its
own four documents with the image's author key.

## What this does not establish

- **Anything in a cloud.** Both guests are on this host, one chip, one certificate chain,
  exactly as in ticket 14 and with the same consequences: nothing here exercises two platforms
  or a network between two hosts.
- **A TDX peer presenting a policy on real hardware.** The second vendor is unit tests over
  the fake TDX platform and the recorded quotes. No TDX guest has ever presented a policy
  digest, and the acquirer's two SEV-SNP-only shortcuts still live where ticket 17 left them.
- **That the egress section does anything.** `unattested: false` is required, refused when
  permissive, and covered by the digest a peer checks — but no code stops a sandbox sending
  traffic anywhere. Until the section grows into a netfilter allow-list and something enforces
  it, it is a statement the author signed and the verifier checked, not a control.
- **That `forward_to` stops traffic at the network layer.** It stops this tunneld dialing a peer
  whose image its policy does not name, which is a refusal at the handshake and is tested in
  both the live run and the unit tests. It is not a filter: a sandbox with another way onto the
  network is not constrained by it, which is the same gap the egress section has.
- **A policy that changes under a live tunnel.** No run here outlives the maximum age, so
  nothing shows a peer being re-verified against a policy that moved after it was admitted.
- **Key custody.** The reference value author key is still the throwaway ticket 14's packaging
  script generated, and both guests' sets and both policies are signed with it.
