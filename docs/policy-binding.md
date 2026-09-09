# A policy bound into the evidence

Ticket 18. A sandbox's policy is its own signed reference value set; its digest is folded into
the hardware evidence under ADR-0002's binding version 2, and every verifier checks that
digest against a per-entry allow-list of measurement and policy pairs before it recomputes the
binding. All of it lands above the vendor seam: neither `verify/snp.go` nor `verify/tdx.go`
changed, and nothing under `attest/tsm/`, `pkg/` or `runsc/` did either. It builds on ticket
14 (`docs/two-guests-on-hardware.md`), whose image and harness this run rebuilds, and on
ticket 17 (`docs/tdx-verifier.md`), whose vendor-tagged document is the version this one
extends. Proven live once, on that harness's two SEV-SNP guests. No cloud, no TDX hardware.

**In one sentence:** two guests booting one measured image, differing in nothing but which
policy digest their reference value names, admit and refuse each other exactly as their sets
say — and what the ticket found is that the most constrained pair this design can express is
one that admits nothing in either direction, because the policy a set names is the digest of a
document that would have to contain it.

---

## What was built

**The document is a policy** (format version 3, `attest/refvalsfile.go`). A reference value
set gains a required top-level `egress` section — `{"version": 1, "unattested": false}` — and
that is what makes the file a statement about behaviour rather than only a guest list. Both
fields are required: a document that does not say whether unattested egress is permitted has
not said it is forbidden, and a loader supplying the answer would be deciding policy on the
author's behalf. A document claiming `"unattested": true` is refused on load, because nothing
here enforces permitting it and a digest a peer vouches for should not vouch for a promise no
code keeps. The section versions separately from the document, since ticket 19 is what grows
it. Version 2 documents are refused with a sentence saying to add the section and sign again —
the same treatment version 1 got for its missing vendor tag, and for the same reason.

**Its digest is over the signed bytes** (`attest.PolicyDigestOf`). A policy digest is SHA-256
over exactly the region the author's signature covers: the domain separation prefix and the
document. It names what somebody authorised rather than what is on disk, and the consequence
is worth saying out loud because it would otherwise be discovered by hand — `sha256sum
reference-values.json` is a different number and the wrong one. `emit-refvals -digest-of PATH`
exists so that nobody computes it another way; it needs no key and does not load the set.

**The binding carries it** (ADR-0002's amendment, `attest/binding.go`). `report_data` under
binding context v2 is `SHA-512(pubkey ‖ ctx ‖ policy_digest)`, where `ctx` is version byte
`0x02` and fifteen zero bytes. The context is the same sixteen bytes wide it always was: the
digest travels *beside* it in the certificate payload rather than inside it, because widening
the context would move a byte a v1 reader already reads. The payload is version 2 for the same
reason, and its new field is `OPTIONAL` for exactly one: a v1 payload is five fields where
this reader wants six, and it must parse far enough to be refused on its version rather than
complained about as DER. `ratls.NewIdentityForContext` is still the seam a later version grows
through — ticket 18 is only its first caller to pass something other than the zero context.

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

**What an operator does.** A tunneld loads one set, which is both the guest list it enforces
and the policy it presents, and prints that set's digest at start on the serial console, the
only diagnostic surface a measured guest has (user story 48):

```
tunneld: policy digest c7294dec…e1b4 (sha256 over the signed reference value set; put it in a
peer's policy_digest)
```

That number is what goes into a peer's `policy_digest`. `emit-refvals -policy-digest` writes
one into a set, `build-image.sh` takes `PEER_POLICY_DIGEST` and records both the emitted set's
own digest and the peer policy it admits in the image manifest, and `verify-evidence` gained
`-policy-digest` so a bundle can still be judged from outside the guest that produced it. The
harness does not trust any single one of them: for every set it authors it asserts that the
digest `emit-refvals` printed when it wrote the document equals `emit-refvals -digest-of` on
the document as delivered, and equals the line the guest holding that set printed at start.
Those three agreeing is the operator's workflow closed end to end.

The memo is updated where it describes any of this: `report_data`, the reference value fields,
the verification list, and open question 2 — "binding runsc's configuration to the evidence" —
which this ticket answers rather than defers.

## What the tests proved

| claim | test |
|---|---|
| a version 2 document, carrying no egress section, is refused and told what to add | `TestAVersionTwoDocumentIsRefusedAsCarryingNoEgressSection` |
| an egress section that is missing, of another version, or permissive is refused | `TestAnEgressSectionThatIsNotAPolicyIsRefused` |
| the loaded set's digest is over the signed bytes and not over the file | `TestALoadedSetCarriesTheDigestOfTheBytesItsAuthorSigned` |
| `policy_digest` survives the document, and one of the wrong shape is refused | `TestAPolicyDigestOnAValueSurvivesTheDocument`, `TestAPolicyDigestOfTheWrongShapeIsRefused` |
| a listed digest is admitted; an unlisted one refuses as `PolicyMismatch` naming what was presented; an entry listing none admits any | `TestAPeerPresentingAListedPolicyIsAccepted`, `TestAPeerPresentingAnUnlistedPolicyIsRefused`, `TestAnEntryWithNoPolicyDigestAdmitsAnyPolicy` |
| a digest swapped in flight, with both policies listed so the peer reaches the binding, refuses as `BindingMismatch` | `TestAPolicyDigestSwappedInFlightIsRefusedAsABindingMismatch` |
| a v1 context, and a v1 payload on the wire, refuse as `UnknownBindingContext` | `TestAVersionOneBindingContextIsNoLongerAdmitted`, `TestAPeerSpeakingPayloadVersionOneIsRefused` |
| the same allow-list at the second vendor, with nothing in `verify/tdx.go` knowing a policy exists | `TestATDXPeerIsAdmittedOnlyByASetListingItsPolicy` |
| genuine recorded AMD evidence over a genuine v1 binding is refused today, with the v1-speaking stand-in as its control | `TestARecordingMadeBeforeBindingVersionTwoIsRefusedAsAnUnknownContext` |
| one dialer and two listeners differing in nothing but which digest they name | `TestATunneldAdmitsAPeerOnlyIfItsSetListsThatPeersPolicy` |

Both vendors are covered, and which artefact carries which half is not the split the ticket
expected. AMD's acceptance path is `snpfake`, ticket 02's platform, which can be handed any
binding. Intel's is the fake TDX platform of ticket 17, and it has to be: the recorded quotes
were taken over fixed caller-supplied bytes, so their binding cannot be chosen and no peer
presenting a policy of its own can be built out of one. What a recording can still show is a
refusal, and it shows two — a recorded TDX quote presented with any key is a binding mismatch,
and the recorded SEV-SNP bundle from ticket 05, acquired over a real v1 binding, is now
refused as an unrecognised context with the v1-speaking stand-in beside it as the control.

## The live run

The image is ticket 14's, rebuilt around the new tunneld: same build script, same author key
`3f27c388…ec72` whose public half is inside the measurement, same TCB floor `9,0,23,72` and
the same guest policy bits. A different binary is a different measurement, so the launch
measurement is now `a60effde…50b2` where ticket 14's was `06c6007a…`, predicted offline from
the build inputs and never read off a guest (`predicted-measurement.txt`, `manifest.txt`). The
set the build emitted beside it lists no `policy_digest` and its own digest is
`c7294dec…e1b4`, the number every guest carrying that stock set prints at start.

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

The whole run is 96 assertions and no failures (`tunnel-run.txt`), with `relay-selftest.sh`'s
5 of 5 as the control on the relay. `policy-pinned` is the positive control between the plain
`live` run and the refusal, and `policy-mismatch` carries its own local control in that A
admits B on the same handshake B refuses A on, so the wiring is demonstrably intact at the
moment of the refusal. Unlike ticket 14 this list does not end with a second `live`.

## What this run found

**A sandbox's policy is its own signed set, so two peers cannot both pin each other: A's set
would have to name the digest of B's set while B's names the digest of A's, and each digest is
taken over a document that would then already have to contain it.** Nobody can author that
pair, on this design or on any other that makes a policy the digest of the document stating
it. Constrained admission is therefore one-directional per pair — one side pins, and the entry
the other side holds is unconstrained, which is exactly what `policy-pinned` is and why the
unconstrained line on B's console is the price of it. A pair in which *both* entries name a
digest can only ever name at least one digest nobody presents, so `policy-mismatch` is not one
scenario among many: it is the shape of every fully constrained pair, and it admits nothing in
either direction. That is why the ticket's own sentence, "B dials A and is admitted", is a
statement about A's verdict on B's evidence and not about a connection. A admits B, B refuses
A, and the handshake carrying both fails. Both guests dial in that scenario so the record says
so from both ends rather than leaving it to be inferred from one. The limitation is named here
and the decision left to the author; nothing in this ticket redesigns around it.

**The `PEERS` counter counts the vendor seam, which is below the policy check.** `cmd/tunneld`
wraps `attest.Verifier` — step 3 — with a recorder, and the policy digest is checked at step 4
on the certificate payload, not in the report. So guest B's console reads `PEERS
verifier_calls=116 accepted=116 refused=0` in the scenario where it refused every one of those
peers: what `accepted` means there is that A's evidence was genuine, its image was the one B's
set names and its platform was above B's floor — everything the platform can vouch for was
right. The harness therefore does not assert that the counter reports refusals. It asserts
that B's verification count equals its policy refusal count and that its accepted count equals
both, which is the positive statement that the policy and nothing below it was what refused.
`modified` and `tcbfloor` in ticket 14 are the contrast: there the same counter does report
refusals, because what was wrong was something the reference value set could see.

**Cold establish was 294.168 ms, and ticket 14's caveat applies to it.** It is one figure,
from the first dial after a cold boot, and ticket 14 measured that same handshake anywhere
between 16.312 ms and 252.785 ms with the attestation work identical in all of them; what
differs is address resolution, what the transport retransmitted, and what else the host was
doing. The `live` scenario's own first dial in this run cost 1,133.538 ms for the same reason.
No run here outlives the fifteen-minute maximum age, so unlike ticket 14 there is no second
cold figure with nothing but attestation behind it, and none of these numbers should be quoted
as the cost of verifying a policy. What the policy check adds is a 32-byte comparison against
a list already in memory.

## What the version bump cost

Every bundle recorded under `docs/snp` predates v2, and a recording whose report data can no
longer be recomputed is a recording nobody can check again. So `BindingContextV1` stays
exported and still hashes two inputs rather than three, and `verify-evidence` gained
`-binding-version` (default 2) to judge those bundles. Asking for a policy digest at binding
version 1 is an error rather than a silently ignored flag, since a v1 binding covers no policy
and pretending otherwise would compute bytes no platform ever echoed.

Two recorded documents no longer load at all: `evidence/ticket14/reference-values.json` is
format version 1 and `evidence/tdx/refvals/reference-values.v20260826.json` is version 2, and
neither carries an egress section. The tests that read them re-author them in process under a
test key and say so. Nothing was regenerated to hide this, and the live guests are unaffected
because the image build emits their set every time it builds an image.

`attest/tsm/tsm_test.go` changed by two lines: its binding fixture now claims v2 and carries a
digest, because the control test at the end of that file drives `Verification` and would
otherwise be refused for speaking a version this verifier dropped. What package `tsm` does is
unchanged — the acquirer writes the 64 bytes it is handed and reads back what the platform
echoed — and no production file under `attest/tsm/`, `pkg/` or `runsc/` was touched.

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

Then, unprivileged:

```sh
docs/snp/image/package-tunneld.sh        # guard, build, measure, emit the set and its digest
docs/snp/relay-selftest.sh
docs/snp/tunnel-on-two-guests.sh -run-for 300 -capture docs/snp/evidence/ticket18 \
    -scenario live -scenario policy-pinned -scenario policy-mismatch
```

`PEER_POLICY_DIGEST` on `build-image.sh` puts a peer's digest into the image's own emitted
set; the ticket 18 image was built without it, so its set is unconstrained and the two policy
scenarios author their own sets with the image's author key.

## What this does not establish

- **Anything in a cloud.** Both guests are on this host, one chip, one certificate chain,
  exactly as in ticket 14 and with the same consequences: nothing here exercises two platforms
  or a network between two hosts.
- **A TDX peer presenting a policy on real hardware.** The second vendor is unit tests over
  the fake TDX platform and the recorded quotes. No TDX guest has ever presented a policy
  digest, and ticket 19 is where the acquirer's two SEV-SNP-only shortcuts still live.
- **That the egress section does anything.** `unattested: false` is required, refused when
  permissive, and covered by the digest a peer checks — but no code stops a sandbox sending
  traffic anywhere. Until ticket 19 grows the section into a netfilter allow-list and enforces
  it, it is a statement the author signed and the verifier checked, not a control.
- **A policy that changes under a live tunnel.** No run here outlives the maximum age, so
  nothing shows a peer being re-verified against a policy that moved after it was admitted.
- **Key custody.** The reference value author key is still the throwaway ticket 14's packaging
  script generated, and both guests' sets — and both policy digests — are signed with it.
- **That mutual pinning is possible.** It is not, for the reason above, and this ticket only
  names it. Whether one-directional constraint is enough, or whether the policy should be a
  document other than the set that names peers, is a decision this record leaves open.
