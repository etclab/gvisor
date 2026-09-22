# Pushing a policy over the tunnel

Ticket 22, the other half of `docs/sandbox-contract.md`. A sandbox's contract has always had a
verb for a pushed policy; nothing pushed one. This is what does: after a tunnel is established
— which is to say after both sides have judged the other's evidence — the delegator sends the
policy on it and waits, and the peer's tunneld hands it to the sandbox beside it and answers.
Nothing was added to the wire. Nothing under `pkg/` or `runsc/` changed. An exchange that is not
a policy is byte-identical to what it was before this existed.

**In one sentence:** a policy is trusted for having arrived over a tunnel whose far end was
already admitted, so it needs no signature of its own — and because the tunnel is what carries
that trust, a peer that will not apply it is refused as `PolicyNotApplied` and the tunnel is
closed, before any stream or exchange has run over it.

Spike **E2** (`docs/snp/evidence/ticket22/spikes/E2/`) is what this stands on: one unchanged
framed `Exchange` carries a push and its acknowledgement in 0.83 ms at the median for a 2 KiB
policy on loopback, 64 KiB and 1 MiB blobs pass too, and the 16 MiB framing bound is nowhere
near the size of a policy. It also recorded the construction that makes a push before admission
impossible, file and line at a time, which is the section below with the test against it.

---

## The wire, message by message

A push is **one ordinary exchange**. The request is the policy; the response is the
acknowledgement.

| | bytes |
| --- | --- |
| A → B, the push | `{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}` |
| B → A, acknowledged | `{"format":"policy-ack","version":1,"ok":true}` |
| B → A, refused | `{"format":"policy-ack","version":1,"ok":false,"reason":"…"}` |

Both documents are one frame on one stream, under the framing ticket 11 fixed: a four-byte
big-endian length, the payload, end of stream, and trailing bytes are a protocol violation
(`attest/tunnel/tunnel.go:379`, `:398`). Concurrent exchanges each take their own stream, so a
push neither waits on an application exchange nor can be confused with one — E2 measured a 2 KiB
push returning its ack in 0.96 ms while a 400 ms exchange was in flight on the same tunnel.

**The format field is the routing key.** A request that parses as a JSON object whose `format`
is `policy` is a push and goes to the sandbox; everything else goes to the application handler
exactly as before (`addressedToTheSandbox`, `attest/tunneld/push.go:168`; the fork itself is
`handleFor`, `:151`, and the one call site is `attest/tunneld/tunneld.go:358`). The **version is
deliberately not part of that question**: a push whose version this side does not read is still
a push, and answering it with a refusal is the whole difference between a peer that learns its
policy did not land and a peer whose policy was quietly echoed back by an application handler.

**The acknowledgement is its own format**, `policy-ack`, because it is its own document: an
application response that happened to be JSON, or a peer that echoed the policy back, must not
read as an acknowledgement. Its version is always this side's — it says which reader wrote the
answer — so a refusal of an unknown version is still an answer the pusher can read
(`attest/tunneld/push.go:74`).

**The three refusal sentences are fixed** (`attest/tunneld/push.go:88`):

| what happened | what goes back |
| --- | --- |
| the envelope is not `policy` version 1 | `this tunneld does not read a policy of that format and version` |
| no sandbox has been attached | `no sandbox is attached to this tunneld` |
| the sandbox returned an error | `the sandbox beside this tunneld did not apply it` |

The detail behind each — which field, which version, which sandbox, which socket — stays on the
receiving side's console, in the refusal log where every other reason in the taxonomy surfaces.
What crosses is a statement about the document the peer itself wrote, which is why saying it is
not the leak the refusal taxonomy is careful about: a peer learns nothing about this side's
reference value set, its sandbox, or its machine. It learns what it has to know to act, which is
that its policy is not in force.

## What tunneld reads of a policy, and what it does not

Two fields. `sandbox.ReadEnvelope` (`attest/sandbox/policy.go:74`) reads `format` and `version`
and nothing else; `n`, `f` and `x` are unparsed by every line of code in this tree. A tunneld
that parsed a policy would be a second implementation of whatever a policy means, in the one
process that has no business holding an opinion about it — and the sandbox that eventually
enforces one will parse it against a version it declares it understands.

The envelope is read **at the boundary, before the sandbox is woken**. `Tunneld.Attach`
(`attest/tunneld/push.go:128`) wraps whatever sandbox it is given in `PolicyChecked`
(`attest/tunneld/sandbox.go:121`), so that holds whichever sandbox is beside this tunneld: the
null one in this process, or a `sandbox.Host` with another process behind it. An acknowledgement
therefore means *a sandbox has that policy* on every implementation of the contract, rather than
meaning whatever the sandbox beside a particular tunneld made of a document it could not read.

Unknown fields are ignored, which is the opposite of how this module loads its signed documents
(`attest/refvalsfile.go` refuses them) and deliberately so: there an unknown field is a
constraint the loader cannot see, and here the unknown fields *are* the policy. The version is
what stands in for the strict decode.

## Why the policy needs no signature

Because the tunnel already carries the trust a signature would.

The tunnel exists only because this side judged the peer's evidence against its own reference
value set and the peer judged this side's; both verdicts are bound to the keys TLS proved
possession of (ADR-0002's amendment). A signature on the policy would be the pushing operator
saying a second time what the pushing guest's measurement already said, in a document that
cannot be about this exchange — and it would need a second authorising key, a second loader and
a second revocation story, all to re-answer "may this peer tell me anything at all", which
admission answered.

What is **not** claimed is that a pushed policy is measured. It is in nobody's launch
measurement, and a verifier reading the peer's image cannot see it. That is why the egress
ceiling went the other way in the same ticket: the ceiling is compiled into the measured image
and its digest is what every guest presents (`attest/ceiling`, ADR-0008), so what a verifier can
check remains checkable, and a push narrows behaviour within a bound that was measured. A push
cannot widen it, because a pushed policy reaches a sandbox and never the netfilter rule set.

The honest statement of the trust, then, is: **a policy is as trustworthy as the peer that
pushed it, and the peer is exactly as trustworthy as its evidence made it.** A host that
rewrites the *receiving* guest's config device cannot inject one — there is no policy on that
device any more (`attest/cmd/tunneld/main.go`, "policy.json is not on that list"), and the push
arrives inside the tunnel.

What a host can do is choose what the *pushing* guest pushes. The document `-push-policy` names
is read off that guest's config device, which is outside its launch measurement, and the live
run does exactly that: `/config/push-policy.json`, deliberately not `policy.json`
(`docs/sandbox-contract-on-hardware.md`). That is not a hole in the argument, it is the
argument — what the receiver trusts is the pusher's evidence, and a verifier reading the
pusher's image learns its ceiling and not its delegation.

## PolicyNotApplied, and when the tunnel closes

`attest.ReasonPolicyNotApplied` (`attest/refusal.go:109`) is the tenth reason in the taxonomy and
was, until ticket 26, the only one that is not a verdict on evidence. Every reason before it is
reached inside a handshake, by a verifier holding a report against a reference value set. This
one is reached after the handshake succeeded, and no `attest.Verifier` can return it.

It is reached on **both sides of the same event**:

| side | when | what it does |
| --- | --- | --- |
| the receiver | the envelope is unreadable, no sandbox is attached, or `Apply` returned an error | logs the refusal, answers `ok:false`, closes the tunnel (`refusePush`, `attest/tunneld/push.go:216`) |
| the delegator | the ack says `ok:false`, is not a `policy-ack` version 1, is not JSON, or does not arrive inside `PushTimeout` | logs the refusal, closes the tunnel, returns the refusal to its caller (`makePush`, `:316`) |

Closing is the point. A peer whose policy did not land is a peer whose next stream would run
under a contract neither side holds; carrying that stream would make the push advisory, which is
the shape this design refuses everywhere else. The delegator's caller gets an
`*attest.Refusal` — `errors.Is(err, attest.ErrRefused)` holds and `attest.ReasonOf(err)` is
`ReasonPolicyNotApplied` — and the operator gets the line on the console, which is where the
detail lives.

**The refusal is written before the tunnel goes.** `Conn.Serve` sends a handler's answer after
the handler returns, so a connection closed inside the handler would take the answer with it and
the peer would learn only that its tunnel died. The close is therefore scheduled
`pushRefusalGrace` = 100 ms out (`attest/tunneld/push.go:103`). Nothing rests on the grace being
long enough: a pusher that gets no answer refuses its own push for the same reason and closes
its side too, which is the same outcome by the other route.

**A refusal is not cached.** The tunnel is gone, so the next ask dials a new one, re-attests, and
pushes again. Two peers that disagree about a policy therefore burn one handshake per attempt
and carry nothing — visibly, on both consoles — rather than settling into a quiet half-state.

## PolicyNotLive, the eleventh

`attest.ReasonPolicyNotLive` is ticket 26's, and it is the second reason reached after a
handshake succeeded. The two are answers to different questions asked at different times: the
tenth is *did the policy land*, the eleventh is *is it still in force*. A peer refused for the
eleventh did nothing wrong at the push, and an operator reading the two on one console should
not have to guess which happened, which is why it is a reason of its own and not a detail on the
tenth.

It is reached on **one** side only, unlike the tenth:

| side | when | what it does |
| --- | --- | --- |
| the receiver | the sandbox beside it — the one that acknowledged — stops pulsing, pulses another policy's digest, or closes its socket (`docs/sandbox-contract.md`, *Liveness*) | logs the refusal and closes the tunnel (`watchLiveness`, `attest/tunneld/push.go`) |
| the delegator | — | nothing. Its push was acknowledged; all it ever learns is that its stream ended |

**Nothing new crosses the wire for it.** There is no message that says "your policy lapsed", and
adding one would be telling a peer about the inside of this guest. What the peer sees is what it
sees for every refusal after admission: its tunnel went, and its next stream fails. The reason
is on the receiving side's console, in the same refusal log, exactly as the tenth is.

**Only a sandbox in another process is watched.** The optional interface is implemented by
`sandbox.Host` alone, so a tunneld whose sandbox is in its own process carries its tunnels
exactly as it did before, and every recorded scenario that runs the null sandbox in process is
unchanged.

## The ordering guarantee

> Nothing reaches a peer before that peer's sandbox has applied the policy: not a stream, not an
> exchange, not a byte.

Enforced in one place. `Tunneld.admitted` (`attest/tunneld/tunneld.go:423`) takes the tunnel out
of the cache — dialing, attesting or re-attesting as the cache sees fit — and then runs the push
before it returns the connection. Everything that reaches a peer goes through it:

| caller | path |
| --- | --- |
| `Tunneld.Peer` | builds the channel, then asks it for its tunnel (`tunneld.go:400`) |
| `Channel.Exchange`, `Channel.OpenStream` | `tunnelTo` → `admitted` (`tunneld.go:518`) |
| `Tunneld.Open`, the sandbox contract's verb | `Peer` then `OpenStream` (`attest/tunneld/sandbox.go:62`) |

So there is no way to hold a stream to a peer whose sandbox has not acknowledged, short of
holding one from before — and there is nothing before, because `admitted` is where a tunnel
first reaches a caller.

**Once per tunnel, not once per peer.** The push is remembered in a `pushBook`
(`attest/tunneld/push.go:245`) keyed by the `*tunnel.Conn`, not by the peer's name or address. A
second `Open` on a live tunnel pushes nothing; a tunnel that was lost, or that reached its
maximum age and was re-attested, is a new connection and a new push. That is the right grain: a
re-attested peer is a peer judged afresh, and a policy the tunnel before it applied is not a
fact about this one.

**Racing callers share one push.** The book's entry is a promise — `onePush`, a channel and an
error (`:255`) — made by whichever caller arrived first and waited on by everyone else
(`pushPolicy`, `:292`). Eight concurrent `Open`s on a fresh tunnel make one push between them
and all eight wait for it. Dead connections are dropped from the book as new ones are entered,
the way the accepted list is.

**The deadline is enforced by the pusher.** `Conn.Exchange` takes a context for opening its
stream and then reads the response without one, so a peer that accepts a push and never answers
would hold the caller until the tunnel died of idleness — a minute of a sandbox waiting for a
stream. `exchangePush` (`:336`) waits on the answer or on `PushTimeout`, whichever comes first,
and the goroutine it leaves behind ends when the connection is closed, which every failure does.
`DefaultPushTimeout` is 10 s (`:236`): not a performance number — E2 measured the round trip at
0.83 ms — but the bound that turns a peer which never answers into a refusal this side reaches
on its own.

## A push before admission is impossible

Not prevented: impossible, by construction, and the construction is E2's table. A push is an
exchange on a `tunnel.Conn`; `Conn`'s fields are unexported and its only constructor `newConn`
is unexported (`attest/tunnel/tunnel.go:453`); `newConn` is called from exactly two places, the
listener after `answerEstablishment` returned and `Dial` after the QUIC handshake in which ratls
judged the peer; early data is refused (`Allow0RTT: false`, `quic.DialAddr` rather than
`DialAddrEarly`), so no stream can precede the handshake; and `Cache.Get` hands out only what
`Dial` returned.

`TestAPushBeforeAdmissionIsImpossible` (`attest/tunneld/push_test.go`) is the assertion: with B's
set not admitting A's image, A's `Open` returns `ErrNotEstablished` and `attest.ReasonOf` on it
is `ReasonNone` — **not** `PolicyNotApplied`, which would be a claim about a peer nobody
reached — and B's sandbox was handed nothing at all. The other half of the construction is the
manufactured channel: `&tunneld.Channel{}` compiles, reaches no peer, and refuses with
`ErrNoTunneld` rather than dereferencing the tunneld it has not got
(`TestAChannelNoTunneldMadeRefusesRatherThanPanicking`, `attest/tunneld/sandbox_test.go`).

## Where the policy comes from, and where it goes

`tunneld -push-policy FILE` (`attest/cmd/tunneld/main.go:190`). The file is read once at startup
and its envelope is said out loud before any peer is dialed:

```
tunneld: push policy /config/delegation.json: format=policy version=1 bytes=69 sha256=8c1062e8…
```

That line is half a claim; the other half is the peer's, and they are the same number or the
push carried something else:

```
tunneld: SANDBOX applied format=policy version=1 bytes=69 sha256=8c1062e8…
```

`loadPushPolicy` (`main.go:522`) refuses a file that is not a JSON object, and one whose format
is not `policy` — the format is what tells a push from an ordinary exchange, so a document with
another one would reach no sandbox at all. It does **not** check the version against this
build's: which versions may be *applied* is the receiving peer's question and its tunneld answers
it. No flag is no policy and no push, which is what every scenario recorded before ticket 22
runs, and is why those recordings still mean what they meant.

On the receiving side, the sandbox a push goes to is whichever one the command attached
(`attachSandbox`, `attest/cmd/tunneld/nullsandbox.go:70`):

| how the command was started | who applies a pushed policy |
| --- | --- |
| no `-sandbox-socket` | the in-process null sandbox, which records format, version, length and SHA-256 and enforces nothing |
| `-sandbox-socket PATH` | `sandbox.Host`, which sends `APPLY` down the unix socket and returns the attached sandbox's answer — or refuses the push when nobody is attached |

Both go through `PolicyChecked`, so the envelope is read at the boundary either way.

One consequence for the figures a recorded run prints: the exercise establishes by asking the
contract for a stream, so with `-push-policy` set its `kind=establish` line covers the handshake
*and* the push round trip, which E2 measured at 0.83 ms for a 2 KiB policy against tens of
milliseconds for an establishment. Without the flag nothing is pushed and the figure means
exactly what it meant before, which is why every scenario recorded under `docs/snp` still reads
the way it was written.

## What proves it

Every test is offline, on the loopback harness with the fake platform injected through `Config`
(`attest/tunneld/tunneld_test.go`, `start`).

| claim | test |
| --- | --- |
| a request that says it is a policy reaches the sandbox, is acknowledged, and does not reach the application handler — and an ordinary exchange on the same tunnel still does | `TestAPushedPolicyReachesTheSandboxAndIsAcknowledged` |
| the three ways a push does not land — the sandbox refuses it, the version is not one this tunneld reads, no sandbox is attached — each answer `ok:false` with their own sentence, log `PolicyNotApplied`, and close the tunnel under a stream that was already open on it | `TestAPushTheSandboxRefusesClosesTheTunnel` |
| a version 2 document never reaches the sandbox: it is refused at the boundary | same test, second case, asserting the sandbox was handed nothing |
| A opens to B, B's **null** sandbox acks, A gets a stream, and B's console carries `SANDBOX applied` with the digest of exactly the bytes A pushed | `TestNoStreamIsHandedOutBeforeThePushIsAcknowledged` |
| from the delegator's side: a refusal, an unknown version and an unacknowledged push are all `PolicyNotApplied`, no stream is handed out, and the next `Open` re-dials and pushes again | `TestAPeerThatWillNotApplyThePolicyIsRefused` |
| nothing reaches a peer before its sandbox applied the policy: B records `applied, exchange, stream` in that order, and one tunnel is one push | `TestNothingReachesAPeerBeforeItsSandboxAppliedThePolicy` |
| a tunnel past its maximum age is a new tunnel and is pushed to again | `TestAFreshTunnelIsPushedToAgain` |
| eight concurrent `Open`s on a fresh tunnel make one push and all wait for it | `TestConcurrentOpensShareOnePush` |
| a push before admission is impossible: a refused peer yields the admission refusal, not `PolicyNotApplied`, and no push attempt at all | `TestAPushBeforeAdmissionIsImpossible` |
| a push reaching a socket-attached sandbox goes through `Host.Apply` and comes back as that sandbox's answer | `TestAPushReachesASandboxInAnotherProcess` |
| tunneld checks the envelope before the sandbox sees the policy | `TestTunneldChecksTheEnvelopeBeforeTheSandboxSeesThePolicy` (`sandbox_test.go`) |
| the last two reasons each have a sentence of their own and no verifier can return either | `TestEveryReasonInTheTaxonomyHasASentenceOfItsOwn`, `TestNoVerdictOnEvidenceIsAReasonReachedAfterAdmission` (`attest/taxonomy_test.go`) |
| every reason in the taxonomy, the eleventh included, has a test that refuses a tunnel for it | `TestEveryReasonInTheTaxonomyRefusesATunnel` (`attest/tunneld/refusal_test.go`) |
| a sandbox that stops pulsing, pulses another policy's digest, or whose workload exits closes the tunnel the policy arrived on, as `PolicyNotLive`, under a stream already open on it | `TestASandboxThatStopsEnforcingAPushedPolicyClosesTheTunnel` (`attest/tunneld/liveness_test.go`), one case each |
| a tunneld whose sandbox is in its own process is not watched, and its tunnel stands | `TestASandboxInThisProcessIsNotWatched` (same file) |
| the pushing side is untouched: its push was acknowledged, it refuses nothing, and all it learns is that its stream ended | asserted in every case of the first of those two |
| the policy to push is read, refused if it is not one, and said out loud with its digest | `TestThePolicyToPushIsReadAndSaidOutLoud` (`attest/cmd/tunneld/main_test.go`) |

`go test ./... -count=1` in `attest/` passes, `go vet ./...` is clean, `gofmt` is clean, and the
push paths pass under `-race`. The two guard tests in `attest/cmd/tunneld` are unchanged and
still hold: the measured binary reaches no fixture, no fake platform and no `testing`.

`ripwire attest --quality-delta=e2fd17f26..HEAD` reports `gating="0"`. It reported 32 gating
rows first, and four fixes took it to 17 before anything was acked: the ack's marshalling folded
into one site so that `applyOrRefuse` returns the sentence and `applyPushed` writes the
document; `start` grew a variadic hand on the configuration instead of a second starter beside
it; `Peer` now establishes by asking the channel it is about to return for its tunnel, so there
is one path to a tunnel rather than two that looked alike; and the push timeout resolves once in
`New` the way the limits do. The 23 acked rows are in `attest/.ripwire_quality_acks` with the
reason: 17 are line counts that follow from documenting a tenth refusal reason in a const block
whose line count is every constant's, and 6 are idiom collisions between one mutex-guarded
accessor and another across package boundaries neither side may cross. What is left unacked is
non-gating and deliberately visible — the dead-code rows every new test function produces, and
two helpers one parameter over the bar.

**Ticket 21's replay harness passes unchanged**: the 64 live verdict invocations
(`docs/snp/evidence/ticket21/harness/verdict-invocations-v2.txt`) replayed against an
`attest-tool` built at this branch tip are byte-identical from line 2 onward to the same list
replayed at `e2fd17f26`, and the exit-status histogram is the same (8 / 15 / 37 / 4). The tenth
reason changed no verdict, because no verdict on evidence can reach it.

## What proves it on hardware

Everything above is offline, on the loopback harness. `docs/sandbox-contract-on-hardware.md`
is the same thing on two SEV-SNP guests: guest A pushes a version 1 policy at guest B over a
tunnel both sides attested, B's null sandbox applies it and A is handed a stream only then;
a second run pushes version 2, B refuses it at the boundary without waking a sandbox, and the
tunnel goes with the refusal. The digest A printed before it dialled and the digest B printed
when it applied are the same number, on two consoles. The recorded run is
`docs/snp/evidence/ticket22/`.

## What is not built

- ~~**Nothing enforces a pushed policy.**~~ Built, in ticket 26: the sentry narrows the name table
  it already holds to what `n` says, while the workload runs, and refuses an `execve` of anything
  `x` does not name, with `f` read for the subset check and still approximated by the read-only,
  locked, noexec mounts rather than enforced atom by atom (`docs/policy-in-the-sentry.md`). Ticket
  27 made the acknowledgement mean that the sandbox which will enforce the policy has it
  (`docs/the-ack-means-the-sandbox.md`). Under all of it, the netfilter ceiling the image carries
  and the reference value set that admits a peer at all are what they were.
- **One policy for every peer.** `Config.PushPolicy` is one document, not a table keyed by peer
  name. Per-peer delegation is what that field becomes when something needs it; a second peer
  table with no test behind it would not be.
- **No ordering between two pushes.** One tunnel carries one push, so the question does not
  arise today — and a live tunnel still carries exactly one. Ticket 26 did not change that: it
  made "which policy is in force" a question the sandbox answers once a second for the one push
  its tunnel carried, not a way to carry two. Two peers pushing two different policies at one
  sandbox produce two watches and at most one of them can match, which is the honest answer to a
  question the contract never promised.
- ~~**A tunnel outlives the policy it pushed.**~~ Built, in ticket 26: the far sandbox says which
  policy it is enforcing once a second, and a tunnel whose sandbox has stopped is closed as
  `PolicyNotLive`. See above, and `docs/sandbox-contract.md` for the constants and what they cost.
- **The push is not measured and does not claim to be.** See "Why the policy needs no
  signature". A verifier reading a peer's image learns the ceiling, not the delegation.
