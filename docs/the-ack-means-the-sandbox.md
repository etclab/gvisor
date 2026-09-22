# An acknowledgement means the sandbox has it

Ticket 27, on branch `ticket-27-an-ack-means-the-sandbox-has-it` over master `cea8ae91d`. It
closes leftovers 21 and 22 of `docs/policy-in-the-sentry.md`, gives `x` one meaning per
spelling, and takes the stale text out of the tree. Everything below is proved on loopback and
in unit tests. No hardware run was made and none is claimed.

## The two clients, and one enforcing client per socket

Two processes attach to one tunneld socket in a measured guest. `runsc tunnel-helper`
(`runsc/sandbox/sandbox.go:2036`) forwards a pushed policy to the sentry as `Policy.Narrow`
and pulses `alive`; it is the only client in the guest that enforces anything. The exit —
ticket 23's `socketSandbox` and `ServeExit` — hands the bytes to `sandbox.Null`, which records
a digest and enforces nothing. On master `Host.Apply` pushed to whatever was attached at that
instant, so a push landing before the helper attached was acknowledged by the exit and
enforced by nothing: leftover 21, and SEV-SNP pair 3 is what it looks like on a console.

Contract version 4 adds one message: a client sends
`{"id":0,"type":"attach","role":"enforcing"}` or `"role":"network"` first, and it is answered
only when refused (`attest/sandbox/socket.go:42`, `:94`, `:106-109`). `sandbox.Dial` takes the
role as its second argument (`attest/sandbox/client.go:75`), and the helper's copy of the
protocol sends the same message (`runsc/cmd/tunnel_client.go:63-64`, `:115`, `:133-141`).
Nothing else on the wire changed; `docs/sandbox-contract.md` documents v4.

`Host.admit` (`attest/sandbox/host.go:594-617`) refuses an attach on a closed host, an unknown
role, a second attach on one connection (`this client has already attached`) and a second
enforcing client (`a second enforcing client is not permitted on this socket`); the reader
loop refuses a stream request from a client that has not attached (`this client has not
attached`, `:717-724`), read off the one-way `declared` flag at `:525` rather than by taking
the host's lock. A refusal is sent as an `error` message, logged, and the socket closed
(`:573-585`).

## The acknowledgement waits

`Host.Apply` (`attest/sandbox/host.go:189-236`) pushes to the enforcing attachment and to
nothing else (`enforcing()` at `:285-293`). With none attached and a caller that can be waited
for, the push waits (`:266-312`); a context with neither a deadline nor a way to cancel is
refused at once with `ErrNoEnforcingSandbox` (`:274-277`, sentinel at `:99`); a cancellable context with no deadline is bounded end to end by
`DefaultApplyWait`, ten seconds (`:115`, `bound` at `:241-247`), over the wait for an
attachment and the wait for its answer together; a caller's own deadline is kept. `inForce`
and the `SANDBOX applied` line are written only after the enforcing sandbox acknowledged
(`:229-234`, `said` at `:331-342`), and one push slot serialises pushes and replays
(`holdPush` at `:250-259`).

### The numbers that decided it, from E1

The master-era E1 run the previous notes quoted is not in the tree. What is committed is the
re-run made on this branch, at commit `648e056da`
(`docs/snp/evidence/ticket27/spikes/E1/output.txt:4`) on 2026-09-22T00:41:47Z (`:2`), over 25
runs (`:39`) — a build that already had the fix in it. The decision to wait rests on the
window it measured being far inside the push deadline.

| over 25 runs | exit attach (role network) | runsc start to the enforcing attachment | `Host.Apply` entered to returned |
|---|---:|---:|---:|
| Min | 577 µs | 112.396 ms | 258.622 ms |
| p50 | 830 µs | 151.357 ms | 338.267 ms |
| Mean | 867 µs | 149.556 ms | 338.554 ms |
| p90 | 1.043 ms | 170.845 ms | 385.397 ms |
| Max | 1.549 ms | 176.234 ms | 397.594 ms |

All fifteen figures are `spikes/E1/output.txt:70-88`. The maximum, 176.234 ms, is a fiftieth
of the ten seconds a pushing peer already allows, so `DefaultPushTimeout` did not need raising
— the question E1 was asked. Three counts say who was in the window (`:91-93`): the push was
entered before the enforcing attachment in **25 of 25** runs, the exit was offered the
document in **0 of 25**, and the enforcing sandbox acknowledged **22 of 25**. The other three
were refused by the sentry, in its own words carried back through the helper: `the sandbox is
created and a policy is honoured only by a started one` (`:14`).

## Late-attach delivery

An enforcing sandbox that attaches after a push was acknowledged is replayed the policy in
force (`replayInForce`, `attest/sandbox/host.go:632-656`, started for every enforcing
attachment at `:587`). It takes the push slot, so it cannot cross a caller's push, and reads
`inForce` after taking it. A replay the sandbox refuses marks that attachment's claim lost and
drops it (`:650-654`).

E2 measured what a second delivery costs, on master-era code at `cea8ae91d`
(`spikes/E2/notes.md:18`) on 2026-09-21T19:05:15Z (`spikes/E2/output.txt:2`). The first
delivery to sentry A took 4.860595 ms (`:13`) and to a fresh sentry B with nothing in force
3.181803 ms (`:32`); one replay to A took 2.263784 ms (`:18`); over 50 replays min 906 µs, p50
1.252 ms, mean 1.867 ms, p90 2.838 ms, max 18.148 ms (`:22-26`). Every delivery answered
`err=<nil>` and returned the same digest,
`e1a4ddd603e1edfba4479099c174dd815534b9174c4c74ea32a08f88ad7ce3e8` (`:6`, `:12`, `:17`,
`:31`): the subset check reads a replay of the policy in force as a narrowing of itself, and
the sentry needed no change.

## What a liveness miss does with no tunnel open

The watch belongs to the sandbox attachment and outlives the tunnel the policy arrived on
(`attest/tunneld/push.go`, `livenessWatch` at `:283-295`, `watchLiveness` at `:357-382`). On a
miss, a mismatch or a close: with a tunnel still open it is closed and the peer refused under
`ReasonPolicyNotLive` (`:371-373`); with none open the refusal says `no tunnel was closed
because none was open` (`:375-376`); either way the enforcing attachment is dropped and
nothing is left in force (`:378`, `DropEnforcing` at `attest/sandbox/host.go:419-432`).

Three things keep that from firing on a lawful change: the watch is retired before the next
policy is pushed, because a sandbox that takes a policy pulses that policy's digest
(`applyOrRefuse`, `:233`); it goes back on only where there is still something to watch, which
`errors.Is(err, sandbox.ErrNoEnforcingSandbox)` decides (`:241-243`); and a watch that has
fired is spent (`fired` at `:294`, `startWatch` at `:300-303`). Received pushes are serialised
under `applyMu` (`:220`), and `Host.Watch` says `no attachment has acknowledged this policy`
when nothing on the socket ever claimed it (`attest/sandbox/host.go:375`).

E3 measured the defect, not the fix. It ran on master-era code at `cea8ae91d`
(`spikes/E3/notes.md:22`) with the idle timeout at its 60 s default and a 62 s wait
(`spikes/E3/output.txt:7`, `:9`). The host's watch saw the loss both ways — `the sandbox
closed its socket` after 250.403818 ms when the workload was killed (`:11-12`), `it missed 3
pulses` after 3.000303968 s when it was stopped (`:25-26`) — and tunneld said nothing either
time: `Tunneld logged 0 new refusal(s)` and `Tunneld logged NOTHING: watchLiveness exited
silently when tunnel idled out` (`:13-14`, `:27-28`). A stream opened afterwards failed the
same way in both, with `tunneld: unknown peer: "b" is not in the peer table` (`:16`, `:30`).
The fixed behaviour is proved by `attest/tunneld/liveness_test.go` and by the loopback
teardown assertion, not by E3.

## `x`, in one paragraph, sent nowhere

> **What a spelling of `x` grants.** An absent `x` key leaves exec unconstrained: no exec sink
> is installed and `execve` is not checked. A present `x` is the binaries it names. An empty
> `x` list is a grant of nothing: the sink is installed with an empty allow set and every
> `execve` is refused. Absent is therefore wider than empty rather than equal to it, and the
> subset check is ordered accordingly — from a base with no `x`, any `x` a push spells is a
> narrowing, including the empty one; from a base that has one, only a subset narrows, and
> dropping the key is refused with `it widens x by unconstraining exec`
> (`runsc/boot/policy.go:476-500`). Whether the sink must be enforcing is a separate question:
> `policyNeedsSink(x, installed)` is true for any present `x` and for an absent one once a
> sink exists (`:585-587`). The set goes in before the sink is registered, because a sink
> seccheck can reach while its allow list is nil permits every exec (`:212-224`), and a
> narrowing back to no allow list at all is ignored once a set is in force
> (`pkg/sentry/policyx/policyx.go:170-179`). Four tests pin it: `TestPolicySubsetXDirections`,
> `TestPolicyExecAtomsTellsTheThreeSpellingsApart`, `TestPolicyNeedsSink`,
> `TestExecAllowOfAnEmptyXPermitsNothing`.

The definition of done asked for the distinction in `attest/sandbox/policy.go` as well, and it
is not drawn there. It cannot be: `Atoms` concatenates the three sets into one list, and the
absence of a `run:` atom is the absence of the grant, so no atom could mean "unconstrained"
(`attest/sandbox/policy.go:166`). `Atoms`, `Widening` and `CheckNarrows` (`:166`, `:303`,
`:345`) have no non-test caller, so nothing turns on the reading; it is pinned instead by a
test that names where the distinction *is* drawn.
`TestAnAbsentXAndAnEmptyXAreOneGrantOfNoExec` (`policy_test.go:236`) asserts that the two
spellings give the same atoms, that neither grants a `run:` atom, and that naming one exec
widens both. One format, two readings, and the one that governs a workload is the sentry's.
`"x":null` reads as the absent key rather than being refused (`runsc/boot/policy.go:411-413`);
that is a leftover below.

## The loopback proof

`docs/snp/evidence/ticket27/loopback/`. Ticket 26's harness —
`attest/cmd/agent-probe/governed_test.go`, `TestGovernedLoopback` — re-run with the `hold +
60` idle-timeout workaround gone and a fifth scenario added. The tunnelds are in the test's
own process with the fake SNP platform, so nothing here is evidence about attestation. It ran
three times against the same tip, `e8701aae5`, and passed each time; all three transcripts are
kept, and the evidence directory kept is the last of them, `20260921-205050/`, the other two
having been deleted to keep the record small (`loopback/notes.md:35-40`). The runsc is
`bazel-bin/runsc/runsc_/runsc`, sha256
`49740e434b42e1c1d65546258f2bcbd16134469cf8ea72190321a353daf9823c`
(`20260921-205050/README.md:3`).

| run | runsc status | wall | `Apply` at `a` | the window | what it says |
|---|---:|---:|---:|---:|---|
| off-policy | 1 | 551 ms | 161.905 ms | 2 ms | the refusal is the pushed policy's, not the table's |
| on-policy | 0 | 6.261 s | 172.024 ms | 1 ms | the workload gets through its steps under P0 |
| narrowed | 0 | 5.876 s | 3.803 / 3.713 / 2.905 ms | 188 ms | a narrowing mid-run, and a widening refused |
| killed | 137 | 665 ms | 144.259 ms | 2 ms | the teardown reached from outside |
| early-push | 0 | 6.069 s | 370.78 ms | 1 ms | an ack means the enforcing sandbox has it |

Statuses and walls are `README.md:13-17`; the `Apply` figures `:243`, `:271`, `:341-343`,
`:372`, `:417`; the windows `:251`, `:279`, `:352`, `:380`, `:425`. Every push took one
handshake.

**early-push** is the scenario the ticket is for: the pusher's document is inside `Host.Apply`
at `a` before `runsc` is started at all, the harness holding the two in that order rather than
leaving it to a goroutine (`loopback.holdStart`, `governed_test.go:228`). Five moments, from
`README.md:405-409`:

| moment | when |
|---|---|
| `Host.Apply` entered at `a` | 20:50:42.634038 |
| `SANDBOX attached on …/a.sock role=enforcing` | 20:50:42.825973 |
| `SANDBOX applied … bytes=199 sha256=db45384408fe…fdd7` | 20:50:43.004720 |
| `Host.Apply` acknowledged the push | 20:50:43.004855 |
| the pusher's `PUSH` line: `Peer` returned | 20:50:43.005616 |

The push was entered 192 ms before the enforcing sandbox attached and acknowledged 179 ms
after it (`README.md:411`), with a cold `Open` of 410 ms of which `Apply` at `a` was 370.78 ms
(`:417`). The sentry applies, the helper acknowledges, and only then does `a` write `SANDBOX
applied` and `Apply` return; what the harness asserts is the negative, that an `Apply`
returning nil before the attach fails the run (`tellEarly`, `governed_test.go:509`). The
workload then ran governed and completed, status 0 after 6.069 s with `NO-MODEL DONE
model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480 in 5.598s` (`README.md:411`).

Two assertions elsewhere changed. `tellTeardown` requires exactly one liveness loss per run
(`governed_test.go:606-611`): the sandbox goes once, and every extra loss is a refusal written
against a peer for something that did not happen. `tellNarrowed` replaces ticket 26's
assertion that the first peer's tunnel is torn down as a mismatch with the assertion that
nothing is lost between the narrowing and the workload's own exit; the single loss came
5.309 s after the narrowing (`README.md:315`). `adapter_test.go:362-368` records the other
half: tunneld `a` pushes nothing at `b`, because behind `b` is an exit, which attaches as a
network client and is never pushed a policy — one added sentence in
`docs/sandbox-contract.md` says so.

**What was not run.** The model was not called. `-without-model`
(`attest/cmd/agent-probe/agent.go`, `RunWithoutModel` at `:291`) leaves out the one step that
needs a key and nothing else: the model endpoint is requested for real over the same tunnel
with no `x-api-key` header, and every run that reached it got HTTP 401 and 141 bytes; the
document is then fetched as `fetch_url` fetches it, HTTP 200 and 20480 bytes, which is the
20 KiB cap and not the document's size (`loopback/notes.md:44-63`). The flag is explicit
rather than a fallback (`cmd/agent-probe/main.go:124-127`). `TestGovernedLoopback` needs no
key by design and none was read (`governed_test.go:285`); `TestClaudeGoverned` skips without
one (`:722-723`) and `TestAdapterLoopback` fails without one (`adapter_test.go:156-158`).
Every run's strace digest says `0 execs` (`loopback/notes.md:222`).

## The defects found on the way

1. **A resurrected watch killed sandboxes on early pushes.** `applyOrRefuse` retired the watch
    before pushing and started it again when the push did not land — and what it started again
    could be a watch that had already fired at the end of an earlier sandbox's life.
    `Host.Watch` reported the loss at once and `DropEnforcing` closed the new sandbox's
    helper; since the helper's death ends the sandbox, a push that arrived a moment early
    killed the sandbox it was pushed at. Every attempt at the proof before the three kept runs
    lost one of the five runs to it (`loopback/notes.md:183-210`). A fired watch is now spent.
2. **The wrong attachment was dropped.** `DropEnforcing` closed whichever attachment was
    enforcing when the drop arrived, so a fresh sandbox that attached inside the quarter-pulse
    a loss takes to be seen was closed for the dead one's failure. `claimLost` is now set on
    the attachment whose claim went, and one that has not lost a claim is left alone
    (`attest/sandbox/host.go:398-401`, `:419-432`).
3. **`Host.Apply` was unbounded.** A sandbox that attaches and never answers holds the push
    slot as surely as one that never attaches. There is now one bound over both halves
    (`:101-115`), and a push that times out gives up the attachment rather than leaving in
    force a policy the sandbox may install a moment later.
4. **The refusal said the sandbox had closed its socket when it had not.** `Host.Watch` with
    nothing that ever acknowledged the policy now says `no attachment has acknowledged this
    policy` (`:375`).
5. **`checkedLive` could silently stop being `Live`.** A single wrapper embedding both
    `sandbox.Sandbox` and `sandbox.Live` would promote a method at the same depth from both,
    which is ambiguous rather than an error and would leave the value quietly not `Live` — and
    the watch that would not start is the one thing nothing else notices. Two wrappers and
    three compile-time assertions now say it (`attest/tunneld/sandbox.go:128-151`).
6. **The sentry readiness race.** The helper dialled the sentry's control socket once and
    failed with `connection refused` when the sentry was not yet listening, which made the
    first early-push run fail. `policyApplier.connect` now retries for up to
    `narrowConnectWait`, five seconds, with backoff, and `Policy.Narrow` is called only once
    connected (`runsc/cmd/tunnel_helper.go:236`, `:288-305`; commit `cd8d745de`).

The helper's death is now the sandbox's: `runsc/cmd/tunnel_helper.go` exits non-zero when
tunneld closes its client with a reason (`util.Fatalf` at `:110`), and
`runsc/sandbox/sandbox.go` reaps it (`:2099`, `:2114`) and ends the sandbox on a non-zero exit
before teardown. Exit 0, and any exit during teardown, is not a failure (`:2117`,
`:2125-2128`).

## Tests and the quality gate

`make test TARGETS="//runsc/boot:boot_test //pkg/sentry/policyx:policyx_test //runsc/cmd:cmd_test //runsc/sandbox:sandbox_test"`:

```
//pkg/sentry/policyx:policyx_test                               (cached) PASSED in 0.2s
//runsc/boot:boot_test                                          (cached) PASSED in 0.6s
//runsc/cmd:cmd_test                                            (cached) PASSED in 9.4s
//runsc/sandbox:sandbox_test                                    (cached) PASSED in 0.2s
Executed 0 out of 4 tests: 4 tests pass.
```

In `attest/`, with `/usr/local/go/bin` on `PATH`,
`go test -race ./sandbox/... ./tunneld/... ./cmd/agent-probe/... -count=1`:

```
ok  	gvisor.dev/gvisor/attest/sandbox	11.117s
ok  	gvisor.dev/gvisor/attest/sandbox/deno	1.781s
ok  	gvisor.dev/gvisor/attest/tunneld	129.271s
ok  	gvisor.dev/gvisor/attest/cmd/agent-probe	5.595s
```

`go build ./... && go vet ./... && go test ./... -count=1` passes every package in the module
(`tunneld` 88.389 s, `attest` 13.228 s, `sandbox` 8.747 s and seven more, none failing).
`~/.local/bin/ripwire attest --quality-delta=cea8ae91d..HEAD`, from the worktree root:

```
<quality-delta baseline="ref-pair" regressions="24" minor="0" acked="3" stale="13"
 preexisting-worse="0" new-symbol="24" gating="0" register-macro-excluded="0"
 base_ref="cea8ae91d294b39ac468cc4676e79bf9a20e0d6b"
 target_ref="850559f2b2691382bb2ce1cceeb0b573bde14aa9" churn="unavailable"
 renames="34" rename_window_commits="0" acked_by_rename="0" acked_by_content="0">
```

Gating 0, and nothing that existed at master got worse: all 24 regressions are
`origin="new-symbol"` — fourteen dead-code and eight verbosity rows, every one a test function
or `RunWithoutModel`, plus two duplication groups. Three acks were added to
`attest/.ripwire_quality_acks`, each scoped `by=sandbox,tunneld`. `duplication
1d3610f0d1273cf0` is `Client.Err` joining the mutex-guarded accessor family acked at ticket
21 (members `Client.Err`, `Tunneld.attached`, `watchedVerifier.count`,
`sessionRecorder.offered`). `duplication cf2805055be4f495` and
`new-clone-of-reused-helper cf2805055be4f495` are the five-line bounded poll `attest/tunneld`
now has as well as `attest/sandbox`, whose two members sit in different test packages, both
`_test.go`. The thirteen `stale=` rows are a hygiene disclosure and never gating.

## Leftovers

Continuing the numbering of `docs/policy-in-the-sentry.md`, which ends at 25.

26. **Under `runsc create` and `runsc start`, a helper that dies later is unobserved.** The
    watch is the creating process's (`runsc/sandbox/sandbox.go:236-242`), and under `create` +
    `start` that process exits after `New()`. Egress stays fail-closed — the adapter answers
    `ENETUNREACH` for a name it holds no route for — but exec is unconstrained if no policy
    ever arrived. Closing it needs the sentry to own a liveness fd.
27. **The first peer whose policy was narrowed by a second keeps its tunnel and is told
    nothing.** Retiring the old watch before the new push is what stops a lawful narrowing
    reading as a mismatch; the cost is that the peer whose policy is no longer in force learns
    nothing (`loopback/notes.md:171-172`). A decision is needed: tell it, or say in the
    contract that a claim ends at the next push.
28. **`"x":null` reads as the absent key**, the one spelling the format admits and the
    document did not mean to (`runsc/boot/policy.go:411-413`). Pinned by a test rather than
    refused.
29. **`replayInForce` is not tracked by `h.wg`.** `Host.Close` waits for the accept loop and
    the per-connection readers (`attest/sandbox/host.go:152`, `:464`, `:485`) but not the
    replay goroutine at `:587`, which ends on the attachment's own context instead.
30. **`Live.Watch` takes the digest from the caller** (`attest/sandbox/live.go:85`), so a
    caller could watch a digest the sandbox never acknowledged; what saves it is that tunneld
    computes the digest over the bytes it received.
31. **`Atoms`, `Widening` and `CheckNarrows` have no non-test caller**
    (`attest/sandbox/policy.go:166`, `:303`, `:345`) — leftover 14, still open, with two
    readings of one format now pinned by a test rather than reconciled.
32. **Three of 25 E1 pushes were refused by a created-but-not-started sandbox**
    (`spikes/E1/output.txt:93`). That is leftover 20's window, unchanged: closing it needs a
    verb that says "start the workload under this policy".
33. **The bounded-wait helper is written twice**, in `attest/sandbox/socket_test.go` and
    `attest/tunneld/liveness_test.go`, because neither test package can export to the other.
    It belongs in `attest/internal/fixture`. Acked, not fixed.
34. **Thirteen stale ack rows are left in the ledger.** `attest/.ripwire_quality_acks` is 146
    lines, and thirteen of its rows name a finding or a target that no longer exists.
35. **The console in the loopback transcript shows `SANDBOX attached` twice per connection**
    (`loopback/20260921-205050/README.md:449-450`): once when the socket was accepted and once
    with the role once the attach message arrived. The first line was removed from
    `attest/sandbox/host.go` after the run rather than re-running the proof; the evidence is
    left as it was made.
36. **The `fired` flag is read before it is stored.** `startWatch` reads `fired`
    (`attest/tunneld/push.go:301`) and `watchLiveness` stores it (`:369`) without a lock between
    them, so a retirement that races the loss can start the spent watch once more. It is benign
    only because `DropEnforcing` refuses an attachment whose claim was not lost; the ordering
    should be made explicit.
37. **No hardware re-run.** Everything above is loopback and unit tests. The root runner and
    the ticket 26 runbooks exist if one is wanted.
