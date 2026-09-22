# The loopback proof re-run — an acknowledgement that means the sandbox has it

Ticket 27's proof, run on the workstation on 2026-09-21, worktree
`/home/pniroula/Projects/gvisor-t27`, branch
`ticket-27-an-ack-means-the-sandbox-has-it` at `02f641219`. No sudo and no
hardware.

This is ticket 26's harness — `attest/cmd/agent-probe/governed_test.go`,
`TestGovernedLoopback` — re-run against this branch's runsc with the `hold + 60`
idle-timeout workaround gone and a fifth scenario added. Four of the five runs
are ticket 26's, so what is new here is the fifth, **early-push**, and the two
things about the other four that contract v4 changed.

    root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry
                         │                                          Policy.Narrow
                         └──tunnel──▶ tunneld b ──▶ the exit ──▶ the real network

It is loopback: the tunnelds are in the test's own process with the fake SNP
platform, so **nothing here is evidence about attestation**, and every "cold
Open" below is a QUIC handshake plus a fixture's arithmetic.

## Setup

| thing | value |
|---|---|
| branch tip | `02f641219` |
| runsc | `make runsc` `-c opt`, sha256 `49740e434b42e1c1d65546258f2bcbd16134469cf8ea72190321a353daf9823c` |
| harness | `attest/cmd/agent-probe/governed_test.go`, `TestGovernedLoopback` |
| seccheck receiver | `../../ticket26/tools/seccheck-receiver`, built to `bazel-bin/seccheck-receiver` |
| workload | this package, `CGO_ENABLED=0`, `/agent-probe -network plain -task summarize -without-model -dir /tmp` |
| table | `api.anthropic.com:443`, `www.rfc-editor.org:443`, the same document in all five runs |
| exit | ticket 23's `socketSandbox` + `ServeExit`, `-allow api.anthropic.com:443,www.rfc-editor.org:443` |
| API key | none. None is needed and none was read |

Reproduced by `./run.sh`. It was run three times against this tip and passed
each time — `run-20260921-203707.log`, `run-20260921-203740.log` and
`run-20260921-203814.log` — and the evidence directory kept is the last of the
three, `20260921-203814/`, whose `README.md` the harness wrote and from which
every number below is copied. The first two runs' directories were deleted to
keep this record small; their logs say what they said.

## What was not run, and why

The model was not called. `-without-model` (`attest/cmd/agent-probe/agent.go`,
`RunWithoutModel`) leaves out the one step that needs a key and nothing else:

- The request to `https://api.anthropic.com/v1/messages` is made for real, over
  the same `*http.Client` and therefore the same tunnel, carrying the body the
  loop builds and **no `x-api-key` header**. What comes back is the API's own
  answer to an unauthenticated request, and the status printed is the status
  received. Every run that reached it got `HTTP 401` and `141` bytes of
  `{"type":"error","error":{"type":"authentication_error","message":"x-api-key
  header is required"}…}`. A status that came back at all is a stream that
  crossed the tunnel and an exit that dialled `api.anthropic.com:443`, which is
  what these runs need that leg for.
- The document is then fetched the way the `fetch_url` tool fetches it, over the
  same client: `HTTP 200`, `20480` bytes, which is the 20 KiB cap `fetch_url`
  reads to and not the size of RFC 8446.
- `write_file` writes `summary.txt`, whose content says what it is and claims to
  be nothing else.
- Each run ends in the line `NO-MODEL DONE model_status=… model_bytes=…
  doc_status=… doc_bytes=…`, which is the marker the harness asserts on. It is
  deliberately not the model's `DONE`.

Nothing in `20260921-203814/` is model output, there is no token count and no
cost, and the gap between the two requests is the fixed five seconds
`withoutModelPause` names rather than a model thinking. A hardware re-run on
SEV-SNP or TDX is not required for done and was not made.

## The five runs

| run | runsc status | wall | handshakes | `Apply` at `a` | the window | what it says |
|---|---:|---:|---:|---:|---:|---|
| off-policy | 1 | 516 ms | 1 | 130.808 ms | 1 ms | the refusal is the pushed policy's, not the table's |
| on-policy | 0 | 6.14 s | 2 | 15.518 ms | 3 ms | the workload gets through its steps under P0 |
| narrowed | 0 | 5.979 s | 1, 1, 1 | 3.126 / 3.418 / 3.803 ms | 172 ms | a narrowing mid-run, and a widening refused |
| killed | 137 | 625 ms | 1 | 128.671 ms | 2 ms | the teardown reached from outside |
| early-push | 0 | 6.05 s | 1 | 384.342 ms | 2 ms | **an ack means the enforcing sandbox has it** |

"The window" is how long each run was governed by `--tunnel-table` and nothing
else, read off the sentry's own log at both ends. It is the arrangement's and
not the harness's: a policy cannot be applied to a loader that has not started
its workload (`runsc/boot/policy.go:106`).

### early-push, which is what this ticket is for

The pusher's tunneld is built and its push is inside `Host.Apply` at `a`
**before `runsc` is started at all**; the harness holds the two in that order
rather than leaving it to a goroutine being scheduled (`loopback.holdStart`).
Four moments, two clocks:

| moment | clock | when |
|---|---|---|
| `Host.Apply` entered at `a` | a's goroutine | 20:38:06.735097 |
| `SANDBOX attached on …/a.sock role=enforcing` | a's console | 20:38:06.926855 |
| `SANDBOX applied … sha256=db45384408fe…fdd7` | a's console | 20:38:07.119429 |
| `Host.Apply` acknowledged the push | a's goroutine | 20:38:07.119464 |
| the pusher's `PUSH` line: `Peer` returned | the pusher | 20:38:07.120339 |

The push was entered **192 ms before** the enforcing sandbox attached and
acknowledged **193 ms after** it, on the first handshake, with a `cold Open` of
425 ms of which `Apply` at `a` was 384.342 ms. The sentry's own account of the
same document is `tunnel narrow: applied in 1.106539ms, of which the table swap
was 92.638µs` at 20:38:07.118128 — a millisecond before the console line, which
is the order the design requires: the helper forwards, the sentry applies, the
helper acknowledges, and only then does `a` write `SANDBOX applied` and `Apply`
return.

What the acknowledgement now means is the whole of the fifth run. On master a
push made at this moment was answered by the exit's own client, which records a
digest and enforces nothing, and the sandbox that would enforce it attached
afterwards and was never given the document — ticket 26's finding 2 and leftover
21. Here there was nothing on the socket that could answer it until the enforcing
helper arrived, and what is asserted is that no acknowledgement came back before
it did: an `Apply` that returned nil before the attach fails the run.

The workload then ran governed and completed — status 0 after 6.05 s,
`NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480
in 5.566s` — with both streams crossing the exit and the seccheck receiver
printing no refusal.

### off-policy

The table names both destinations; the pushed policy names only
`www.rfc-editor.org:443`. The workload was refused at the resolver (`no such
host`, which is NXDOMAIN reported by Go's resolver before any connect), the exit
was never asked to dial `api.anthropic.com`, and the sentry emitted two
`egress_refused protocol=dns name=api.anthropic.com reason=unknown-name` events
— two for one name because the resolver asks A and AAAA.

### on-policy

`TIMING tunnel_open=511ms first_connect=524ms first_byte=552ms task_end=6.14s`
and `NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200
doc_bytes=20480 in 5.637s`. It took **2 handshakes**: the first push landed
before the loader had started its workload, was refused with the sentry's own
sentence, took its tunnel with it, and the retry landed. That is the ordinary
shape of a push at a starting sandbox and is why the harness records the count.
Liveness ended with the workload exiting, 189 ms after runsc exited.

### narrowed

Two policies landed and the second removed a name:

    20:37:56.267531  tunnel narrow: sha256=db45384408fe…fdd7 n=2 of 2 names kept x=1 f=1
    20:37:56.304653  is gone
    20:37:56.304885  tunnel narrow: sha256=36cce26ef69b…c37d n=1 of 2 names kept x=1 f=1

The narrowing landed **72 ms** after the exit accepted the first stream, and the
workload's second request is a fixed five seconds after its first — so the
document host was gone before it was asked for, and the workload was told `dial
tcp: lookup www.rfc-editor.org on 127.0.0.53:53: no such host`. With the model
step left out that race is no longer a race, so the refusal is asserted rather
than recorded either way. The sentry emitted two `egress_refused` events for the
name, and the exit was never asked to dial it. The third peer, pushing P0 again
at a sandbox now holding P1, was refused with `it widens n by
[net:www.rfc-editor.org:443]` in `a`'s log and the fixed sentence `the sandbox
beside this tunneld did not apply it` on the wire.

**This is the one run whose assertion changed from ticket 26's.** Ticket 26
recorded the first peer's tunnel being torn down 185 ms after the narrowing,
because its watch over P0's digest saw the sandbox pulsing P1's. That reading
closed a tunnel, which was the intent, and dropped the enforcing attachment,
which since this ticket reaps the helper would end the sandbox mid-task. So the
watch over the old policy is retired before the new one is pushed
(`attest/tunneld/push.go`, `applyOrRefuse`), and what is asserted here is that
nothing was lost while the workload ran: the single loss reported came 5.58 s
after the narrowing, when the workload exited.

The consequence is a finding rather than an assertion: the first peer, whose
policy is no longer the one in force, keeps its tunnel and is told nothing.

### killed

`runsc kill … KILL` was sent 495 ms into the run, while the first request was in
flight; runsc ended with status 137 after 625 ms. The loss was reported 17 ms
**before** runsc's own exit was accounted and the tunnel was refused 16 ms
before it — the sandbox's socket closes when the sentry goes, and runsc returns
a few milliseconds later, so a loss on that side of the line is the ordinary
case and not a clock running backwards.

## The defect this re-run found

Every attempt at this proof made before the three kept here lost one of the five
runs, and not always the same one, to a single mechanism:

1. A push arrives before the loader has started its workload and is refused with
   the sentry's own sentence. This is ordinary and is what the handshake count
   records.
2. `applyOrRefuse` retires the watch over the policy in force before pushing and
   starts it again when the push does not land. The watch it started again was a
   watch that had already fired at the end of an earlier sandbox's life, over a
   digest nothing was enforcing any more.
3. `Host.Watch` found no attachment that had acknowledged that digest and
   reported the loss at once. `DropEnforcing` then closed whatever attachment
   was enforcing — which was the **new** sandbox's helper, seconds old and
   innocent.
4. The helper exits non-zero when tunneld closes its client, and runsc ends a
   sandbox whose helper exited non-zero before teardown. So a push that arrived
   a moment early killed the sandbox it was pushed at, and the retry that should
   have landed had nothing left to land in.

It was closed while this proof was being written, in `97e628713` (drop the
attachment whose claim was lost, not whichever is enforcing when the drop
arrives), `b4ebb2e60` (give up an attachment that does not answer a push) and
`02f641219` (a watch that has fired is spent and is not started again). The runs
kept here were all made after those had landed, and each of the three passed.
The runs made before them are not kept: they were made against a tree that was
being changed under them and reproduce nothing.

Two harness assertions were added out of it and are the guard: `tellTeardown`
requires exactly one liveness loss per run, because the sandbox goes once and
every extra loss is a refusal written against a peer for something that did not
happen; and `tellNarrowed` requires that nothing be lost between the narrowing
and the workload's own exit.

## What this does not say

Nothing about attestation: the platform is `internal/snpfake` and the verifier
is a fixture. Nothing about a measured guest. Nothing about `x`, which nothing
here execs — every run's strace digest says `0 execs`, the same as ticket 26's.
Nothing about what a model does with a denied tool, which is ticket 26's finding
and needed a model to find. Nothing about two peers over a real network.

## Files

| file | what |
|---|---|
| `run.sh` | the run, exactly as run; it writes `run.log` beside itself |
| `run-20260921-203707.log`, `run-20260921-203740.log`, `run-20260921-203814.log` | the three runs' transcripts, untrimmed |
| `20260921-203814/README.md` | written by the harness: every push, every refusal, every event, per run, and `a`'s whole console with a clock on it |
| `20260921-203814/<run>/` | one directory per sandbox: stdout, stderr, table, `pod-init.json`, seccheck output, strace digest and the debug logs |
| `../spikes/E1/` | the attach window this scenario's wait is affordable because of |
