# E4 — one hop with a pushed policy, where applying means starting a process

**Question.** Two tunnelds over loopback, as in E2, but behind B the sandbox is
not the null one: it is a throwaway adapter whose `Apply` turns the pushed
document into Deno flags and execs E3's agent under them. Does the task
complete, does it fail at a named resource, and — the question the ticket
actually asks — **is "apply then ack" enough when apply means "start a process
with flags"?**

**Answer, up front: the hop works and the ack is a lie waiting to happen.**
Case (i) completed, case (ii) failed at exactly the resource the policy left
out, case (iii) was refused for widening and took the tunnel with it. And case
(iv), which the ticket did not ask for and which is the whole of the answer:
a policy whose flags Deno rejects at startup produces a process that **starts**,
is **acknowledged**, and is **dead about 40 ms later**. The acknowledgement was true
when it was sent and there is no second one.

Nothing in the repository was changed by this spike. `attest/` is untouched:
the harness is a `_test.go` file copied in to run and deleted afterwards.

---

## The arrangement, and why this one

The ticket leaves the shape to be decided and recorded. This is the cheapest
honest one:

```
A ── tunnel ──▶ B         A pushes P. B's adapter turns P into Deno flags and
  "RUN"                   execs E3's agent.ts under them. Deno IS the enforcer
  ◀── result ──           on B; the tunnel carries the request and the result,
                          and A's push is what set the flags.
                     B ── the agent's own fetches go straight out ──▶ internet
```

The alternative — routing the Deno agent's egress back through the tunnel, as
E2 did for the Go agent — would have put two enforcers in series and measured
neither. Here **Deno is the only thing between the agent and the network**, and
the only reason it is holding the flags it is holding is that A pushed them.
That is the property E4 is for.

A never sees the internet and never sees a trust decision about it. What A
gets back over the stream is the agent's timestamped transcript and an exit
status. That is deliberate: it is the concrete form of "the agent gets a stream
or an error, and the refusal is visible to A as a tool error, not as a trust
decision".

## The two shape changes P needed

Ticket 22's provisional bytes are `{format, version, n:[{cidr, ports}],
f:[{path, modes}], x:[{path|sha256}]}`. Two of that could not be used as
written, and the adapter parses a variant. Both are recorded here rather than
fixed anywhere.

1. **`n` carries `host`, not `cidr`.** E3 measured why: Deno's `--allow-net`
   check is against the **name in the URL, before resolution**. It parses a
   CIDR correctly and matches addresses against it correctly — but the string
   it is matching is `api.anthropic.com`, which is in no CIDR. A `{cidr,
   ports}` entry therefore maps to a flag that grants exactly the destinations
   an agent never names. The entry here is `{"host":"api.anthropic.com",
   "ports":[443]}`, and it maps one-to-one onto `--allow-net=host:port`. An
   empty `ports` maps to a bare host, which E3 measured grants every port.
2. **There is an `e`.** `(N, F, X)` has no letter for the environment, and the
   agent cannot read its API key without `--allow-env=ANTHROPIC_API_KEY`. The
   adapter reads `e:[{variable}]`. This is the same finding E3 ended on,
   arriving here as a thing that had to be typed before anything would run.

`f:{path, modes}` mapped unchanged: `modes` containing `r` becomes
`--allow-read=path`, `w` becomes `--allow-write=path`. `x:{path}` mapped
unchanged to `--allow-run=path`; `x:{sha256}` was not exercised, because E3
had already measured that Deno has nowhere to put a digest.

## The adapter

`e4_deno_sandbox_test.go.txt`, the `e4Sandbox` type and its three helpers: 33
lines to turn the document into a **capability set**, 14 to render that set as
a Deno command line, 12 for the subset test, 25 for `Apply` itself, 41 to exec
the process and timestamp everything it says. Everything else in the file is
the two tunnelds, the stream ends and the six policies.

It compares **capability sets** and not flag strings. `--allow-net=a,b` and
`--allow-net=b,a` are different strings and the same policy; the atoms
(`net:api.anthropic.com:443`, `write:./summary.txt`, `env:ANTHROPIC_API_KEY`)
sort, so a widening is `!subset(new, previous)` and a reordering is nothing.

`Apply` refuses with `sandbox.ErrPolicyRefused` on three things: a document it
cannot decode (unknown fields included — a sandbox that enforces a policy
cannot skip the part it did not recognise, which is the opposite of tunneld's
rule for the envelope), a capability set that is not a subset of the last one
applied, and an `exec.Start` that fails. It acks — returns nil — after
`cmd.Start()` has returned, and at that moment the only true statement it can
make is *the process started*.

## What ran

```
cp e4_deno_sandbox_test.go.txt attest/tunneld/spike23_e4_test.go
cd attest && go test ./tunneld/ -run TestSpike23E4 -v -count=1 -timeout 15m   # ×2
rm attest/tunneld/spike23_e4_test.go
```

Two passes, `run1.log` and `run2.log`; both PASS, both in 17.3–17.4 s. The
Deno binary is `~/.deno/bin/deno` 2.9.6 and the script is
`../E3/agent.ts`, unchanged — same task, same model `claude-sonnet-5`, same
two tools.

One cosmetic thing about the logs: every goroutine writes to one transcript, so
a line from an earlier case's serve loop can land under a later case's heading.
The `pid` in each `B APPLIED` line says which process a block belongs to.

## The cases

### (i) P narrower than E1's list, and sufficient

```json
{"format":"policy","version":1,
 "n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]}],
 "f":[{"path":"./summary.txt","modes":"w"}],"x":[],"e":[{"variable":"ANTHROPIC_API_KEY"}]}
```

became

```
deno run --no-prompt --allow-net=api.anthropic.com:443,www.rfc-editor.org:443 \
  --allow-write=./summary.txt --allow-env=ANTHROPIC_API_KEY  ../E3/agent.ts
```

and the task completed: `fetch_url`, `write_file`, DONE, exit 0, and A read the
whole transcript off the stream. E1's eleven destinations and twenty paths are
now two hosts and one file, and that was enough.

| | run 1 | run 2 |
| --- | --- | --- |
| cold tunnel at A — dial, both sides judge the other's evidence, push, ack, **and the process starts** | **32 ms** | **49 ms** |
| `Apply` at B — parse, subset test, `exec.Start` | **2.391 ms** | **2.704 ms** |
| process start → first tool call | **1.854 s** | **1.728 s** |
| the agent, end to end | 7.261 s | 7.529 s |
| input / output tokens | 14 954 / 527 | 14 963 / 549 |
| cost | $0.035178 | $0.035416 |

E2's cold `Open` over the null sandbox was 34–44 ms. **Starting a Deno process
inside `Apply` costs about 2 ms of that** — the exec, not the runtime, which
takes a further ~70 ms to print its first line and 1.7–1.9 s to reach the first
tool call, all of it after the ack.

### (ii) P omits `www.rfc-editor.org:443`

The exact text, as it reaches the model, verbatim from the transcript A
received:

```
  1.592s |   tool_use fetch_url {"url":"https://www.rfc-editor.org/rfc/rfc8446.txt"} -> 107 bytes, is_error=true
  1.593s |     the model is told: fetch_url: NotCapable: Requires net access to "www.rfc-editor.org:443", run again with the --allow-net flag
```

So: **yes, the model sees it as a tool error.** `NotCapable` is thrown by
`fetch` inside the tool, the tool catches it exactly as E1's Go tool catches a
dial error, and it goes back as a `tool_result` with `is_error: true`.

**And no, that is not what A sees.** A sees a completed stream with `exit=0`
and a transcript — not a refusal, not a reason, nothing in the taxonomy. The
model did what E3's negative run did: it wrote the summary from what it already
knew, called `write_file`, and said DONE. In **both** E4 passes its final text
was the bare word `DONE`, with no mention of the restriction at all — E3's
standalone negative run had at least appended a note saying the document was
never fetched. A caller reading the exit status, or the file, or the final
text, cannot tell case (ii) from case (i).

| | run 1 | run 2 |
| --- | --- | --- |
| cold tunnel at A | 40 ms | 37 ms |
| `Apply` at B | 1.974 ms | 1.572 ms |
| process start → first tool call | 1.584 s | 1.677 s |
| input / output tokens | 2 773 / 604 | 2 751 / 570 |
| cost | $0.011586 | $0.011202 |

Cheaper only because the 20 KB of RFC 8446 never entered the conversation —
which is, in token counts, the one place the difference is visible.

### (iii) a second push that widens

`P3` is `P1` plus `{"host":"example.com","ports":[443]}`. The adapter refused:

```
B  REFUSAL verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:42787
   pushed a policy this sandbox did not apply: sandbox: policy refused: it widens
   [env:ANTHROPIC_API_KEY net:api.anthropic.com:443 net:www.rfc-editor.org:443 write:./summary.txt] to
   [env:ANTHROPIC_API_KEY net:api.anthropic.com:443 net:example.com:443 net:www.rfc-editor.org:443 write:./summary.txt]
A  REFUSAL verification refused: the policy pushed to the peer was not applied: "b" at 127.0.0.1:59444
   did not apply the policy pushed to it: the peer refused it: the sandbox beside this tunneld did not apply it
A  Open after 34ms returned: attest: verification failed
A  reason = the policy pushed to the peer was not applied (errors.Is ErrRefused: true)
```

`Open` returned a refusal at 34 ms / 40 ms, `attest.ReasonOf` is
`ReasonPolicyNotApplied`, and `push.go`'s `refusePush` closed the tunnel after
the 100 ms grace. The detail — which capability widened — stayed on B's console
and never crossed the wire; the pusher was told the fixed sentence "the sandbox
beside this tunneld did not apply it". That is the design working as written.

**How it was provoked, and what that says.** A second tunneld, `sandbox-a-iii`,
with `Config.PushPolicy = P3`, dialing the same B. It could not be A: a push is
**once per tunnel** (`pushBook` is keyed by `*tunnel.Conn`, and
`Config.PushPolicy` is one document fixed at `New`), so the same tunneld on the
same tunnel has no second push to make. **Widening-refusal is untestable on a
live tunnel** — not merely hard to reach, structurally absent. What can be
tested is what was tested: a *different pusher* arriving at a sandbox that has
already narrowed. On a live tunnel the invariant "a policy may only narrow" has
nothing to constrain, because there is only ever one policy.

For the contrast, case **(iii b)**: a third tunneld pushing `P1` **minus**
`www.rfc-editor.org:443` — a narrowing — was applied, and the tunnel came up.
So the subset test is real and not "every second push fails". What the log also
says is the price:

```
B  the policy restarts the agent: the run under [… net:www.rfc-editor.org:443 …] is killed and its conversation is gone
B  APPLIED [env:ANTHROPIC_API_KEY net:api.anthropic.com:443 write:./summary.txt] -> deno run … (pid 2819422, 1.682ms)
B  the agent ended after 3ms: exit=-1 err=signal: killed
```

**A narrowing is a restart.** The flags are fixed at `exec`, so a second policy
is a new process: the running agent is killed mid-conversation, its message
history is gone, and the new one starts the task again from turn 1 in the same
working directory, over the same `summary.txt`.

### (iv) the process starts, is acknowledged, and then dies

Not asked for, and it is the answer. `P5` names the host `nonsense///`, which
E3 measured Deno rejects at flag parsing:

```
B  APPLIED [… net:nonsense///:443 …] -> deno run --no-prompt --allow-net=nonsense///:443 … (pid 2819646, 1.856ms)
A  Open took 43ms, err=<nil>                       ← the push was ACKNOWLEDGED
B  the agent ended after 43ms: exit=1 err=exit status 1
A  received 341 bytes:
exit=1 first_tool_call=0s
    34ms | error: invalid host 'nonsense///': invalid char found in FQDN
```

`exec.Start` succeeded, so `Apply` returned nil, so the ack went back, so A's
`Open` returned a stream. Forty-one milliseconds after that ack the process was gone (run 2: thirty-five). A held
a perfectly good tunnel to a sandbox with nothing in it, and only found out
because it asked.

### (v) the envelope is fine and the body is not

`{"format":"policy","version":1,"n":"everywhere","f":[],"x":[]}` passes
`sandbox.ReadEnvelope` — tunneld reads two fields and both are right — and dies
in the adapter:

```
sandbox: policy refused: it is not a policy this sandbox reads: json: cannot unmarshal string into Go struct field e4Policy.n …
```

Refused, `ReasonPolicyNotApplied`, tunnel closed, at 36–40 ms. The split is
exactly where `policy.go` says it is: tunneld owns "is this addressed to me",
the sandbox owns "can I do this".

## The answer: is "apply then ack" enough?

**No.** It is enough for a sandbox whose `Apply` is a state change in the
acknowledging process, which is what `Null` is and what the contract was
written against. It is not enough for a sandbox whose `Apply` is `fork`+`exec`,
and E4 names three reasons, in the order they cost something:

1. **The ack is a claim about the past.** `Apply` can truthfully say "the
   process started" and can say nothing about whether it is still running. Case
   (iv): the ack left `Apply` 1.856 ms after `exec.Start`, the process was dead at 43 ms, and A's tunnel stayed up. Every
   failure mode of a process — a flag the runtime rejects, a missing script, an
   immediate crash, an OOM kill — lands *after* the only moment the contract
   has for saying no.
2. **There is no way to re-ack, and no way to un-ack.** `Sandbox.Apply` returns
   once. `push.go` waits for exactly one answer per tunnel and then never looks
   again. A sandbox that learns its process died has nothing to call: no
   revocation verb, no event, no second exchange. The tunnel's continued
   existence keeps asserting something the sandbox no longer believes.
3. **The flags are fixed at `exec`, so a second policy is a restart.** Case
   (iii b): the narrowing was applied by killing a running agent and starting
   another. The contract has no vocabulary for that — nothing in `Apply`'s
   signature distinguishes "I have adopted this policy" from "I have destroyed
   the workload you were talking to and started a new one under it". A
   delegator that narrows mid-task silently discards the task.

The shape of what is missing is the same in all three: `Apply` is a
**request/response** and the thing it applies to has a **lifetime**. Anything
built on this contract for a process sandbox needs either a liveness signal
from sandbox to tunneld (so that a dead workload ends the tunnel the way a
refused push does), or an `Apply` that does not return until the workload is
past the point where its flags can kill it — and the second is only a longer
version of the same lie.

## What broke, and in what order

1. **`n` broke before anything ran.** `{cidr, ports}` cannot be a Deno flag
   that matches what an agent dials. The document had to carry a host.
2. **The key broke next.** Nothing in `(N, F, X)` grants an environment
   variable, and the agent exits at line one without it. `e` had to be invented.
3. **The ack broke in case (iv)**, at 43 ms, after it had already been sent.
4. **The narrowing broke the workload** in case (iii b): a second policy is a
   restart, and a restart is a new conversation.
5. **The widening refusal could not be provoked the way the ticket imagines
   it.** One push per tunnel means there is no second push on a live tunnel;
   it took a second pusher on a second tunnel.
6. **The refusal in case (ii) did not reach A as anything at all.** The model
   was told `NotCapable`, worked around it, and A read `exit=0`. The one thing
   the delegator can act on is buried in a transcript it has to parse.

## Two things this says beyond the cases

- **Nothing in the policy stops the adapter from handing the child a secret.**
  `cmd.Env = os.Environ()` puts `ANTHROPIC_API_KEY` in the child's environment
  unconditionally; `--allow-env` only decides whether the script may *read* it.
  The `e` entry is a read gate on an environ the sandbox chose. A promoted
  package has to build the child's environment from the policy, not filter
  access to the host's.
- **`Attested` was as empty here as in E2.** B's exit knows the vendor, the
  measurement and the policy digest of whoever opened the stream, and nothing
  about which policy that peer pushed or whether the process it started is the
  one now answering. The digest in `Attested.PolicyDigest` is the peer's
  *egress ceiling*, not the document it pushed — two different numbers that a
  reader of the contract could easily take for one.
