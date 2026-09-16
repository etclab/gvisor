# Two hops — a root pushes to A, A's agent delegates to B, B runs under A's policy

**Question.** Ticket 23's last item: *a root client pushes `P0` to A; A's agent asks for B and A
pushes `P1 ⊑ P0`; B runs the task under `P1`; then B asks for something `P1` does not grant and is
refused at Deno, and the refusal is visible to A as a tool error, not a trust decision.* Spike E4
did one hop with a throwaway adapter. This is two hops on the promoted pieces — the loop in
`attest/cmd/agent-probe`, the sandbox in `attest/sandbox/deno`, the push in `attest/tunneld` —
with nothing copied in to run.

**Answer, up front.** The two hops work and the refusal lands exactly where the ticket says it
should: `NotCapable` at Deno, a `tool_result` with `is_error: true` at A, no reason from the
taxonomy anywhere near A. What does **not** hold is everything above that line: nothing checks
that `P1 ⊑ P0`, the workload on B starts when the policy is applied rather than when the request
arrives, and A's model — told to repeat the far transcript verbatim — answered root with the far
side's last word, `DONE`, in the case where the far side had been denied something. Root cannot
tell case (i) from case (ii).

The harness is `attest/cmd/agent-probe/twohops_test.go`, `-run TestTwoHops`, skipped unless
`AGENT_PROBE_LIVE=1` and `AGENT_PROBE_DENO` names a Deno that exists. Two passes, `run1.log` and
`run2.log`, both PASS in 24 s. (The harness was tightened after those two passes — the workload's
output goes to a file rather than to a locked buffer, and four one-line accessors went away — and no
line either run printed changed shape; neither run produced any stderr, which is the only place the
two could have ordered differently.) Deno is `~/.deno/bin/deno` **2.9.6**, the model is
`claude-sonnet-5`, and the task on B is E1's, byte-identical to the one every spike ran.

---

## The arrangement

```
  root                         a                              b
  ───────────                  ────────────                   ─────────────────────────
  tunneld                      tunneld                        tunneld
  PushPolicy = P0  ──push──▶   sandbox.Null                   sandbox/deno
                               (records P0, enforces nothing)  Apply = exec deno run --no-prompt
                                                                      --allow-net=… --allow-write=…
  Null.Open("a") ──"GO\n"──▶   agent-probe's loop                     --allow-env=ANTHROPIC_API_KEY
                               task=delegate, one tool
                               PushPolicy = P1  ──push──▶      Apply → the Deno agent starts HERE
                               delegate: Open("b"), "RUN\n"
                               ◀── the far transcript ──       one goroutine accepts the stream,
  ◀── a's final text ──        as a tool_result                 waits for Done(), answers with the
                                                                transcript and the exit status
                                                               b ── the agent's own fetches ──▶ net
```

Who pushes what: root's tunneld pushes **P0** to a, whose null sandbox records it and acknowledges;
a's tunneld pushes **P1** to b, whose Deno sandbox turns it into permission flags and starts the
process under them. **Deno is the only enforcer in the picture.** Neither tunneld filters a stream,
and a's sandbox enforces nothing at all — a null sandbox is the honest implementation of a contract
in which the sandbox is not where anything is enforced.

Three tools at most, as the ticket requires: the agent on **a** is offered exactly one, `delegate`,
so the only thing it can reach is the peer its task names; the agent on **b** is offered two,
`fetch_url` and `write_file`. "A's agent asks for B" is a model decision — the prompt names the
peer, the model chooses to call the tool.

### Why the stream says RUN after the work has started

E4's harness owned the Deno process's stdin and could carry a `RUN` line into it. The promoted
package owns the process's stdio and exposes none of it, and `deno/agent.ts` starts on end of input,
which is what a process the sandbox started gets. Three arrangements were possible:

1. start the agent with `Args` naming a socket the bridge listens on, so the script connects there
   for RUN and the transcript — **then P needs a net or read grant for the delegation channel
   itself**;
2. the same through two files — **then P needs `f` grants for them**;
3. let the agent start as the sandbox starts it, and have the bridge on b answer the stream with
   what the process said once it has ended.

This record uses **(3)**, and the consequence is stated rather than hidden: **under this package a
pushed policy starts the workload, so the task begins at push time, before any stream exists.** The
stream a opens carries only *give me the result*; the accept is what it triggers, not the work. That
(1) and (2) would each have needed a grant is itself a finding — **the delegation channel is a
resource P has to grant**, and (3) is the only arrangement in which it is not.

### `P1 ⊑ P0` is nobody's rule

a's tunneld pushes the document it was configured with. No line on either side compares it with what
root pushed at a, and `sandbox.Null` does not even parse P0. The containment here is two constants
written to be contained; in case (i) they are the same document, which the log shows as the same
digest arriving on both hops:

```
a-i  SANDBOX applied format=policy version=1 bytes=215 sha256=857adfb944e67e957ccd98d293ba33c9c7b1118f1d64866723c1dc17f2e35fb4
b-i  SANDBOX deno applied atoms=4 sha256=857adfb944e67e957ccd98d293ba33c9c7b1118f1d64866723c1dc17f2e35fb4 pid=2956695
```

Enforcing "a delegate may only narrow what it was given" is a leftover for the policy track.

---

## The policies

`n` carries a host because Deno checks the name a URL gives before it is resolved; `f`'s `modes` is
a list because a set of modes is a set; `e` exists because `(N, F, X)` has no letter for the variable
the API key is in. All three findings are E3's and E4's, arriving here as things that had to be
typed before anything would run.

```json
P0 = P1(i) = {"format":"policy","version":1,
  "n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]}],
  "f":[{"path":"./summary.txt","modes":["w"]}],"x":[],"e":[{"variable":"ANTHROPIC_API_KEY"}]}
```

**Case (i) uses `P1 = P0` exactly.** `⊑` is not `⊏`, equal sets are applied, and using the same
document on both hops leaves case (ii) as the only case in which P1 is strictly narrower — which is
the variable being measured. `P1(ii)` is P0 without `www.rfc-editor.org:443`. `P2(iii)` is P0 plus
`{"host":"example.com","ports":[443]}`.

---

## The three cases

### (i) P1 = P0, and it is enough

b's Deno was started as

```
deno run --no-prompt --allow-net=api.anthropic.com:443,www.rfc-editor.org:443 \
  --allow-write=./summary.txt --allow-env=ANTHROPIC_API_KEY  deno/agent.ts
```

and the task completed — fetch, write, `DONE`, exit 0 — with the transcript travelling back over the
stream as a tool result and a's model repeating it to root:

```
b-i  the workload ended with status 0, 6.735s after the RUN line arrived
  tool_use delegate {"peer":"b"} -> 1247 bytes, is_error=false
root-i  received 1239 bytes:
RUN assumed: stdin ended without a request, which is how the sandbox starts this process
…
  t=1495ms tool_use fetch_url {"url":"https://www.rfc-editor.org/rfc/rfc8446.txt"} -> 20502 bytes, is_error=false in 134ms
b-i  /tmp/…/002/summary.txt is 1009 bytes, which is the f grant used
```

### (ii) P1 without `www.rfc-editor.org:443`

Deno denied the tool's destination, `agent.ts` marked it, the model was told, and the model worked
around it and said `DONE` anyway — E4's case (ii) again, one hop further up:

```
  t=1523ms tool_use fetch_url {"url":"https://www.rfc-editor.org/rfc/rfc8446.txt"} -> 107 bytes, is_error=true in 7ms
TOOL_ERROR fetch_url: fetch_url: NotCapable: Requires net access to "www.rfc-editor.org:443", run again with the --allow-net flag
…
final text: DONE
b-ii  the workload ended with status 0, 8.72s after the RUN line arrived
```

At **a**, that arrives as a failed tool call and as nothing else:

```
  tool_use delegate {"peer":"b"} -> 1370 bytes, is_error=true
a-ii  Open("b") returned after 103ms: err=<nil>
```

`Open` returned `nil`; a's tunneld logged no refusal; b's tunneld logged no refusal; nothing in a's
view or root's carries `PolicyNotApplied` or any other reason from the taxonomy. The denial is a
tool error, exactly as the ticket asks.

**And root read four bytes.** a's model was told to reply with the far transcript "verbatim, and
nothing else" and answered with the far side's last word instead:

```
root-ii  received 4 bytes:
DONE
```

In both recorded runs case (ii) came back as `DONE` and case (i) came back as the whole transcript.
(A third run, discarded because a parser bug in the harness failed the test, had case **(i)** answer
`DONE` too — so the verbatim repeat is discretion and not a rule.) The assertion in the test is
therefore where the ticket puts the claim — the denial is visible **at a** as a tool error — and the
line the harness prints records what root read instead.

### (iii) a second pusher widens, while b's workload is running

`P2` is P0 plus one host. It cannot be a's second push: a push is once per tunnel, so the widening
had to come from a second tunneld on a second tunnel, which is E4's finding repeated on the promoted
package. It arrives while case (i)'s Deno process is alive — the harness triggers it the moment b
accepts a's stream — and is refused:

```
b-i  SANDBOX deno refused: sandbox: policy refused: it widens [env:ANTHROPIC_API_KEY net:api.anthropic.com:443 net:www.rfc-editor.org:443 write:./summary.txt] by [net:example.com:443]
a2-i  REFUSAL … "b" at 127.0.0.1:56857 did not apply the policy pushed to it: the peer refused it: the sandbox beside this tunneld did not apply it
a2-i  Open returned after 42ms: attest: verification failed
a2-i  reason = the policy pushed to the peer was not applied (errors.Is ErrRefused: true)
b-i  the process the first push started is still running: Done is not closed
b-i  the one process this sandbox ever started: SANDBOX deno applied atoms=4 sha256=857adfb9… pid=2956695
```

`Open` at the widening pusher is `ReasonPolicyNotApplied`; the detail — which capability widened —
stays on b's console and never crosses the wire; and the running workload is untouched: `Done` is
not closed, the pid is the one the first push started, and the sandbox started exactly one process
in its life. Case (i)'s answer came back normally afterwards.

---

## Timings

Each hop's **cold tunnel** is measured at the dialer around `Open` and contains the dial, both sides
judging the other's evidence, the push and the acknowledgement. **push+ack** is measured at the
pushed side, from entry to `Apply` to its return, by a wrapper the harness puts between tunneld and
the sandbox. **First tool call** is stamped by the far agent itself (`t=…ms` on its call lines,
milliseconds from the start of its runtime); **agent end to end** is the far agent's own `wall time`.

| case (i) | run 1 | run 2 |
| --- | --- | --- |
| root→a cold tunnel | 46 ms | 46 ms |
| root→a push+ack at a (`Null.Apply`) | **88 µs** | **78 µs** |
| a→b cold tunnel | 100 ms | 92 ms |
| a→b push+ack at b (`deno.Apply`: parse, subset test, exec, 50 ms settle) | **53.005 ms** | **53.594 ms** |
| b: process start → first tool call | 1 495 ms | 1 498 ms |
| b: the agent, end to end | 6.707 s | 6.826 s |
| root → answer, total | 12.272 s | 12.21 s |

| case (ii) | run 1 | run 2 |
| --- | --- | --- |
| root→a cold tunnel | 43 ms | 43 ms |
| root→a push+ack at a | 88 µs | 95 µs |
| a→b cold tunnel | 103 ms | 84 ms |
| a→b push+ack at b | 51.979 ms | 51.627 ms |
| b: process start → first tool call | 1 523 ms | 1 416 ms |
| b: the agent, end to end | 8.692 s | 8.694 s |
| root → answer, total | 10.806 s | 10.706 s |

| case (iii) | run 1 | run 2 |
| --- | --- | --- |
| `Apply` at b, refusing the widening | 179 µs | 153 µs |
| `Open` at the second pusher, refused | 42 ms | 33 ms |

The shape to keep: **the second hop's cold tunnel is the first hop's plus the workload's `exec` and
its settle.** 46 ms against 100 ms, and the 53 ms between them is `Apply` — of which 50 ms is the
settle the package waits before it acknowledges, so the exec itself is the ~3 ms E4 measured as ~2 ms
without one. Everything the Deno runtime spends afterwards — ~1.5 s to the first tool call — is after
the acknowledgement and outside the push entirely.

## Tokens and cost

`claude-sonnet-5`, $2.00/M input and $10.00/M output, as the loop prices it.

| | run 1 in / out | run 1 cost | run 2 in / out | run 2 cost |
| --- | --- | --- | --- | --- |
| (i) a — 2 requests, one `delegate` | 1 654 / 644 | $0.009748 | 1 661 / 656 | $0.009882 |
| (i) b — 3 requests, `fetch_url` + `write_file` | 14 929 / 515 | $0.035008 | 14 969 / 542 | $0.035358 |
| (ii) a — 2 requests, one `delegate` | 1 737 / 97 | $0.004444 | 1 693 / 53 | $0.003916 |
| (ii) b — 3 requests, the fetch denied | 2 851 / 684 | $0.012542 | 2 780 / 612 | $0.011680 |
| **the run** | | **$0.061742** | | **$0.060836** |

Case (iii) costs nothing of its own: it rides on case (i)'s workload. Case (ii)'s b is cheap for the
one reason that matters — the 20 KB of RFC 8446 never entered the conversation — which is where the
denial is visible in numbers even when it is not visible in the exit status.

## What did not hold

1. **Nothing enforces `P1 ⊑ P0`.** a pushes the document it was given; no code compares the two. By
   construction here, and a leftover for the policy track.
2. **The workload starts at push time, not at request time.** `Apply` is `exec`, so the task begins
   when the policy lands. The stream that "asks" for it arrives after the agent has already made its
   first model request. A delegator that pushes and then decides not to ask has already paid for a
   run.
3. **The delegation channel is a resource P would have to grant** in either arrangement that carries
   a real request into the workload — a socket needs a net grant, files need `f` grants. Only the
   arrangement in which the request is not carried at all avoids it.
4. **The model on b says `DONE` after a denied tool**, writes a summary from what it already knew,
   and exits 0: `TOOL_ERROR fetch_url: … NotCapable …` then `final text: DONE`, status 0, and
   `summary.txt` is 1 045 bytes (run 1) against 1 009 bytes in case (i). The artifact, the exit
   status and the last word are all indistinguishable from a run that was not denied anything.
5. **A's model does not pass the tool error on.** Root read `DONE` in case (ii) in both runs. The
   `is_error: true` that the contract delivered correctly to a stops at a's model, and root's view of
   a denied delegation is a four-byte answer. A delegator that wants to know has to be told by
   something other than the agent it delegated to.
6. **The peer name on an accepted stream is wrong on loopback.** `nameOf` matches the peer table on
   the address only, since an accepted connection comes from an ephemeral port; on loopback every
   peer is `127.0.0.1`, so a's single-entry table named **root's** stream `peer="b"`, and b, whose
   table is empty, saw `peer=""`. The measurement and the policy digest beside them are the identity;
   the name is decoration, and on one machine it is decoration that lies.
7. **`Attested.PolicyDigest` is still the peer's egress ceiling and not the document it pushed** —
   E4's last paragraph, unchanged. Nothing in what b is told about a says which policy a pushed, and
   nothing in what a is told says which one b applied.
8. **A widening refusal is still only reachable from a second pusher.** One push per tunnel means a
   live tunnel has no second policy to refuse, so the invariant "a policy may only narrow" has
   nothing to constrain on the tunnel it was pushed on.
9. **a's own model requests do not go over the contract.** a reaches `api.anthropic.com` directly:
   what this record measures is the delegation hop, and the model endpoint behind the contract is
   spike E2's measurement. An `a` whose own egress went through a tunnel would need an exit peer,
   which is a third hop and not this ticket's.
