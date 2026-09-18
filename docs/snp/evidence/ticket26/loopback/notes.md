# The loopback proof — an unmodified agent completing a task under a policy pushed over a tunnel

Ticket 26's proof that the thing this ticket builds works end to end with a real
agent and a real model in it, run on the workstation on 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t26`, branch
`ticket-26-the-sandbox-honors-a-pushed-policy`. No sudo and no hardware.

**Why this exists beside the two-guest proof.** The compiled-in egress ceiling
(`attest/ceiling`) permits no TCP egress from a measured guest, and this ticket
does not change it. So the two-guest TDX run can prove the tunnel, the push, the
narrowing and the teardown, and it cannot run an agent that talks to a model.
This is where the model-backed task is proven under a pushed policy. It is
loopback: the tunnelds are in the test's own process with the fake SNP platform,
so **nothing here is evidence about attestation**, and the numbers below that
name a handshake are named as what they are.

## Setup

| thing | value |
|---|---|
| runsc | `make runsc` `-c opt`, sha256 `6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819` |
| harness | `attest/cmd/agent-probe/governed_test.go`, `TestGovernedLoopback` |
| seccheck-receiver | `../tools/seccheck-receiver/`, sha256 `d7be04465f899c4af6f5c94de2307cde5bd220679497db2455ea085189d509dd` |
| workload | this package, `CGO_ENABLED=0`, `/agent-probe -network plain -task summarize -dir /tmp` |
| model | `claude-sonnet-5`, the task ticket 23 and ticket 25 both ran, byte-identical |
| table | `api.anthropic.com:443`, `www.rfc-editor.org:443`, the same document in all four runs |
| exit | ticket 23's `socketSandbox` + `ServeExit`, `-allow api.anthropic.com:443,www.rfc-editor.org:443` |

Reproduced by `./run.sh`; `20260918-160939/` is the run these numbers come from,
with `README.md` written by the harness, the untrimmed test transcript in
`output-01-governed-loopback.txt`, and one directory per sandbox holding its
stdout, stderr, table, `pod-init.json`, seccheck output, strace digest and all
five debug logs.

**What is new here and what is ticket 25's.** Everything around the sandbox is
ticket 25's loopback world unchanged: the rootfs, the bundle, the two tunnelds
`a` and `b`, the exit, the capture and the key handling. What is added is a
third tunneld, `root`, which dials `a` and whose whole purpose is the document
it carries — so the policy reaches the sentry over a tunnel and through the
contract, and not through a flag.

    root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry
                         │                                          Policy.Narrow
                         └──tunnel──▶ tunneld b ──▶ the exit ──▶ the real network

## The three policies

| what | sha256 | bytes |
|---|---|---|
| P0, the whole table | `db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7` | 199 |
| P0 without the model endpoint (the control's) | `8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b` | 156 |
| P1, P0 without the document host (the narrowing) | `36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d` | 155 |

```
P0 = {"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]},
      {"host":"www.rfc-editor.org","ports":[443]}],"f":[{"path":"./summary.txt","modes":["w"]}],
      "x":[{"path":"/agent-probe"}]}
```

`x` names the workload by its path inside the rootfs. **It was enforced on
nothing**: the sentry execs the first process itself, before any policy can
land, and `agent-probe` execs nothing afterwards — every run's strace digest
says `0 execs`. `x` was parsed, subset-checked and carried in the digest, and
the exec sink it installed never saw a call. X is exercised in the adapter check
(`../adapter-check/notes.md` §5) and measured in spike E2; it is not exercised
here and the record must not read as though it were. `f` is tracked and enforced
by nothing but the mounts, the same as everywhere else.

## (a) on-policy — the task completes under the policy

    PUSH sha256=db453844…fdd7 returned after 114ms on attempt 2, 363ms into the run
    a  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe…fdd7
    tunnel narrow: sha256=db45384408fe…fdd7 n=2 of 2 names kept x=1 f=1
    tunnel narrow: applied in 740.203µs, of which the table swap was 87.861µs
    TIMING tunnel_open=552ms first_connect=566ms first_byte=599ms task_end=9.813s

The agent, which knows none of this is there:

    request 1: stop_reason=tool_use input_tokens=657 output_tokens=86 in 2.534s
      tool_use fetch_url {"url":"https://www.rfc-editor.org/rfc/rfc8446.txt"} -> 20502 bytes, is_error=false
    request 2: stop_reason=tool_use input_tokens=6920 output_tokens=436 in 5.329s
      tool_use write_file {"path":"summary.txt",…} -> 31 bytes, is_error=false
    request 3: stop_reason=end_turn input_tokens=7377 output_tokens=5 in 1.104s
    final text: DONE
    totals: input_tokens=14954 output_tokens=527    cost: $0.035178    wall time: 9.296s

runsc exited 0. Both destinations were reached over the tunnel, the exit saw
host, port and ciphertext, and the seccheck receiver printed nothing because
nothing was refused.

## (b) off-policy control — the refusal is the push and not the table

Same table, both names in it. The push leaves the model's endpoint out:

    tunnel narrow: api.anthropic.com:443 at 100.64.1.0 is gone
    tunnel narrow: 1 of 2 names kept
    tunnel narrow: applied in 2.695648ms, of which the table swap was 511.873µs

and the agent, whose first act is a model request, gets — **verbatim** —

    agent-probe: request 1: Post "https://api.anthropic.com/v1/messages": dial tcp:
      lookup api.anthropic.com on 127.0.0.53:53: no such host

with the sentry's own account of why:

    egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=…20:09:02.400578637Z
    egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=…20:09:02.406124663Z

Two events for one name because the resolver asks A and AAAA. `TIMING
tunnel_open=never first_connect=never first_byte=never task_end=500ms`: no
stream reached the exit, nothing was sent to the model, and **this run cost
nothing**. The refusal landed at the resolver (NXDOMAIN, which Go reports as
`no such host`) and not at the connect, so no `connect` failed and there is no
`ENETUNREACH` in this run — which is the same finding ticket 25 recorded for
the table and is now true of a policy.

## (c) a narrowing while the task is running

    tunnel_open at 1.519s        the exit accepts the stream of the first model request
    2.188s   root  pushes P0                       ack, applied in 894.404µs, swap 106.309µs
    2.254s   root2 pushes P1                       ack, applied in 589.709µs, swap 137.646µs
             tunnel narrow: www.rfc-editor.org:443 at 100.64.1.1 is gone
             tunnel narrow: 1 of 2 names kept
    2.292s   root3 pushes P0 again                 REFUSED

The narrowing landed **735 ms after the exit accepted the first stream** and
1.9 s before the model's first answer came back, so the document host was gone
before the agent ever asked for it. What the agent did with that is the most
interesting thing in this directory:

    request 1: tool_use fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt -> 127 bytes, is_error=true
    request 2: tool_use fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt -> 127 bytes, is_error=true
    request 3: tool_use fetch_url https://www.ietf.org/rfc/rfc8446.txt        -> 115 bytes, is_error=true
               tool_use fetch_url http://www.rfc-editor.org/rfc/rfc8446.txt   -> 126 bytes, is_error=true
    request 4: tool_use write_file summary.txt -> 31 bytes, is_error=false
    request 5: stop_reason=end_turn
    final text: DONE

It retried the same URL, then tried a **different host** and then the same host
over plain HTTP, and when all four were refused it wrote a summary of RFC 8446
from its own knowledge and reported `DONE`. The run therefore looks, from
outside, like a task that succeeded: runsc exited 0 and the last word is the one
the prompt asked for. This is ticket 23's finding — *a denied tool is not a
failed task* — reproduced with the enforcement below the runtime rather than in
it, and it is the strongest argument in this ticket for why a transcript is not
evidence and the sentry's log is.

The sentry refused all four, by name:

    egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name  ×6
    egress_refused protocol=dns name=www.ietf.org       reason=unknown-name  ×2

`www.ietf.org` was refused by the **boot table**, which never carried it, and
`www.rfc-editor.org` by the **policy**, which removed it. The event does not say
which, and nothing in it could: both are `unknown-name`.

The exact words the agent was given cannot be read off the transcript —
`agent-probe` prints a tool result's length and not its bytes — but the lengths
pin them exactly. The tool result is `"fetch_url: " + err.Error()`
(`attest/cmd/agent-probe/agent.go:403`), and

    fetch_url: Get "https://www.rfc-editor.org/rfc/rfc8446.txt": dial tcp: lookup
      www.rfc-editor.org on 127.0.0.53:53: no such host

is 127 bytes, the `https://www.ietf.org/…` form is 115 and the `http://` form is
126 — the three lengths the transcript records. The wording is the one run (b)
printed to stderr verbatim for its own name.

**The first peer's tunnel goes, and the workload does not.** 185 ms after the
narrowing was acknowledged:

    SANDBOX liveness lost: it pulsed 36cce26e…c37d, expected db453844…fdd7
    REFUSED verification refused: the policy pushed to the peer is no longer live:
      a peer at 127.0.0.1:41414 pushed a policy this sandbox no longer enforces:
      it pulsed 36cce26e…c37d, expected db453844…fdd7

That is the eleventh reason reached by a digest mismatch rather than by a
silence, on a sandbox that was alive and working throughout: runsc exited 0
after 17.97 s, having started one process and finished the same one. 185 ms is
within the bound the design gives it — a watch looks every quarter of a pulse
(`sandbox.watchInterval`), so ≤250 ms.

**The widening is refused, and the sentence naming the component stays here.**

    a's log:  … pushed a policy this sandbox did not apply: sandbox: policy refused:
              the sandbox refused it: policy refused: it widens n by [net:www.rfc-editor.org:443]
    the peer: attest: verification failed
              … "a" at 127.0.0.1:49791 did not apply the policy pushed to it:
              the peer refused it: the sandbox beside this tunneld did not apply it

**This is worth stating plainly because a reader will look in the wrong place.**
The sentence that names the component is written in the guest's refusal log and
does not cross the tunnel. What the pusher is told is one fixed sentence,
`the sandbox beside this tunneld did not apply it` (`attest/tunneld/push.go`,
`ackRefused`), and `attest.Refusal.Error()` is `attest: verification failed`
with the rest in `LogString()`. That is deliberate — which of its own reasons a
guest refused for is a fact about that guest — and it means a peer cannot tell a
widening from a sandbox that was not ready. See the window below, which is the
same fact from the other side.

## (d) liveness teardown, twice

| how the workload ended | runsc exited | loss reported | tunnel refused | what the loss said |
|---|---|---:|---:|---|
| the task finished (run a) | 16:09:14.376 | **+50 ms** | **+50 ms** | `the sandbox closed its socket` |
| `runsc kill … KILL` mid-task | 16:09:37.226 | **+33 ms** | **+33 ms** | `the sandbox closed its socket` |

Both are the fast case the design names: the workload ends, the sentry goes, the
helper's fd-3 link ends, the helper closes its tunneld client, the attachment
goes, and the next quarter-pulse reports it. The killed run was stopped 393 ms
into the run, 2 ms after the exit had accepted its first stream (`tunnel_open=391ms`,
the harness's own transcript in the README); runsc exited 137 after 515 ms and
the model request in flight was never answered, so it has no cost to report.

The mismatch in (c) at 185 ms and these two at 33–50 ms bracket the quarter-pulse
granularity from both ends. Nothing here waited three seconds, because nothing
here went quiet — that case is spike E3's.

## What a push costs, and the window before it

| run | handshakes | cold Open (pusher) | `Apply` at `a` | `Policy.Narrow` | table swap |
|---|---:|---:|---:|---:|---:|
| off-policy | 3 | 75 ms | 38.723 ms | 2.696 ms | 511.9 µs |
| on-policy | 2 | 114 ms | 56.883 ms | 740.2 µs | 87.9 µs |
| narrowed, first | 1 | 51 ms | 3.901 ms | 894.4 µs | 106.3 µs |
| narrowed, second | 1 | 66 ms | 3.285 ms | 589.7 µs | 137.6 µs |
| narrowed, third (refused) | 1 | 38 ms | 2.014 ms | — | — |
| killed | 3 | 70 ms | 41.824 ms | 2.314 ms | 142.4 µs |

The first `Apply` in a sandbox's life is 35–57 ms and every later one in the same
sandbox is 2–4 ms: the control socket has never been dialled before, which is
exactly the shape spike E1 measured over twenty-four pushes and the adapter
check saw again. The sentry's own half is under a millisecond after the first,
and the table swap — the part a running workload is exposed to — is 88–512 µs.

**The window.** A policy cannot be applied to a loader that has not started its
workload (`runsc/boot/policy.go:106`), and a push made before that is refused
and *takes its tunnel with it*, so a retry is a fresh handshake. A sandbox
becomes ready in four steps and a push can arrive between any two of them; the
harness therefore pushes back to back until one lands, and records how many
handshakes it burned. What the sandbox's first milliseconds run under is the
boot table and nothing else:

| run | workload started | policy landed | window | the workload's first query |
|---|---|---|---:|---|
| off-policy | 16:09:02.281193 | 16:09:02.284043 | **3 ms** | 119 ms after it started, 116 ms after the policy |
| on-policy | 16:09:04.924477 | 16:09:04.925405 | **1 ms** | 129 ms after it started, 128 ms after the policy |
| narrowed | 16:09:17.721578 | 16:09:18.774680 | **1.053 s** | 365 ms after it started, 688 ms *before* the policy |
| killed | 16:09:37.003528 | 16:09:37.005876 | **2 ms** | 91 ms after it started, 89 ms after the policy |

**This is a finding and not a harness artefact.** Three of the four runs closed
the window in one to three milliseconds; the fourth took a second, on the same
machine, with the same code, because the helper took a second to attach under
load. There is no way to be in front of it: the workload starts when the sentry
starts it, and there is no verb in this design that says "start the workload
under this policy". What governs until the push lands is `--tunnel-table`, which
is the ceiling every push narrows — so the guarantee the arrangement actually
offers is *"no wider than the boot table from the first instruction, and no
wider than P from the moment P lands"*, and the record should say that rather
than "the workload ran under P".

## What this does not say

Nothing about attestation: the platform is `internal/snpfake` and the verifier
is a fixture, so the 38–114 ms "cold Open" above is a QUIC handshake plus a
fixture's arithmetic and **is not an attestation cost**. Nothing about a
measured guest: there is no TEE here and no guest execution overhead to read.
Nothing about X, which nothing exercised. Nothing about two peers over a real
network. `rq5-loopback.md` beside this file says which of RQ5's six components
these runs can speak to and which they cannot.

## Files

| file | what |
|---|---|
| `run.sh` | the run, exactly as run |
| `20260918-160939/README.md` | written by the harness: every push, every refusal, every event, per run |
| `20260918-160939/output-01-governed-loopback.txt` | the untrimmed test transcript |
| `20260918-160939/<run>/` | one directory per sandbox: stdout, stderr, table, seccheck, strace digest, all five debug logs |
| `rq5-loopback.md` | the RQ5 components these runs can and cannot measure |
| `../spikes/E4/` | the same arrangement with Claude Code as the workload |
