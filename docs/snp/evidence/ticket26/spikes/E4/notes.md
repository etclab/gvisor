# E4 — Claude Code under a policy: what the task did, every refusal, and whether anyone outside can tell

Ticket 26's fourth experiment, run on the workstation on 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t26`, branch
`ticket-26-the-sandbox-honors-a-pushed-policy`. No sudo and no hardware. It is
the only thing in this ticket that spends money on a shipped agent runtime, and
it is **also the definition of done's "Claude Code governed run"** — governed-1,
governed-2 and governed-3 below are that run, three times, and there is no
separate `claude-governed/` directory.

The ticket asks: *Claude Code headless under a pushed policy whose `n` is the API
host and nothing else, on ticket 25's E4 host list. Record the task's outcome,
every refusal with its errno, and whether the run is distinguishable from an
unrestricted one from the outside.* The answers are: it completed, there is no
errno, and no — not from inside the guest, and only by one stream from outside.

## Setup

| thing | value |
|---|---|
| runsc | `make runsc` `-c opt`, sha256 `6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819` |
| harness | `attest/cmd/agent-probe/governed_test.go`, `TestClaudeGoverned` |
| Claude Code | version `2.1.276`, the ELF, the same one ticket 25's smoke ran |
| command | `claude -p "Reply with exactly the word OK." --output-format json --model claude-haiku-4-5-20251001` |
| seccheck-receiver | `../../tools/seccheck-receiver/`, sha256 `d7be04465f899c4af6f5c94de2307cde5bd220679497db2455ea085189d509dd` |
| table | `api.anthropic.com:443` **and** `http-intake.logs.us5.datadoghq.com:443`, in all four runs |
| policy | `{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[],"x":[]}` |
| | 94 bytes, sha256 `b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d` |

Reproduced by `./run.sh`; `20260918-161409/` is the run these numbers come from,
with `README.md` written by the harness and `output-01-claude-under-a-policy.txt`
the untrimmed test transcript.

The table is ticket 25's E4 host list, unchanged, so **the push is the only
difference**: it narrows `n` by the log intake, which the CLI contacts on a
fresh HOME with no opt-in and which a table built from `agent-probe` alone would
have missed. `f` and `x` are empty, so exec stays unconstrained — a shipped
runtime forks `git` and re-execs itself as `rg`, and constraining that is spike
E2's question and not this one.

Three governed runs and one unrestricted, in that order, on the same afternoon,
against the same binary in the same rootfs behind the same exit.

## 1. The task's outcome: it completed, four times out of four

| run | policy | result | `is_error` | turns | cost | wall | of it API | runsc | streams at the exit | intake dialled |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| governed-1 | pushed | `OK` | false | 1 | $0.003206 | 8.973 s | 2210 ms | 0 | 8 | no |
| governed-2 | pushed | `OK` | false | 1 | $0.003286 | 9.014 s | 2653 ms | 0 | 8 | no |
| governed-3 | pushed | `OK` | false | 1 | $0.003201 | 8.359 s | 2302 ms | 0 | 8 | no |
| unrestricted | none | `OK` | false | 1 | $0.003236 | 8.767 s | 2462 ms | 0 | 9 | yes |

$0.012931 for the four, as the CLI reported it. The governed runs are *inside*
the unrestricted run's wall time, not beside it: 8.359–9.014 s against 8.767 s.

This is the answer ticket 23 asked for on the other side of the fence. There, a
denied tool was not a failed task and the runtime reported success anyway; here
the enforcement is below the runtime, the destination is gone at the resolver,
and **the task still succeeds** — because the destination that was taken away
was not one the task needed. What that shows is not that enforcement is weak: it
is that *task outcome is not a channel for policy*, and an operator who wants to
know whether a policy bit has ever mattered must read the sentry and not the
agent.

## 2. Every refusal, and why there is no errno

Every governed run refused exactly the same thing, twice:

    tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
    tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name

    egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name
      time=2026-09-18T20:13:34.428068546Z
    egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name
      time=2026-09-18T20:13:34.429986404Z

Twice for one name because glibc's resolver asks A and AAAA; the responder
answers NXDOMAIN to both. The name table the sentry answered from says the rest:

| name | queries | types | answers, governed | answers, unrestricted |
|---|---:|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | `100.64.1.0`, `noerror-empty` | `100.64.1.0`, `noerror-empty` |
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | **`nxdomain`** | `100.64.1.1`, `noerror-empty` |

**There is no errno.** The ticket asks for every refusal "with its errno", and
the honest answer is that this refusal has none. A name the policy in force does
not carry is answered NXDOMAIN by the responder inside the sentry; glibc turns
that into `EAI_NONAME` from `getaddrinfo`, which is a library result and not a
failed system call. No `connect` is attempted, so `ENETUNREACH` — the errno the
design gives an off-policy *address* — never happens. The errno only appears
when a workload dials a synthetic address it resolved before the narrowing
(`reason=not-in-table`, spike E1 §2); a program that resolves at the moment it
dials never sees one.

The CLI made **one** attempt at the intake and did not retry it. It logged
nothing about it on stdout and the result JSON does not mention it.

## 3. Distinguishable from the outside?

| what is compared | governed | unrestricted |
|---|---|---|
| the task's result | `OK`, `is_error=false` | `OK`, `is_error=false` |
| runsc's exit status | 0, 0, 0 | 0 |
| wall | 8.973 s, 9.014 s, 8.359 s | 8.767 s |
| streams the exit accepted | 8, 8, 8 | **9** |
| destinations the exit dialled | `api.anthropic.com:443` | `api.anthropic.com:443`, `http-intake.logs.us5.datadoghq.com:443` |
| `sentry/egress_refused` events | **2** | 0 |

And inside the guest, where an observer would look first — the `## syscalls that
failed` tally of the `--strace` log, governed-1 against unrestricted, every row
that differs:

```
governed unrestricted  syscall
     171      138  futex errno=11 (try again)
     143      145  futex errno=110 (connection timed out)
      11       16  futex errno=512 (to be restarted if SA_RESTART is set)
       8        2  futex errno=516 (interrupted by signal)
     278      276  openat errno=2 (no such file or directory)
      16       14  recvfrom errno=11 (request would block)
```

Six rows, all of them scheduler noise: futex wakeups, a couple of `openat`s, a
couple of non-blocking reads. **Not one network syscall differs.** Neither run
has a failed `sendto` or a failed `socket`, and the only failed `connect` in
either is the same pair of `connect errno=2 (no such file or directory)` — an
`AF_UNIX` path that is not there — present identically in both. The two traces
of a 232 MB agent runtime, one of which was refused a destination it tried to
use, are the same trace.

**The verdict.** Distinguishable from the *sentry's* side, exactly and by name:
two events that say which name, which protocol and which reason. Distinguishable
from the *exit's* side, weakly: one stream fewer, which an observer would have
to know to expect. Not distinguishable from the task's outcome, its exit status,
its wall time or its cost. Not distinguishable at all from inside the guest by
anything a syscall trace can see.

That cuts both ways and the record should say both. It is a good property — a
policy that silently removes a destination does not hand the workload a
fingerprint of what is being enforced on it, which is the shape a workload that
wanted to detect and adapt would need. And it is a warning — nothing in the
task's own output will ever tell an operator that a policy bit fired, so the
seccheck sink is not a debugging convenience, it is the only channel.

## 4. What the push cost

| run | handshakes | cold Open (pusher) | `Apply` at `a` | `Policy.Narrow` | table swap | landed |
|---|---:|---:|---:|---:|---:|---:|
| governed-1 | 3 | 99 ms | 52.443 ms | 2.052 ms | 884.8 µs | 349 ms into the run |
| governed-2 | 3 | 123 ms | 65.721 ms | 824.4 µs | 201.9 µs | 384 ms into the run |
| governed-3 | 4 | 78 ms | 35.231 ms | 1.323 ms | 530.8 µs | 403 ms into the run |

Each run's first stream reached the exit at 2.397–2.64 s, so the policy was in
force for about two seconds before the CLI opened anything, and the intake query
came later still. The handshake count is the window described in
`../../loopback/notes.md`: a push made before the sentry has started the
workload is refused and takes its tunnel with it, so a peer that wants to govern
from the first instruction retries, and three or four handshakes is what that
cost here.

The cold Open is a QUIC handshake against the fake SNP platform with a fixture
verifier. **It is not an attestation cost and must not be quoted as one.**

## 5. What this does not say

Nothing about attestation, a measured guest, or a real network: the tunnelds are
in the test's own process. Nothing about `x` — it is empty here, and Claude Code
forks `git` and re-execs itself as `rg` unconstrained; whether `{path|sha256}`
can name those identities is spike E2's answer and not this one. Nothing about
`f`. Nothing about what the CLI would do if the *model* endpoint were taken away
mid-run — the loopback proof's `narrowed` run answers that question for
`agent-probe` and nobody has asked it of this runtime.

## 6. Files

| file | what |
|---|---|
| `run.sh` | the run, exactly as run |
| `20260918-161409/README.md` | written by the harness: the four runs, the push, the asked-for list, every refusal, the comparison |
| `20260918-161409/output-01-claude-under-a-policy.txt` | the untrimmed test transcript |
| `20260918-161409/<run>/` | one directory per sandbox: stdout, stderr, table, seccheck, strace digest, all five debug logs |
| `../../loopback/notes.md` | the same arrangement with `agent-probe` as the workload, and the narrowing-mid-run and teardown cases |
