# A pushed policy inside the sandbox, over loopback: 2026-09-21T20:50:50-04:00

runsc is `/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc`
(sha256 `49740e434b42e1c1d65546258f2bcbd16134469cf8ea72190321a353daf9823c`); the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,www.rfc-editor.org:443`.

Five runsc sandboxes, one after the other, sharing a rootfs, a bundle shape, an exit, an allow list and a `--tunnel-table` that names both destinations. What differs is the policy a third tunneld pushes at `a` — once the sandbox has attached to its socket, or before it attaches in early-push — and when a second and a third peer arrive. The workload is this package built with `CGO_ENABLED=0` and run as `/agent-probe -network plain -task summarize -without-model -dir /tmp`: no contract, no dialer of its own, Go's own resolver, and nothing in it knows a policy exists.

**The model was not called in these runs.** `-without-model` leaves out the one step that needs a key and nothing else: the model endpoint is requested for real over the same client and therefore the same tunnel, with the body the loop builds and no `x-api-key` header, so what it answers is an authentication error — and a status that came back at all is a stream that crossed the tunnel and an exit that dialled `api.anthropic.com:443`. The document host is then fetched the way the `fetch_url` tool fetches it. No number below is a token count, a cost or a summary, because no model was asked; each run ends in `NO-MODEL DONE`, whose figures are the statuses and byte counts measured.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| off-policy | `api.anthropic.com:443, www.rfc-editor.org:443` | 1 | 551ms | `tunnel_open=never first_connect=never first_byte=never task_end=551ms` |
| on-policy | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 6.261s | `tunnel_open=581ms first_connect=593ms first_byte=619ms task_end=6.261s` |
| narrowed | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 5.876s | `tunnel_open=469ms first_connect=480ms first_byte=503ms task_end=5.876s` |
| killed | `api.anthropic.com:443, www.rfc-editor.org:443` | 137 | 665ms | `tunnel_open=538ms first_connect=550ms first_byte=573ms task_end=665ms` |
| early-push | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 6.069s | `tunnel_open=431ms first_connect=442ms first_byte=468ms task_end=6.069s` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## off-policy

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1782914161/off-policy-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1782914161/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback569555736/001/off-policy/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback569555736/001/off-policy/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback569555736/001/off-policy/debug/ --strace run --bundle /dev/shm/t25-1782914161/off-policy t25-off-policy-536947
```

The exit saw nothing: no stream reached it in this run.

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: api.anthropic.com:443 at 100.64.1.0 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b n=1 of 2 names kept x=1 f=1
tunnel narrow: applied in 1.30174ms, of which the table swap was 204.315µs
tunnel dns: q="api.anthropic.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
tunnel dns: q="api.anthropic.com" type=A answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1782914161/off-policy.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:50:21.204289441Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:50:21.206211095Z
disconnected
```

## on-policy

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1782914161/on-policy-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1782914161/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback569555736/001/on-policy/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback569555736/001/on-policy/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback569555736/001/on-policy/debug/ --strace run --bundle /dev/shm/t25-1782914161/on-policy t25-on-policy-536947
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed www.rfc-editor.org:443 -> 104.18.20.81:443
EXIT api.anthropic.com:443 ended
EXIT www.rfc-editor.org:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 1.031036ms, of which the table swap was 140.339µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 68.668256ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=noerror-empty
tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 17.445422ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1782914161/on-policy.events
connected: the sentry speaks wire version 1
disconnected
```

## narrowed

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1782914161/narrowed-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1782914161/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback569555736/001/narrowed/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback569555736/001/narrowed/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback569555736/001/narrowed/debug/ --strace run --bundle /dev/shm/t25-1782914161/narrowed t25-narrowed-536947
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 19.159666ms, host fd 37, local 100.64.0.1:40001
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 774.995µs, of which the table swap was 40.28µs
tunnel narrow: www.rfc-editor.org:443 at 100.64.1.1 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d n=1 of 2 names kept x=1 f=1
tunnel narrow: applied in 647.865µs, of which the table swap was 147.009µs
tunnel dns: q="www.rfc-editor.org" type=A answer=nxdomain
tunnel: refused dns :0 name="www.rfc-editor.org" reason=unknown-name
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="www.rfc-editor.org" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1782914161/narrowed.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:50:37.530052981Z
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:50:37.531966683Z
disconnected
```

## killed

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1782914161/killed-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1782914161/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback569555736/001/killed/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback569555736/001/killed/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback569555736/001/killed/debug/ --strace run --bundle /dev/shm/t25-1782914161/killed t25-killed-536947
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 2.150585ms, of which the table swap was 178.015µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.045615ms, host fd 37, local 100.64.0.1:40001
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1782914161/killed.events
connected: the sentry speaks wire version 1
disconnected
```

## early-push

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1782914161/early-push-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1782914161/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback569555736/001/early-push/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback569555736/001/early-push/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback569555736/001/early-push/debug/ --strace run --bundle /dev/shm/t25-1782914161/early-push t25-early-push-536947
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed www.rfc-editor.org:443 -> 104.18.21.81:443
EXIT www.rfc-editor.org:443 ended
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 949.035µs, of which the table swap was 103.484µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.634432ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=noerror-empty
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 15.355407ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1782914161/early-push.events
connected: the sentry speaks wire version 1
disconnected
```

## The policies

| what | sha256 | bytes |
|---|---|---|
| P0, the whole table | `db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7` | 199 |
| P0 without the model endpoint (the control's) | `8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b` | 156 |
| P1, P0 without the document host (the narrowing) | `36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d` | 155 |

```
P0 = {"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]},{"host":"www.rfc-editor.org","ports":[443]}],"f":[{"path":"./summary.txt","modes":["w"]}],"x":[{"path":"/agent-probe"}]}
```

## What was not run

The workload ran with `-without-model`, so the model was never called: the run needs no `ANTHROPIC_API_KEY` and none was read. Every leg of the path is measured except the model's answer. The request to `https://api.anthropic.com/v1/messages` is made with the body the loop builds and without the key header, so the status in each run's transcript is the API's answer to an unauthenticated request; a status that arrived is a stream that crossed the tunnel and an exit that dialled `api.anthropic.com:443`. The document fetch that follows is the `fetch_url` tool's, over the same client, and the byte count is what was read. Nothing in this record is model output, and the gap between the two requests is the fixed `withoutModelPause` rather than a model thinking.

## off-policy — the refusal is the push and not the table

The table is `api.anthropic.com:443, www.rfc-editor.org:443` and the policy pushed is `n = [www.rfc-editor.org:443]`. The workload was refused at the resolver (`no such host`, which is NXDOMAIN), runsc ended with status 1 after 551ms, and the exit was never asked to dial api.anthropic.com — so **the refusal is the pushed policy's and not the table's**, which is the whole of what this control says.

What the workload said, in its own words:

```
PLAIN no contract, no dialer of this program's own, net/http's default transport and the ordinary resolver; proxy variables set in this environment: none
WITHOUT-MODEL no model is called in this run and no key is read: the request to https://api.anthropic.com/v1/messages carries the body the loop builds and no x-api-key header, so the status it answers with is an authentication error and what that status proves is the reach of the path and not the model's work. There are no tokens, no cost and no summary below, and the gap before the document fetch is a fixed 5s.
task=summarize
prompt="Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at most five sentences, and save the summary to the file summary.txt in the current directory using write_file. Then reply with the word DONE."
endpoint=https://api.anthropic.com/v1/messages tools=2
model endpoint https://api.anthropic.com/v1/messages: Post "https://api.anthropic.com/v1/messages": dial tcp: lookup api.anthropic.com on 127.0.0.53:53: no such host
agent-probe: requesting https://api.anthropic.com/v1/messages without a key: Post "https://api.anthropic.com/v1/messages": dial tcp: lookup api.anthropic.com on 127.0.0.53:53: no such host
```

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-off` | `8448109a…966b` | 1 | 213ms | 161.905ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:50:21.103635  tunnel narrow: applied in 1.30174ms, of which the table swap was 204.315µs
```

**The window.** The sentry started the workload at 20:50:21.101841 and the first policy landed at 20:50:21.103590, so **2ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 102ms after it started, and the policy was 100.603ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1782914161/off-policy.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:50:21.204289441Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:50:21.206211095Z
disconnected
```

## on-policy — the task completes under the policy, and its end ends the tunnel

`TIMING tunnel_open=581ms first_connect=593ms first_byte=619ms task_end=6.261s`, and the task completed: runsc ended with status 0 after 6.261s, `NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480 in 5.707s`. Every stream the exit carried is in the run's section above.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-on` | `db453844…fdd7` | 1 | 224ms | 172.024ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:50:23.749623  tunnel narrow: applied in 1.031036ms, of which the table swap was 140.339µs
```

**The window.** The sentry started the workload at 20:50:23.748246 and the first policy landed at 20:50:23.749576, so **1ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 130ms after it started, and the policy was 128.713ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with the workload exiting, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:55766 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:50:29.618; the loss was reported **134ms after** that and the tunnel was refused **134ms after** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1782914161/on-policy.events
connected: the sentry speaks wire version 1
disconnected
```

## narrowed — a second peer removes a destination while the task is running

The sentry's own account of the two policies that landed, and of the name the second one removed:

```
20:50:32.285219  tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
20:50:32.343410  is gone
20:50:32.343633  tunnel narrow: sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d n=1 of 2 names kept x=1 f=1
```

The narrowing landed 132ms after the exit accepted the first stream, and the workload's second request is a fixed 5s after its first — so the document host was **not** dialled after the name went, and what the workload saw was:

```
tool fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt: Get "https://www.rfc-editor.org/rfc/rfc8446.txt": dial tcp: lookup www.rfc-editor.org on 127.0.0.53:53: no such host
NO-MODEL DONE model_status=401 model_bytes=141 doc_status=none doc_bytes=0 in 5.37s
```

**The narrowing is not read as a mismatch.** The sandbox pulses the new policy's digest from the moment it takes it, and the watch over the old one is retired before the new one is pushed — so nothing is lost while the workload runs, and the one loss reported is the workload's own exit, 5.309s after the narrowing landed:

```
SANDBOX liveness lost: the sandbox closed its socket
```

This is the one place this run differs from ticket 26's, where the first peer's tunnel was torn down as a mismatch and the number recorded was how long that took. Reading a lawful narrowing as a loss now costs the sandbox rather than one tunnel, so it is not read as one — and the first peer, whose policy is no longer the one in force, keeps its tunnel and is told nothing. That is a finding and not an assertion of this run.

And the third peer, pushing P0 again at a sandbox now holding P1, is refused. The sentence naming the component is `a`'s and stays there:

```
20:50:32.403562  REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:58743 pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it: policy refused: it widens n by [net:www.rfc-editor.org:443]
```

What the peer is told is the fixed sentence the boundary carries back, and not which component widened — that is a fact about this guest, and the peer supplied the document rather than the machine (`attest/tunneld/push.go`, `ackRefused`):

```
attest: verification failed
```

The third peer's own refusal log: `verification refused: the policy pushed to the peer was not applied: "a" at 127.0.0.1:60272 did not apply the policy pushed to it: the peer refused it: the sandbox beside this tunneld did not apply it`

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-narrowed` | `db453844…fdd7` | 1 | 51ms | 3.803ms | acknowledged |
| `root2-narrowed` | `36cce26e…c37d` | 1 | 58ms | 3.713ms | acknowledged |
| `root3-narrowed` | `db453844…fdd7` | 1 | 58ms | 2.905ms | refused |

And the sentry's own, one line per policy it accepted:

```
20:50:32.285242  tunnel narrow: applied in 774.995µs, of which the table swap was 40.28µs
20:50:32.343710  tunnel narrow: applied in 647.865µs, of which the table swap was 147.009µs
```

**The window.** The sentry started the workload at 20:50:32.097367 and the first policy landed at 20:50:32.285219, so **188ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 104ms after it started, and the policy was 83.876ms after it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1782914161/narrowed.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:50:37.530052981Z
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:50:37.531966683Z
disconnected
```

## killed — the same teardown, reached with `runsc kill`

`runsc kill t25-killed-536947 KILL` was sent 539ms into the run, while the first model request was in flight. runsc ended with status 137 after 665ms.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-killed` | `db453844…fdd7` | 1 | 206ms | 144.259ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:50:40.127934  tunnel narrow: applied in 2.150585ms, of which the table swap was 178.015µs
```

**The window.** The sentry started the workload at 20:50:40.125245 and the first policy landed at 20:50:40.127658, so **2ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 153ms after it started, and the policy was 150.987ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with `runsc kill`, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:43244 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:50:40.416; the loss was reported **215ms after** that and the tunnel was refused **215ms after** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1782914161/killed.events
connected: the sentry speaks wire version 1
disconnected
```

## early-push — the push arrives before the sandbox attaches

The push was made at `a` before `runsc` was started: the pusher's handshake was already done and its document already inside `Host.Apply` when the sandbox was created, which is what the harness holds the two in order for. `Host.Apply` waited there for an enforcing attachment, handed it the document, and acknowledged only once the sentry had applied it.

| moment | clock | when |
|---|---|---|
| `Host.Apply` entered at `a` | a's goroutine | 20:50:42.634038 |
| `SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing` | a's console | 20:50:42.825973 |
| `SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7` | a's console | 20:50:43.004720 |
| `Host.Apply` acknowledged the push | a's goroutine | 20:50:43.004855 |
| the pusher's `PUSH` line: `Peer` returned | the pusher | 20:50:43.005616 |

The push was entered **192ms** before the enforcing sandbox attached, and acknowledged **179ms** after it, having been made once. The workload then ran governed and completed: runsc ended with status 0 after 6.069s, `NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480 in 5.598s`.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-early` | `db453844…fdd7` | 1 | 410ms | 370.78ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:50:43.003759  tunnel narrow: applied in 949.035µs, of which the table swap was 103.484µs
```

**The window.** The sentry started the workload at 20:50:43.002270 and the first policy landed at 20:50:43.003693, so **1ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 103ms after it started, and the policy was 101.479ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with the workload exiting, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:57828 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:50:48.757; the loss was reported **2ms before** that and the tunnel was refused **2ms before** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1782914161/early-push.events
connected: the sentry speaks wire version 1
disconnected
```

## a's console, in full

Every line `a` wrote, with the second it was written in. `SANDBOX applied` is one per acknowledged push, `PUSH` is a pusher's own account of its round trip, and `REFUSED` is `a`'s refusal log.

```
20:50:20.891  SANDBOX attached on /dev/shm/t25-1782914161/a.sock
20:50:20.891  SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing
20:50:21.105  SANDBOX applied format=policy version=1 bytes=156 sha256=8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b
20:50:21.107  PUSH root-off sha256=8448109a…966b cold_open=213ms apply=161.905ms tries=1 err=<nil>
20:50:21.356  SANDBOX liveness lost: the sandbox closed its socket
20:50:21.357  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:44405 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:50:23.526  SANDBOX attached on /dev/shm/t25-1782914161/a.sock
20:50:23.526  SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing
20:50:23.750  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:50:23.751  PUSH root-on sha256=db453844…fdd7 cold_open=224ms apply=172.024ms tries=1 err=<nil>
20:50:29.751  SANDBOX liveness lost: the sandbox closed its socket
20:50:29.752  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:55766 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:50:31.879  SANDBOX attached on /dev/shm/t25-1782914161/a.sock
20:50:31.879  SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing
20:50:32.286  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:50:32.287  PUSH root-narrowed sha256=db453844…fdd7 cold_open=51ms apply=3.803ms tries=1 err=<nil>
20:50:32.345  SANDBOX applied format=policy version=1 bytes=155 sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d
20:50:32.346  PUSH root2-narrowed sha256=36cce26e…c37d cold_open=58ms apply=3.713ms tries=1 err=<nil>
20:50:32.403  REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:58743 pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it: policy refused: it widens n by [net:www.rfc-editor.org:443]
20:50:32.404  PUSH root3-narrowed sha256=db453844…fdd7 cold_open=58ms apply=2.905ms tries=1 err=attest: verification failed
20:50:37.654  SANDBOX liveness lost: the sandbox closed its socket
20:50:37.654  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:49525 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:50:39.922  SANDBOX attached on /dev/shm/t25-1782914161/a.sock
20:50:39.923  SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing
20:50:40.129  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:50:40.131  PUSH root-killed sha256=db453844…fdd7 cold_open=206ms apply=144.259ms tries=1 err=<nil>
20:50:40.630  SANDBOX liveness lost: the sandbox closed its socket
20:50:40.631  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:43244 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:50:42.825  SANDBOX attached on /dev/shm/t25-1782914161/a.sock
20:50:42.825  SANDBOX attached on /dev/shm/t25-1782914161/a.sock role=enforcing
20:50:43.004  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:50:43.005  PUSH root-early sha256=db453844…fdd7 cold_open=410ms apply=370.78ms tries=1 err=<nil>
20:50:48.755  SANDBOX liveness lost: the sandbox closed its socket
20:50:48.756  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:57828 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```


