# A pushed policy inside the sandbox, over loopback: 2026-09-21T20:38:15-04:00

runsc is `/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc`
(sha256 `49740e434b42e1c1d65546258f2bcbd16134469cf8ea72190321a353daf9823c`); the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,www.rfc-editor.org:443`.

Five runsc sandboxes, one after the other, sharing a rootfs, a bundle shape, an exit, an allow list and a `--tunnel-table` that names both destinations. What differs is the policy a third tunneld pushes at `a` — once the sandbox has attached to its socket, or before it attaches in early-push — and when a second and a third peer arrive. The workload is this package built with `CGO_ENABLED=0` and run as `/agent-probe -network plain -task summarize -without-model -dir /tmp`: no contract, no dialer of its own, Go's own resolver, and nothing in it knows a policy exists.

**The model was not called in these runs.** `-without-model` leaves out the one step that needs a key and nothing else: the model endpoint is requested for real over the same client and therefore the same tunnel, with the body the loop builds and no `x-api-key` header, so what it answers is an authentication error — and a status that came back at all is a stream that crossed the tunnel and an exit that dialled `api.anthropic.com:443`. The document host is then fetched the way the `fetch_url` tool fetches it. No number below is a token count, a cost or a summary, because no model was asked; each run ends in `NO-MODEL DONE`, whose figures are the statuses and byte counts measured.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| off-policy | `api.anthropic.com:443, www.rfc-editor.org:443` | 1 | 516ms | `tunnel_open=never first_connect=never first_byte=never task_end=516ms` |
| on-policy | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 6.14s | `tunnel_open=511ms first_connect=524ms first_byte=552ms task_end=6.14s` |
| narrowed | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 5.979s | `tunnel_open=481ms first_connect=493ms first_byte=525ms task_end=5.979s` |
| killed | `api.anthropic.com:443, www.rfc-editor.org:443` | 137 | 625ms | `tunnel_open=494ms first_connect=505ms first_byte=530ms task_end=625ms` |
| early-push | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 6.05s | `tunnel_open=433ms first_connect=445ms first_byte=466ms task_end=6.05s` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## off-policy

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1274519801/off-policy-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1274519801/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback522509036/001/off-policy/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback522509036/001/off-policy/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback522509036/001/off-policy/debug/ --strace run --bundle /dev/shm/t25-1274519801/off-policy t25-off-policy-487204
```

The exit saw nothing: no stream reached it in this run.

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: api.anthropic.com:443 at 100.64.1.0 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b n=1 of 2 names kept x=1 f=1
tunnel narrow: applied in 968.914µs, of which the table swap was 171.355µs
tunnel dns: q="api.anthropic.com" type=A answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
tunnel dns: q="api.anthropic.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1274519801/off-policy.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:37:45.317009409Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:37:45.321352391Z
disconnected
```

## on-policy

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1274519801/on-policy-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1274519801/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback522509036/001/on-policy/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback522509036/001/on-policy/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback522509036/001/on-policy/debug/ --strace run --bundle /dev/shm/t25-1274519801/on-policy t25-on-policy-487204
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed www.rfc-editor.org:443 -> 104.18.21.81:443
EXIT api.anthropic.com:443 ended
EXIT www.rfc-editor.org:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 2.219187ms, of which the table swap was 207.509µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 58.461843ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=noerror-empty
tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 24.802567ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1274519801/on-policy.events
connected: the sentry speaks wire version 1
disconnected
```

## narrowed

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1274519801/narrowed-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1274519801/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback522509036/001/narrowed/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback522509036/001/narrowed/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback522509036/001/narrowed/debug/ --strace run --bundle /dev/shm/t25-1274519801/narrowed t25-narrowed-487204
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
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.848611ms, host fd 37, local 100.64.0.1:40001
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 912.861µs, of which the table swap was 121.832µs
tunnel narrow: www.rfc-editor.org:443 at 100.64.1.1 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d n=1 of 2 names kept x=1 f=1
tunnel narrow: applied in 593.755µs, of which the table swap was 222.682µs
tunnel dns: q="www.rfc-editor.org" type=A answer=nxdomain
tunnel: refused dns :0 name="www.rfc-editor.org" reason=unknown-name
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="www.rfc-editor.org" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1274519801/narrowed.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:38:01.592681938Z
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:38:01.595339779Z
disconnected
```

## killed

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1274519801/killed-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1274519801/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback522509036/001/killed/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback522509036/001/killed/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback522509036/001/killed/debug/ --strace run --bundle /dev/shm/t25-1274519801/killed t25-killed-487204
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
tunnel narrow: applied in 2.248982ms, of which the table swap was 466.375µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.400223ms, host fd 37, local 100.64.0.1:40001
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1274519801/killed.events
connected: the sentry speaks wire version 1
disconnected
```

## early-push

```
/home/pniroula/Projects/gvisor-t27/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-1274519801/early-push-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1274519801/a.sock --tunnel-table=/tmp/pniroula/TestGovernedLoopback522509036/001/early-push/table.json --pod-init-config=/tmp/pniroula/TestGovernedLoopback522509036/001/early-push/pod-init.json --debug --debug-log=/tmp/pniroula/TestGovernedLoopback522509036/001/early-push/debug/ --strace run --bundle /dev/shm/t25-1274519801/early-push t25-early-push-487204
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed www.rfc-editor.org:443 -> 104.18.20.81:443
EXIT www.rfc-editor.org:443 ended
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: 2 of 2 names kept
tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
tunnel narrow: applied in 1.106539ms, of which the table swap was 92.638µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.620281ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=noerror-empty
tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 16.738187ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1274519801/early-push.events
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

The table is `api.anthropic.com:443, www.rfc-editor.org:443` and the policy pushed is `n = [www.rfc-editor.org:443]`. The workload was refused at the resolver (`no such host`, which is NXDOMAIN), runsc ended with status 1 after 516ms, and the exit was never asked to dial api.anthropic.com — so **the refusal is the pushed policy's and not the table's**, which is the whole of what this control says.

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
| `root-off` | `8448109a…966b` | 1 | 163ms | 130.808ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:37:45.210053  tunnel narrow: applied in 968.914µs, of which the table swap was 171.355µs
```

**The window.** The sentry started the workload at 20:37:45.208643 and the first policy landed at 20:37:45.210014, so **1ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 108ms after it started, and the policy was 106.801ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1274519801/off-policy.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:37:45.317009409Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-22T00:37:45.321352391Z
disconnected
```

## on-policy — the task completes under the policy, and its end ends the tunnel

`TIMING tunnel_open=511ms first_connect=524ms first_byte=552ms task_end=6.14s`, and the task completed: runsc ended with status 0 after 6.14s, `NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480 in 5.637s`. Every stream the exit carried is in the run's section above.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-on` | `db453844…fdd7` | 2 | 69ms | 15.518ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:37:47.828379  tunnel narrow: applied in 2.219187ms, of which the table swap was 207.509µs
```

**The window.** The sentry started the workload at 20:37:47.825697 and the first policy landed at 20:37:47.828279, so **3ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 139ms after it started, and the policy was 136.82ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with the workload exiting, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:53744 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:37:53.642; the loss was reported **189ms after** that and the tunnel was refused **189ms after** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1274519801/on-policy.events
connected: the sentry speaks wire version 1
disconnected
```

## narrowed — a second peer removes a destination while the task is running

The sentry's own account of the two policies that landed, and of the name the second one removed:

```
20:37:56.267531  tunnel narrow: sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7 n=2 of 2 names kept x=1 f=1
20:37:56.304653  is gone
20:37:56.304885  tunnel narrow: sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d n=1 of 2 names kept x=1 f=1
```

The narrowing landed 72ms after the exit accepted the first stream, and the workload's second request is a fixed 5s after its first — so the document host was **not** dialled after the name went, and what the workload saw was:

```
tool fetch_url https://www.rfc-editor.org/rfc/rfc8446.txt: Get "https://www.rfc-editor.org/rfc/rfc8446.txt": dial tcp: lookup www.rfc-editor.org on 127.0.0.53:53: no such host
NO-MODEL DONE model_status=401 model_bytes=141 doc_status=none doc_bytes=0 in 5.427s
```

runsc ended with status 0 after 5.979s, `TIMING tunnel_open=481ms first_connect=493ms first_byte=525ms task_end=5.979s`, and the workload ran throughout: the narrowing is not a restart and the process the run started is the process that finished.

**The narrowing is not read as a mismatch.** The sandbox pulses the new policy's digest from the moment it takes it, and the watch over the old one is retired before the new one is pushed — so nothing is lost while the workload runs, and the one loss reported is the workload's own exit, 5.58s after the narrowing landed:

```
SANDBOX liveness lost: the sandbox closed its socket
```

This is the one place this run differs from ticket 26's, where the first peer's tunnel was torn down as a mismatch and the number recorded was how long that took. Reading a lawful narrowing as a loss now costs the sandbox rather than one tunnel, so it is not read as one — and the first peer, whose policy is no longer the one in force, keeps its tunnel and is told nothing. That is a finding and not an assertion of this run.

And the third peer, pushing P0 again at a sandbox now holding P1, is refused. The sentence naming the component is `a`'s and stays there:

```
20:37:56.385111  REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:58617 pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it: policy refused: it widens n by [net:www.rfc-editor.org:443]
```

What the peer is told is the fixed sentence the boundary carries back, and not which component widened — that is a fact about this guest, and the peer supplied the document rather than the machine (`attest/tunneld/push.go`, `ackRefused`):

```
attest: verification failed
```

The third peer's own refusal log: `verification refused: the policy pushed to the peer was not applied: "a" at 127.0.0.1:45156 did not apply the policy pushed to it: the peer refused it: the sandbox beside this tunneld did not apply it`

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-narrowed` | `db453844…fdd7` | 1 | 41ms | 3.126ms | acknowledged |
| `root2-narrowed` | `36cce26e…c37d` | 1 | 37ms | 3.418ms | acknowledged |
| `root3-narrowed` | `db453844…fdd7` | 1 | 80ms | 3.803ms | refused |

And the sentry's own, one line per policy it accepted:

```
20:37:56.267568  tunnel narrow: applied in 912.861µs, of which the table swap was 121.832µs
20:37:56.304949  tunnel narrow: applied in 593.755µs, of which the table swap was 222.682µs
```

**The window.** The sentry started the workload at 20:37:56.095072 and the first policy landed at 20:37:56.267531, so **172ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 129ms after it started, and the policy was 43.114ms after it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1274519801/narrowed.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:38:01.592681938Z
egress_refused protocol=dns name=www.rfc-editor.org reason=unknown-name time=2026-09-22T00:38:01.595339779Z
disconnected
```

## killed — the same teardown, reached with `runsc kill`

`runsc kill t25-killed-487204 KILL` was sent 495ms into the run, while the first model request was in flight. runsc ended with status 137 after 625ms.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-killed` | `db453844…fdd7` | 1 | 171ms | 128.671ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:38:04.235658  tunnel narrow: applied in 2.248982ms, of which the table swap was 466.375µs
```

**The window.** The sentry started the workload at 20:38:04.233042 and the first policy landed at 20:38:04.235526, so **2ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 135ms after it started, and the policy was 132.929ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with `runsc kill`, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:52287 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:38:04.505; the loss was reported **17ms before** that and the tunnel was refused **16ms before** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1274519801/killed.events
connected: the sentry speaks wire version 1
disconnected
```

## early-push — the push arrives before the sandbox attaches

The push was made at `a` before `runsc` was started: the pusher's handshake was already done and its document already inside `Host.Apply` when the sandbox was created, which is what the harness holds the two in order for. `Host.Apply` waited there for an enforcing attachment, handed it the document, and acknowledged only once the sentry had applied it.

| moment | clock | when |
|---|---|---|
| `Host.Apply` entered at `a` | a's goroutine | 20:38:06.735097 |
| `SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing` | a's console | 20:38:06.926855 |
| `SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7` | a's console | 20:38:07.119429 |
| `Host.Apply` acknowledged the push | a's goroutine | 20:38:07.119464 |
| the pusher's `PUSH` line: `Peer` returned | the pusher | 20:38:07.120339 |

The push was entered **192ms** before the enforcing sandbox attached, and acknowledged **193ms** after it, having been made once. The workload then ran governed and completed: runsc ended with status 0 after 6.05s, `NO-MODEL DONE model_status=401 model_bytes=141 doc_status=200 doc_bytes=20480 in 5.566s`.

The push, from both ends. `cold Open` is the pusher's: the dial, both sides judging the other's evidence, the push and the acknowledgement. `Apply at a` is `a`'s own clock on the contract socket, the helper, urpc and the sentry. `Policy.Narrow` is the sentry's, and `table swap` is the part of it that replaces the adapter. `handshakes` is how many the push took: a push made before the sentry had started the workload is refused and takes its tunnel with it, so the next one is a fresh handshake.

| peer | sha256 | handshakes | cold Open | Apply at a | outcome |
|---|---|---|---|---|---|
| `root-early` | `db453844…fdd7` | 1 | 425ms | 384.342ms | acknowledged |

And the sentry's own, one line per policy it accepted:

```
20:38:07.118128  tunnel narrow: applied in 1.106539ms, of which the table swap was 92.638µs
```

**The window.** The sentry started the workload at 20:38:07.116395 and the first policy landed at 20:38:07.118093, so **2ms** of this run was governed by `--tunnel-table` and nothing else. The workload's first query was 102ms after it started, and the policy was 100.03ms before it. A policy cannot be applied to a loader that has not started one (`runsc/boot/policy.go:106`), so this window is the arrangement's and not the harness's: what closes it is the boot table, which is the ceiling every push narrows.

Liveness ends with the workload exiting, and the tunnel goes with it:

```
SANDBOX liveness lost: the sandbox closed its socket
REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:46767 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```

runsc exited at 20:38:12.842; the loss was reported **29ms after** that and the tunnel was refused **30ms after** that. The bound is a quarter of a pulse, which is how often a watch looks (`sandbox.watchInterval`).

What the sentry emitted on the seccheck sink:

```
listening on /dev/shm/t25-1274519801/early-push.events
connected: the sentry speaks wire version 1
disconnected
```

## a's console, in full

Every line `a` wrote, with the second it was written in. `SANDBOX applied` is one per acknowledged push, `PUSH` is a pusher's own account of its round trip, and `REFUSED` is `a`'s refusal log.

```
20:37:45.047  SANDBOX attached on /dev/shm/t25-1274519801/a.sock
20:37:45.048  SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing
20:37:45.211  SANDBOX applied format=policy version=1 bytes=156 sha256=8448109aea94a097e2a1566a1aef63558a2557fdfc4950a413dab35f6039966b
20:37:45.212  PUSH root-off sha256=8448109a…966b cold_open=163ms apply=130.808ms tries=1 err=<nil>
20:37:45.462  SANDBOX liveness lost: the sandbox closed its socket
20:37:45.462  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:50098 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:37:47.641  SANDBOX attached on /dev/shm/t25-1274519801/a.sock
20:37:47.641  SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing
20:37:47.760  REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:35255 pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it: policy refused: the sandbox is created and a policy is honoured only by a started one
20:37:47.829  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:37:47.830  PUSH root-on sha256=db453844…fdd7 cold_open=69ms apply=15.518ms tries=2 err=<nil>
20:37:53.831  SANDBOX liveness lost: the sandbox closed its socket
20:37:53.831  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:53744 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:37:55.943  SANDBOX attached on /dev/shm/t25-1274519801/a.sock
20:37:55.944  SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing
20:37:56.268  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:37:56.268  PUSH root-narrowed sha256=db453844…fdd7 cold_open=41ms apply=3.126ms tries=1 err=<nil>
20:37:56.306  SANDBOX applied format=policy version=1 bytes=155 sha256=36cce26ef69b2cb3c8d4f8c5758a1bf94bd50a35e6c02aeebbccd149e4e2c37d
20:37:56.306  PUSH root2-narrowed sha256=36cce26e…c37d cold_open=37ms apply=3.418ms tries=1 err=<nil>
20:37:56.385  REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 127.0.0.1:58617 pushed a policy this sandbox did not apply: sandbox: policy refused: the sandbox refused it: policy refused: it widens n by [net:www.rfc-editor.org:443]
20:37:56.386  PUSH root3-narrowed sha256=db453844…fdd7 cold_open=80ms apply=3.803ms tries=1 err=attest: verification failed
20:38:01.886  SANDBOX liveness lost: the sandbox closed its socket
20:38:01.886  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:55861 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:38:04.064  SANDBOX attached on /dev/shm/t25-1274519801/a.sock
20:38:04.065  SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing
20:38:04.237  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:38:04.237  PUSH root-killed sha256=db453844…fdd7 cold_open=171ms apply=128.671ms tries=1 err=<nil>
20:38:04.489  SANDBOX liveness lost: the sandbox closed its socket
20:38:04.489  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:52287 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
20:38:06.926  SANDBOX attached on /dev/shm/t25-1274519801/a.sock
20:38:06.926  SANDBOX attached on /dev/shm/t25-1274519801/a.sock role=enforcing
20:38:07.119  SANDBOX applied format=policy version=1 bytes=199 sha256=db45384408fe86ffa6215655c852664115af8f8061e21f0d4158635edda5fdd7
20:38:07.120  PUSH root-early sha256=db453844…fdd7 cold_open=425ms apply=384.342ms tries=1 err=<nil>
20:38:12.871  SANDBOX liveness lost: the sandbox closed its socket
20:38:12.872  REFUSED verification refused: the policy pushed to the peer is no longer live: a peer at 127.0.0.1:46767 pushed a policy this sandbox no longer enforces: the sandbox closed its socket
```


