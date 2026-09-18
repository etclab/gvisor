# The adapter over loopback: 2026-09-18T11:04:11-04:00

runsc is `/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-final`
(sha256 `ea305e126ab20e4abc525317f8ab7c04179b0cf0e08a517de6c3799a4b3c4ba0`); the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,www.rfc-editor.org:443`.

Two runsc sandboxes. The workload is this package built with `CGO_ENABLED=0` and run as `/agent-probe -network plain -task summarize -dir /tmp`, which is `&http.Client{}`: no contract, no dialer of its own, Go's own resolver. The only difference between the two sandboxes is the table.

This run used the **post-review** adapter, `sha256 ea305e126ab20e4abc525317f8ab7c04179b0cf0e08a517de6c3799a4b3c4ba0`: the endpoint swap under a lock, the deferred `SHUT_WR` behind a backlog, the helper closing handed-over descriptors, the bounded open, name sanitisation in the resolver lines, the `Readiness` guard and the write holes. The sibling directory `20260918-103148` is this same test against the **pre-review** binary, `sha256 ab593dc254fe9617d8370ce77f81ae5abeb4483e4c980c4605247d441a1f4f70`; both are kept.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| workload | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 9.867s | `tunnel_open=539ms first_connect=551ms first_byte=580ms task_end=9.867s` |
| control | `www.rfc-editor.org:443` | 1 | 615ms | `tunnel_open=never first_connect=never first_byte=never task_end=615ms` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## workload

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-final --root=/tmp/pniroula/TestAdapterLoopback2034432748/001/workload/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1696591995/a.sock --tunnel-table=/tmp/pniroula/TestAdapterLoopback2034432748/001/workload/table.json --pod-init-config=/tmp/pniroula/TestAdapterLoopback2034432748/001/workload/pod-init.json --debug --debug-log=/tmp/pniroula/TestAdapterLoopback2034432748/001/workload/debug/ --strace run --bundle /dev/shm/t25-1696591995/workload t25-workload-716481
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
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 61.434797ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
tunnel dns: q="www.rfc-editor.org" type=AAAA answer=noerror-empty
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 39.03074ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1696591995/workload.events
connected: the sentry speaks wire version 1
disconnected
```

## control

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-final --root=/tmp/pniroula/TestAdapterLoopback2034432748/001/control/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-1696591995/a.sock --tunnel-table=/tmp/pniroula/TestAdapterLoopback2034432748/001/control/table.json --pod-init-config=/tmp/pniroula/TestAdapterLoopback2034432748/001/control/pod-init.json --debug --debug-log=/tmp/pniroula/TestAdapterLoopback2034432748/001/control/debug/ --strace run --bundle /dev/shm/t25-1696591995/control t25-control-716481
```

The exit saw nothing: no stream reached it in this run.

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel dns: q="api.anthropic.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
tunnel dns: q="api.anthropic.com" type=A answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-1696591995/control.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T15:04:11.817556769Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T15:04:11.822416964Z
disconnected
```

## Withheld

These files matched `ANTHROPIC_API_KEY` and were not copied. A `.redacted` copy of each is here in its place.

- `workload/debug/runsc.log.20260918-110401.416628.boot.txt`: the key appears once
- `workload/debug/runsc.log.20260918-110401.416628.gofer.txt`: the key appears once
- `workload/debug/runsc.log.20260918-110401.416628.run.txt`: the key appears once
- `control/debug/runsc.log.20260918-110411.383525.boot.txt`: the key appears once
- `control/debug/runsc.log.20260918-110411.383525.gofer.txt`: the key appears once
- `control/debug/runsc.log.20260918-110411.383525.run.txt`: the key appears once

The sentry writes the container's spec into its debug log, and `process.env` is in the spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's `config.json` lives on tmpfs and why nothing here is copied before it has been searched.
