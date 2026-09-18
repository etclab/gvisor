# The adapter over loopback: 2026-09-18T10:31:48-04:00

runsc is `/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-adapter`; the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,www.rfc-editor.org:443`.

Two runsc sandboxes. The workload is this package built with `CGO_ENABLED=0` and run as `/agent-probe -network plain -task summarize -dir /tmp`, which is `&http.Client{}`: no contract, no dialer of its own, Go's own resolver. The only difference between the two sandboxes is the table.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| workload | `api.anthropic.com:443, www.rfc-editor.org:443` | 0 | 9.881s | `tunnel_open=518ms first_connect=531ms first_byte=553ms task_end=9.881s` |
| control | `www.rfc-editor.org:443` | 1 | 624ms | `tunnel_open=never first_connect=never first_byte=never task_end=624ms` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## workload

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-adapter --root=/tmp/pniroula/TestAdapterLoopback2070206436/001/workload/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-2105451890/a.sock --tunnel-table=/tmp/pniroula/TestAdapterLoopback2070206436/001/workload/table.json --pod-init-config=/tmp/pniroula/TestAdapterLoopback2070206436/001/workload/pod-init.json --debug --debug-log=/tmp/pniroula/TestAdapterLoopback2070206436/001/workload/debug/ --strace run --bundle /dev/shm/t25-2105451890/workload t25-workload-631788
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
tunnel dns: q=api.anthropic.com type=A answer=100.64.1.0
tunnel dns: q=api.anthropic.com type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 68.48878ms, host fd 37, local 100.64.0.1:40001
tunnel dns: q=www.rfc-editor.org type=AAAA answer=noerror-empty
tunnel dns: q=www.rfc-editor.org type=A answer=100.64.1.1
tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 44.006035ms, host fd 44, local 100.64.0.1:40002
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-2105451890/workload.events
connected: the sentry speaks wire version 1
disconnected
```

## control

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-adapter --root=/tmp/pniroula/TestAdapterLoopback2070206436/001/control/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-2105451890/a.sock --tunnel-table=/tmp/pniroula/TestAdapterLoopback2070206436/001/control/table.json --pod-init-config=/tmp/pniroula/TestAdapterLoopback2070206436/001/control/pod-init.json --debug --debug-log=/tmp/pniroula/TestAdapterLoopback2070206436/001/control/debug/ --strace run --bundle /dev/shm/t25-2105451890/control t25-control-631788
```

The exit saw nothing: no stream reached it in this run.

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel dns: q=api.anthropic.com type=A answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
tunnel dns: q=api.anthropic.com type=AAAA answer=nxdomain
tunnel: refused dns :0 name="api.anthropic.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-2105451890/control.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T14:31:48.504088845Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T14:31:48.506265219Z
disconnected
```

## Withheld

These files matched `ANTHROPIC_API_KEY` and were not copied. A `.redacted` copy of each is here in its place.

- `workload/debug/runsc.log.20260918-103138.075667.boot.txt`: the key appears once
- `workload/debug/runsc.log.20260918-103138.075667.gofer.txt`: the key appears once
- `workload/debug/runsc.log.20260918-103138.075667.run.txt`: the key appears once
- `control/debug/runsc.log.20260918-103148.062564.boot.txt`: the key appears once
- `control/debug/runsc.log.20260918-103148.062564.gofer.txt`: the key appears once
- `control/debug/runsc.log.20260918-103148.062564.run.txt`: the key appears once

The sentry writes the container's spec into its debug log, and `process.env` is in the spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's `config.json` lives on tmpfs and why nothing here is copied before it has been searched.
