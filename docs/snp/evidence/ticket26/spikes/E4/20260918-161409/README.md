# E4: Claude Code under a pushed policy: 2026-09-18T16:14:11-04:00

runsc is `/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc`
(sha256 `6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819`); the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,http-intake.logs.us5.datadoghq.com:443`.

Four runsc sandboxes with the same rootfs, the same table — `api.anthropic.com:443` and `http-intake.logs.us5.datadoghq.com:443` — and the same command, `claude -p "Reply with exactly the word OK." --output-format json --model claude-haiku-4-5-20251001`. The first three have a policy pushed at `a` by a third tunneld once the sandbox has attached, whose `n` is the API host and nothing else, so the push narrows the table by the log intake. The fourth has no push and is the comparison.

The runsc is this branch's own build, `bazel-bin/runsc/runsc_/runsc`, sha256 `6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819`. The Claude Code ELF is version 2.1.276, the one ticket 25's smoke used, so the unrestricted run here and ticket 25's are the same binary in the same rootfs.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| governed-1 | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 0 | 8.973s | `tunnel_open=2.64s first_connect=2.653s first_byte=2.67s task_end=8.973s` |
| governed-2 | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 0 | 9.014s | `tunnel_open=2.557s first_connect=2.57s first_byte=2.59s task_end=9.014s` |
| governed-3 | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 0 | 8.359s | `tunnel_open=2.397s first_connect=2.408s first_byte=2.428s task_end=8.359s` |
| unrestricted | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 0 | 8.767s | `tunnel_open=2.418s first_connect=2.429s first_byte=2.446s task_end=8.767s` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## governed-1

```
/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-3363345203/governed-1-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-3363345203/a.sock --tunnel-table=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-1/table.json --pod-init-config=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-1/pod-init.json --debug --debug-log=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-1/debug/ --strace run --bundle /dev/shm/t25-3363345203/governed-1 t25-governed-1-1810639
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: http-intake.logs.us5.datadoghq.com:443 at 100.64.1.1 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d n=1 of 2 names kept x=0 f=0
tunnel narrow: applied in 2.051818ms, of which the table swap was 884.759µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 70.037289ms, host fd 69, local 100.64.0.1:40001
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.11599ms, host fd 71, local 100.64.0.1:40002
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.050943ms, host fd 72, local 100.64.0.1:40003
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.358782ms, host fd 80, local 100.64.0.1:40004
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.030103ms, host fd 83, local 100.64.0.1:40005
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.639861ms, host fd 84, local 100.64.0.1:40006
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 17.902783ms, host fd 85, local 100.64.0.1:40007
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 17.644438ms, host fd 86, local 100.64.0.1:40008
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=A answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-3363345203/governed-1.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:34.428068546Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:34.429986404Z
disconnected
```

## governed-2

```
/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-3363345203/governed-2-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-3363345203/a.sock --tunnel-table=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-2/table.json --pod-init-config=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-2/pod-init.json --debug --debug-log=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-2/debug/ --strace run --bundle /dev/shm/t25-3363345203/governed-2 t25-governed-2-1810639
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: http-intake.logs.us5.datadoghq.com:443 at 100.64.1.1 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d n=1 of 2 names kept x=0 f=0
tunnel narrow: applied in 824.379µs, of which the table swap was 201.851µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 18.24957ms, host fd 67, local 100.64.0.1:40001
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.692299ms, host fd 71, local 100.64.0.1:40002
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.13636ms, host fd 72, local 100.64.0.1:40003
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.948251ms, host fd 80, local 100.64.0.1:40004
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 18.249892ms, host fd 82, local 100.64.0.1:40005
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.234616ms, host fd 83, local 100.64.0.1:40006
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.105323ms, host fd 84, local 100.64.0.1:40007
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 17.495827ms, host fd 85, local 100.64.0.1:40008
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=A answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-3363345203/governed-2.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:45.635506898Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:45.636683882Z
disconnected
```

## governed-3

```
/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-3363345203/governed-3-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-3363345203/a.sock --tunnel-table=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-3/table.json --pod-init-config=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-3/pod-init.json --debug --debug-log=/tmp/pniroula/TestClaudeGoverned2160688201/001/governed-3/debug/ --strace run --bundle /dev/shm/t25-3363345203/governed-3 t25-governed-3-1810639
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel narrow: http-intake.logs.us5.datadoghq.com:443 at 100.64.1.1 is gone
tunnel narrow: 1 of 2 names kept
tunnel narrow: sha256=b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d n=1 of 2 names kept x=0 f=0
tunnel narrow: applied in 1.322892ms, of which the table swap was 530.771µs
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.528474ms, host fd 67, local 100.64.0.1:40001
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.560203ms, host fd 71, local 100.64.0.1:40002
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.652219ms, host fd 72, local 100.64.0.1:40003
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.392101ms, host fd 80, local 100.64.0.1:40004
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.769394ms, host fd 82, local 100.64.0.1:40005
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.096711ms, host fd 83, local 100.64.0.1:40006
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.722483ms, host fd 84, local 100.64.0.1:40007
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.800039ms, host fd 85, local 100.64.0.1:40008
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=A answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=AAAA answer=nxdomain
tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-3363345203/governed-3.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:56.215086022Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:56.216336546Z
disconnected
```

## unrestricted

```
/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc --root=/dev/shm/t25-3363345203/unrestricted-state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-3363345203/a.sock --tunnel-table=/tmp/pniroula/TestClaudeGoverned2160688201/001/unrestricted/table.json --pod-init-config=/tmp/pniroula/TestClaudeGoverned2160688201/001/unrestricted/pod-init.json --debug --debug-log=/tmp/pniroula/TestClaudeGoverned2160688201/001/unrestricted/debug/ --strace run --bundle /dev/shm/t25-3363345203/unrestricted t25-unrestricted-1810639
```

What the exit saw, which is host, port and ciphertext and nothing else:

```
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT accepted a stream from peer="" vendor=amd-sev-snp measurement=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242 policy_digest=a3a196da455a0030924a3acf2f38608942d9a8f0c703ec0387b1bf5f218ec545
EXIT dialed http-intake.logs.us5.datadoghq.com:443 -> 34.149.66.165:443
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT api.anthropic.com:443 ended
EXIT http-intake.logs.us5.datadoghq.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.552141ms, host fd 67, local 100.64.0.1:40001
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.452992ms, host fd 71, local 100.64.0.1:40002
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 13.298251ms, host fd 72, local 100.64.0.1:40003
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.781753ms, host fd 80, local 100.64.0.1:40004
tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 25.414499ms, host fd 83, local 100.64.0.1:40005
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.782483ms, host fd 84, local 100.64.0.1:40006
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.7131ms, host fd 85, local 100.64.0.1:40007
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 21.211305ms, host fd 86, local 100.64.0.1:40008
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=A answer=100.64.1.1
tunnel dns: q="http-intake.logs.us5.datadoghq.com" type=AAAA answer=noerror-empty
tunnel attach: http-intake.logs.us5.datadoghq.com:443 -> peer "b": ok in 15.737836ms, host fd 87, local 100.64.0.1:40009
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-3363345203/unrestricted.events
connected: the sentry speaks wire version 1
disconnected
```

## The policy

```
{"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[],"x":[]}
```

sha256 `b12101796a563ae0fb48eb1657bf1441f017e84191ef3803eb5a754db8cba86d`, 94 bytes. `n` is the API host and nothing else; `f` and `x` are empty, so exec stays unconstrained and no file is named — which is what makes the only difference between these runs and the fourth a single destination.

## The four runs

| run | policy | result | is_error | turns | cost | wall | api ms | runsc | streams at the exit | intake dialled |
|---|---|---|---|---|---|---|---|---|---|---|
| governed-1 | pushed | `OK` | false | 1 | $0.003206 | 8.973s | 2210 | 0 | 8 | no |
| governed-2 | pushed | `OK` | false | 1 | $0.003286 | 9.014s | 2653 | 0 | 8 | no |
| governed-3 | pushed | `OK` | false | 1 | $0.003201 | 8.359s | 2302 | 0 | 8 | no |
| unrestricted | none | `OK` | false | 1 | $0.003236 | 8.767s | 2462 | 0 | 9 | yes |

The four runs cost $0.012931 between them, as the CLI reported it.

## Every refusal, with the errno

### governed-1

The push: sha256 `b1210179…a86d`, 3 handshake(s), cold Open 99ms, `Apply` at `a` 52.443ms, acknowledged.

| name | queries | types | answers |
|---|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | 100.64.1.0, noerror-empty |
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | nxdomain |

What the sentry refused:

```
16:13:34.427993  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
16:13:34.429911  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

The seccheck sink:

```
listening on /dev/shm/t25-3363345203/governed-1.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:34.428068546Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:34.429986404Z
disconnected
```

What failed at the syscall level: 

```
2  connect errno=2 (no such file or directory)
```
 The whole tally is in this run's `strace-digest.txt`.

### governed-2

The push: sha256 `b1210179…a86d`, 3 handshake(s), cold Open 123ms, `Apply` at `a` 65.721ms, acknowledged.

| name | queries | types | answers |
|---|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | 100.64.1.0, noerror-empty |
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | nxdomain |

What the sentry refused:

```
16:13:45.635470  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
16:13:45.636657  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

The seccheck sink:

```
listening on /dev/shm/t25-3363345203/governed-2.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:45.635506898Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:45.636683882Z
disconnected
```

What failed at the syscall level: 

```
2  connect errno=2 (no such file or directory)
```
 The whole tally is in this run's `strace-digest.txt`.

### governed-3

The push: sha256 `b1210179…a86d`, 4 handshake(s), cold Open 78ms, `Apply` at `a` 35.231ms, acknowledged.

| name | queries | types | answers |
|---|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | 100.64.1.0, noerror-empty |
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | nxdomain |

What the sentry refused:

```
16:13:56.215048  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
16:13:56.216281  tunnel: refused dns :0 name="http-intake.logs.us5.datadoghq.com" reason=unknown-name
```

The seccheck sink:

```
listening on /dev/shm/t25-3363345203/governed-3.events
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:56.215086022Z
egress_refused protocol=dns name=http-intake.logs.us5.datadoghq.com reason=unknown-name time=2026-09-18T20:13:56.216336546Z
disconnected
```

What failed at the syscall level: 

```
2  connect errno=2 (no such file or directory)
```
 The whole tally is in this run's `strace-digest.txt`.

### unrestricted

| name | queries | types | answers |
|---|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | 100.64.1.0, noerror-empty |
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | 100.64.1.1, noerror-empty |

The seccheck sink:

```
listening on /dev/shm/t25-3363345203/unrestricted.events
connected: the sentry speaks wire version 1
disconnected
```

What failed at the syscall level: 

```
2  connect errno=2 (no such file or directory)
```
 The whole tally is in this run's `strace-digest.txt`.

## Distinguishable from the outside?

| what is compared | governed | unrestricted |
|---|---|---|
| the task's result | `OK`, `is_error=false` | `OK`, `is_error=false` |
| runsc's exit status | 0, 0, 0 | 0 |
| wall | 8.973s, 9.014s, 8.359s | 8.767s |
| streams the exit accepted | 8, 8, 8 | 9 |
| destinations the exit dialled | `api.anthropic.com:443` | `api.anthropic.com:443`, `http-intake.logs.us5.datadoghq.com:443` |
| `sentry/egress_refused` events | 2 | 0 |

And the syscall tallies, which is where an observer *inside* the guest would look. These are the rows of `## syscalls that failed` that differ between the first governed run and the unrestricted one:

```
governed unrestricted  syscall
     171      138  futex errno=11 (try again)
     143      145  futex errno=110 (connection timed out)
      11       16  futex errno=512 (to be restarted if SA_RESTART is set)
       8        2  futex errno=516 (interrupted by signal)
     278      276  openat errno=2 (no such file or directory)
      16       14  recvfrom errno=11 (request would block)
```


## Withheld

These files matched `ANTHROPIC_API_KEY` and were not copied. A `.redacted` copy of each is here in its place.

- `governed-1/debug/runsc.log.20260918-161325.871366.boot.txt`: the key appears 15 times
- `governed-1/debug/runsc.log.20260918-161325.871366.gofer.txt`: the key appears once
- `governed-1/debug/runsc.log.20260918-161325.871366.run.txt`: the key appears once
- `governed-2/debug/runsc.log.20260918-161337.071249.boot.txt`: the key appears 15 times
- `governed-2/debug/runsc.log.20260918-161337.071249.gofer.txt`: the key appears once
- `governed-2/debug/runsc.log.20260918-161337.071249.run.txt`: the key appears once
- `governed-3/debug/runsc.log.20260918-161348.292131.boot.txt`: the key appears 15 times
- `governed-3/debug/runsc.log.20260918-161348.292131.gofer.txt`: the key appears once
- `governed-3/debug/runsc.log.20260918-161348.292131.run.txt`: the key appears once
- `unrestricted/debug/runsc.log.20260918-161358.806021.boot.txt`: the key appears 15 times
- `unrestricted/debug/runsc.log.20260918-161358.806021.gofer.txt`: the key appears once
- `unrestricted/debug/runsc.log.20260918-161358.806021.run.txt`: the key appears once

The sentry writes the container's spec into its debug log, and `process.env` is in the spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's `config.json` lives on tmpfs and why nothing here is copied before it has been searched.
