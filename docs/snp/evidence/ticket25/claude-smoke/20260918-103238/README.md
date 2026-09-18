# Claude Code inside the sandbox: 2026-09-18T10:32:38-04:00

runsc is `/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-adapter`; the adapter flags were passed. The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,http-intake.logs.us5.datadoghq.com:443`.

One runsc sandbox. The workload is Claude Code itself, unmodified — the `claude-haiku-4-5-20251001` model, the prompt `Reply with exactly the word OK.`, `--output-format json`, in an empty working directory with a HOME that has never been used. What is asked of the run is that it starts and that the hosts it asks for are recorded; task completion is not required and its absence is not a failure.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| claude | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 0 | 9.086s | `tunnel_open=2.544s first_connect=2.557s first_byte=2.592s task_end=9.086s` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## claude

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/runsc-adapter --root=/tmp/pniroula/TestClaudeCodeSmoke810055925/001/claude/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --tunnel-socket=/dev/shm/t25-658864456/a.sock --tunnel-table=/tmp/pniroula/TestClaudeCodeSmoke810055925/001/claude/table.json --pod-init-config=/tmp/pniroula/TestClaudeCodeSmoke810055925/001/claude/pod-init.json --debug --debug-log=/tmp/pniroula/TestClaudeCodeSmoke810055925/001/claude/debug/ --strace run --bundle /dev/shm/t25-658864456/claude t25-claude-635166
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
EXIT api.anthropic.com:443 ended
```

What the adapter inside the sentry did — every name it answered and every stream it asked for, in its own words:

```
tunnel dns: q=api.anthropic.com type=A answer=100.64.1.0
tunnel dns: q=api.anthropic.com type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 77.596295ms, host fd 69, local 100.64.0.1:40001
tunnel dns: q=api.anthropic.com type=A answer=100.64.1.0
tunnel dns: q=api.anthropic.com type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 16.058717ms, host fd 71, local 100.64.0.1:40002
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 18.87868ms, host fd 72, local 100.64.0.1:40003
tunnel dns: q=api.anthropic.com type=A answer=100.64.1.0
tunnel dns: q=api.anthropic.com type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.32892ms, host fd 80, local 100.64.0.1:40004
tunnel dns: q=api.anthropic.com type=A answer=100.64.1.0
tunnel dns: q=api.anthropic.com type=AAAA answer=noerror-empty
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 14.333235ms, host fd 83, local 100.64.0.1:40005
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 13.159316ms, host fd 84, local 100.64.0.1:40006
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 13.391021ms, host fd 85, local 100.64.0.1:40007
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.030194ms, host fd 86, local 100.64.0.1:40008
tunnel attach: api.anthropic.com:443 -> peer "b": ok in 15.756046ms, host fd 87, local 100.64.0.1:40009
tunnel dns: q=http-intake.logs.us5.datadoghq.com type=A answer=100.64.1.1
tunnel dns: q=http-intake.logs.us5.datadoghq.com type=AAAA answer=noerror-empty
tunnel attach: http-intake.logs.us5.datadoghq.com:443 -> peer "b": ok in 21.536532ms, host fd 88, local 100.64.0.1:40010
```

What the seccheck receiver printed, which is the sentry's own account of the refusal and the only place the reason for it is written down:

```
listening on /dev/shm/t25-658864456/claude.events
connected: the sentry speaks wire version 1
disconnected
```

## Did it start

The sentry traced syscalls from: `0`, `1`, `2`, `3`, `4`, `5`, `Client`, `HeapHelper`, `JITWorker`, `JSCWarmUp`, `claude`, `fs.watch`, `git`, `mi-scavenger`. The first process is exec'd by the sentry itself, so there is no `execve` line for it; the name on its syscall lines is the evidence that it ran. Its children — `git`, and the binary re-exec'd as `rg` — do have `execve` lines, and they are in `strace-digest.txt` with every syscall that failed and every bind.

## The hosts it asked for

Every name the responder inside the sentry was asked for, in the order it was first asked, with how many times and which record types. This is the **asked-for** list, and the sentry's own log is the only place it exists: gVisor's strace formats a `sendto` buffer as a pointer (`pkg/sentry/strace/linux64_amd64.go`: `makeSyscallInfo("sendto", FD, Hex, Hex, Hex, SockAddr, Hex)`), so a DNS query's payload never reaches the syscall log.

| name | queries | types | answers |
|---|---|---|---|
| `api.anthropic.com` | 8 | A, AAAA | 100.64.1.0, noerror-empty | 
| `http-intake.logs.us5.datadoghq.com` | 2 | A, AAAA | 100.64.1.1, noerror-empty | 

And the **connect** list, which is a different question — every `CONNECT` the exit read, in order, by name, because the sandbox never had an address of its own to give:

```
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443
EXIT dialed http-intake.logs.us5.datadoghq.com:443 -> 34.149.66.165:443
```

E4 measured three to four resolutions and seven to ten connections per name per run on a bare host; the two lists above are this run's answer to the same two counts.

## The socket it binds

```
bind(0x11 socket:[29], 0x7f1f03078f72 {Family: AF_UNIX, Addr: "/tmp/cc-socks/1.sock"}, 0x6e) = 0 (0x0) (61.061µs)
```

E4 predicted `/run/user/<uid>/cc-socks/<pid>.sock` and this rootfs provides that directory; the path above is the one this run chose. With no `XDG_RUNTIME_DIR` in the environment the choice is the CLI's own fallback, and whichever directory it lands in has to be writable — which is the reason the rootfs here is read-write rather than read-only with a tmpfs over each path somebody guessed.

## What it cost

`OK` — 1 turn(s), $0.010815, 2248 ms wall, 2704 ms of it API. The cap for this smoke is $0.50.


## Withheld

These files matched `ANTHROPIC_API_KEY` and were not copied. A `.redacted` copy of each is here in its place.

- `claude/debug/runsc.log.20260918-103228.922141.boot.txt`: the key appears 15 times
- `claude/debug/runsc.log.20260918-103228.922141.gofer.txt`: the key appears once
- `claude/debug/runsc.log.20260918-103228.922141.run.txt`: the key appears once

The sentry writes the container's spec into its debug log, and `process.env` is in the spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's `config.json` lives on tmpfs and why nothing here is copied before it has been searched.
