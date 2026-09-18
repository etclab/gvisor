# Claude Code inside the sandbox: 2026-09-18T10:09:16-04:00

runsc is `/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/attest-side/runsc-0755`; the adapter flags were left out (AGENT_PROBE_ADAPTER=0). The tunnelds `a` and `b` are in the test's own process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — is attached to `b` with `-allow api.anthropic.com:443,http-intake.logs.us5.datadoghq.com:443`.

One runsc sandbox. The workload is Claude Code itself, unmodified — the `claude-haiku-4-5-20251001` model, the prompt `Reply with exactly the word OK.`, `--output-format json`, in an empty working directory with a HOME that has never been used. What is asked of the run is that it starts and that the hosts it asks for are recorded; task completion is not required and its absence is not a failure.

A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original was not copied and this is it with the key replaced. One ending `.gz` was over 4 MiB and is kept compressed rather than trimmed.

| run | the names its table carries | runsc status | wall | timings |
|---|---|---|---|---|
| claude | `api.anthropic.com:443, http-intake.logs.us5.datadoghq.com:443` | 1 | 3m5.767s | `tunnel_open=never first_connect=never first_byte=never task_end=3m5.767s` |

The four timings are measured from the moment `runsc` started. `tunnel_open` is the exit accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, `first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` exiting. Three of the four are taken at the exit because that is the only place in this arrangement where the harness and the bytes meet.

## claude

```
/tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/attest-side/runsc-0755 --root=/tmp/pniroula/TestClaudeCodeSmoke775223558/001/claude/state --platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new --debug --debug-log=/tmp/pniroula/TestClaudeCodeSmoke775223558/001/claude/debug/ --strace run --bundle /dev/shm/t25-407652581/claude t25-claude-356733
```

The exit saw nothing: no stream reached it in this run.

No `sentry/egress_refused` event was recorded: `AGENT_PROBE_SECCHECK_RECEIVER` was not set, so no receiver was listening on the remote sink. The refusal is asserted on the errno the workload reported.

## Did it start

The sentry traced syscalls from: `0`, `1`, `2`, `3`, `4`, `5`, `Client`, `HeapHelper`, `JITWorker`, `JSCWarmUp`, `claude`, `fs.watch`, `git`, `mi-scavenger`, `page-out`. The first process is exec'd by the sentry itself, so there is no `execve` line for it; the name on its syscall lines is the evidence that it ran. Its children — `git`, and the binary re-exec'd as `rg` — do have `execve` lines, and they are in `strace-digest.txt` with every syscall that failed and every bind.

## The hosts it asked for

No `CONNECT` reached the exit, so this run names no host through the tunnel.

**The names the resolver was asked for are not in `--strace`.** gVisor's strace formats `sendto`'s buffer argument as a pointer (`pkg/sentry/strace/linux64_amd64.go`: `makeSyscallInfo("sendto", FD, Hex, Hex, Hex, SockAddr, Hex)`), so a DNS query's payload never reaches the log. What the log gives is the count of datagrams to `127.0.0.53:53`, which is in `strace-digest.txt`. The query names are visible only to the responder inside the sentry, so that responder has to log them — one line per query — or the asked-for list cannot be recorded at all. The list above is the **connect** list, which is a different question: E4 saw three to four resolutions and seven to ten connections per name per run.

## The socket it binds

```
bind(0xd socket:[40], 0x7f4832003f72 {Family: AF_UNIX, Addr: "/tmp/cc-socks/1.sock"}, 0x6e) = 0 (0x0) (77.436µs)
```

E4 predicted `/run/user/<uid>/cc-socks/<pid>.sock` and this rootfs provides that directory; the path above is the one this run chose. With no `XDG_RUNTIME_DIR` in the environment the choice is the CLI's own fallback, and whichever directory it lands in has to be writable — which is the reason the rootfs here is read-write rather than read-only with a tmpfs over each path somebody guessed.

## What it cost

The CLI ran to a result and the result is an error: `API Error: Can't reach the API server — check your internet or DNS (EAI_AGAIN)`. Reported cost $0.000000 over 1 turn(s), 175433 ms wall, 0 ms of it API. Recorded, not a failure.


## Withheld

These files matched `ANTHROPIC_API_KEY` and were not copied. A `.redacted` copy of each is here in its place.

- `claude/debug/runsc.log.20260918-100609.100543.boot.txt`: the key appears 13 times
- `claude/debug/runsc.log.20260918-100609.100543.gofer.txt`: the key appears once
- `claude/debug/runsc.log.20260918-100609.100543.run.txt`: the key appears once

The sentry writes the container's spec into its debug log, and `process.env` is in the spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's `config.json` lives on tmpfs and why nothing here is copied before it has been searched.
