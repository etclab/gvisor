# E4 — what a real agent runtime asks the network for

**Question.** Ticket 23's E1 measured a 294-line agent that made one HTTPS request.
Ticket 25 has to put a name table inside the sentry, and ticket 26 has to live with
it, so the number that matters is not what a probe asks for but what a *shipped*
agent runtime asks for. This spike runs Claude Code headless — `claude -p` — under
`strace` and writes down every name it resolves and every `host:port` it connects
to, in order, refused or not.

Nothing in the repository was changed. Everything this spike produced is under this
directory. `attest/` is untouched, and nothing was committed.

---

## What ran

`/home/pniroula/.local/bin/claude` → `/home/pniroula/.local/share/claude/versions/2.1.276`,
version 2.1.276. A native, dynamically linked x86-64 ELF — **not** a node script, and
not a shell wrapper.

Four runs, all with the same trivial prompt and the cheapest model, all in an empty
working directory:

```
claude -p "Reply with exactly the word OK." --output-format json --model claude-haiku-4-5-20251001
```

| run | HOME | traced |
| --- | --- | --- |
| `run-plain` | fresh, empty, never used | no — the check that `-p` runs at all |
| `run1` | fresh, empty, never used | `strace -f -e trace=%network,%file,%process -s 256` |
| `run2` | the HOME `run1` populated | same |
| `run3` | the operator's own `$HOME`, untouched | same |

`run.sh` here reproduces all four. `ANTHROPIC_API_KEY` comes from the environment and
is never written anywhere under this directory; `run.sh` ends by grepping its own
output for the key's first twelve characters and for the prefix every Anthropic
key carries (built at runtime, so no file here is itself a hit for it). Both counts
are 0.

**No prompt, no onboarding, no trust dialog.** With `-p` and a HOME that has never
been used, the CLI runs straight through and exits 0. `--dangerously-skip-permissions`
was not needed and was not used, and no `hasCompletedOnboarding` seed was needed.

**One deliberate deviation from a bare environment.** The shell this ran from is
itself a Claude Code session, so its own variables (`CLAUDECODE`,
`CLAUDE_CODE_MESSAGING_SOCKET`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_ENTRYPOINT`,
`CLAUDE_PID`, `ANTHROPIC_DEFAULT_HAIKU_MODEL`, …) were in the environment. A workload
disk in a sandbox has none of them, and `CLAUDE_CODE_MESSAGING_SOCKET` in particular
would have added an AF_UNIX destination that is an artefact of the harness. `run.sh`
strips exactly those. Nothing that disables telemetry or auto-update was set — the
point was the natural host list.

---

## The answer: the ordered host list

Identical in all three traced runs, and the order never varies:

1. **`api.anthropic.com`** — `160.79.104.10:443` (v4), `[2607:6bc0::10]:443` (v6)
2. **`http-intake.logs.us5.datadoghq.com`** — `34.149.66.165:443` (v4),
   `[2600:1901:0:9e23::]:443` (v6)

That is the whole list. **Two names, one port: 443.** No third-party CDN, no
telemetry host besides the Datadog log intake, no update check, no plugin
marketplace fetch, no MCP connector — in `run3` the CLI printed on stderr that
*claude.ai connectors are disabled because ANTHROPIC_API_KEY … takes precedence*,
so an API-key deployment does not reach the connector hosts at all.

Both names are resolved through the host resolver: `/etc/resolv.conf` names
`127.0.0.53`, so every lookup is a UDP query to **systemd-resolved's stub at
`127.0.0.53:53`**, `A` and `AAAA` sent back to back in one `sendmmsg`. There is no
DoH, no bundled resolver, and no hard-coded nameserver. The client uses glibc:
before every lookup it tries `/var/run/nscd/socket` (ENOENT here) and does an
`RTM_GETADDR` netlink dump.

`api.anthropic.com` is resolved **three times** in `run1`/`run2` and **four times** in
`run3` — the client does not cache the answer across its internal HTTP agents. **Seven to ten** TCP
connections are opened to it per run over IPv4 (7 / 8 / 10 in run1 / run2 / run3),
plus two or three IPv6 attempts, plus exactly one connection to the Datadog intake.
Not one connection: an agent runtime opens a pool.

The name behind each connection has two independent witnesses in the trace: the DNS
answer, and the **SNI in the TLS ClientHello**, which is `api.anthropic.com` or
`http-intake.logs.us5.datadoghq.com` verbatim. They agree everywhere. An in-sentry
name table can be checked against either.

### Refused or failed

| what | result | why |
| --- | --- | --- |
| `connect()` to `[2607:6bc0::10]:443` and `[2600:1901:0:9e23::]:443` | `ENETUNREACH` ×2–3 per run | this workstation has no IPv6 route. **The client tries IPv6 first, every time, for both hosts.** A sandbox that offers only v4 will see these failures on every lookup; one that offers v6 will see the session go over v6. |
| `connect()` to `unix:/var/run/nscd/socket` | `ENOENT` ×2 per run | no nscd on this host; glibc falls through to DNS. |
| `connect()` on **SOCK_DGRAM** to `160.79.104.10:443` / `:0` and `34.149.66.165:0` | `0`, no bytes sent | glibc `getaddrinfo` asking the kernel which source address it would pick, to sort the candidate list (RFC 3484). Not traffic — but the sandbox still has to answer it, and E1 saw the same thing with port 0. Here the port is 443 whenever `getaddrinfo` was called with a service. |

Nothing was refused by a peer. No `ECONNREFUSED` anywhere, in any run.

---

## What the binary needs from the filesystem to start

### It creates, in a HOME that has never been used

`$HOME/.claude`, `$HOME/.claude/backups`, `$HOME/.claude/sessions`,
`$HOME/.claude/projects/<slugified-cwd>/`, and `$HOME/.claude.json` (rewritten
atomically through `$HOME/.claude.json.tmp.<pid>.<nonce>` ten times in `run1`).
**The lock is a directory**: `mkdir $HOME/.claude.json.lock` succeeds eight times in
`run1`, so a filesystem that cannot `mkdir` blocks the config write.

### It reads (or misses) under HOME

`$HOME/.claude.json`, `$HOME/.claude/settings.json` (ENOENT ×10 `openat` + ×13 `statx` on a fresh HOME;
opened 18 times in `run3`), `$HOME/.claude/.credentials.json` (ENOENT ×10 in `run1` — with an API key it does not
need it; in `run3` it is opened 16 times anyway), `$HOME/.claude/remote-settings.json`
(**ENOENT 30 times, `statx` ENOENT 47 times in `run1`** — the single hottest missing
path), `$HOME/.claude/policy-limits.json` and its `.stamp.json` / `.signature.json`
siblings, `$HOME/.claude/CLAUDE.md`, `$HOME/.claude/{agents,commands,skills,plugins,rules,output-styles,plans,workflows}`.

### It walks the working directory's ancestors

From the cwd up to `/`, looking for `CLAUDE.md`, `CLAUDE.local.md` and `.claude/*` at
every level (`/tmp/CLAUDE.md`, `/tmp/.claude/agents`, `/tmp/.git`, …). A sandbox that
makes `/` or an intermediate directory unreadable will make that walk error rather
than miss.

### /etc

`/etc/resolv.conf` and `/etc/nsswitch.conf` (`newfstatat` on every lookup, `openat`
once), `/etc/hosts` (3–5×), `/etc/host.conf`, `/etc/gai.conf`. `/etc/services` is never touched.
For trust it probes a list and takes the first hit:
`/etc/ssl/cert.pem` (ENOENT), `/etc/ssl/ca-bundle.pem` (ENOENT),
`/etc/pki/tls/cert.pem` (ENOENT), `/etc/pki/tls/certs/ca-bundle.crt` (ENOENT),
`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (ENOENT), then
**`/etc/ssl/certs/ca-certificates.crt` (opened, once)** plus a directory walk of
`/etc/ssl/certs` and `/usr/share/ca-certificates`. One CA bundle file is enough;
the walk is a fallback.

### /proc and /sys

`/proc/self/{exe,maps,stat,statm,cgroup,ns/pid,uid_map,fd/N}`, `/proc/<pid>/stat`,
`/proc/version`, `/proc/sys/vm/{mmap_min_addr,overcommit_memory}`, and
`/proc/sys/fs/binfmt_misc/WSLInterop` (a WSL probe). From `/sys`:
`/sys/devices/system/cpu/online`, `/sys/devices/system/node/node1..5` (NUMA), and
`/sys/fs/cgroup/{cpu.max,memory.high,memory.max}` at three levels of the hierarchy.
A sandbox with no cgroup files or no `/sys/devices/system/node` will not break it —
these are all read-and-shrug — but they are reads the sentry will see.

### /run — an AF_UNIX server, not just a client

The process **binds and listens** on `/run/user/<uid>/cc-socks/<pid>.sock`
(`bind` → `listen(512)` → `chmod 0600`), and `unlink`s it on exit. That directory
must exist and be writable. This is the only AF_UNIX socket it creates; the only
AF_UNIX socket it *connects* to is nscd's, which is absent.

---

## Runtime facts

* **Native ELF**, `interpreter /lib64/ld-linux-x86-64.so.2`, not stripped.
  `ldd`: `linux-vdso.so.1`, `librt.so.1`, `libc.so.6`, `libpthread.so.0`,
  `libdl.so.2`, `libm.so.6`. No libssl, no libcrypto, no libcurl, no libnode —
  TLS is in the binary; only name resolution goes through glibc.
* **Heavily threaded**: 43 thread ids in `run1`, 41 in `run2`, 64 in `run3`. DNS,
  TLS and the file walk all run on different threads, which is why the trace has to
  be joined across `<unfinished>`/`resumed`.
* **It forks.** `vfork` + `execve`, in every run:
  * `/usr/bin/git` ×4 — `ls-files --error-unmatch -- :(icase).claude/settings.local.json`,
    then repository probes with `-c protocol.ext.allow=never -c core.hooksPath=/dev/null`.
  * **itself, ×3** — `…/versions/2.1.276 --version`, and twice with ripgrep's flags
    (`--no-config --files --hidden --glob …`). The binary is multi-call: it re-execs
    its own path as its bundled `rg`. A sandbox that hides or re-labels the
    executable's own path breaks file search, not just `--version`.
* **It spawns a shell only in `run3`**: `/bin/sh -c "ps -o command= -p <ppid>"`,
  which then `execve`s `/usr/bin/ps`. With a fresh HOME there is **no shell at all**.
* It probes `PATH` for `bun`, `deno`, `node`, `npm`, `pnpm`, `yarn`, `git`, `ps` —
  `stat` only, no exec, except for `git`.
* Wall time per run: 1.9–3.2 s; API time 2.2–3.5 s.

---

## Telemetry / auto-update knobs — recorded, not set

Taken from the binary's own strings, so they are what *this* build reads, not what a
web page says. **None of these was set in any run**; the host list above is the
natural one.

* Off switches: `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `DISABLE_AUTOUPDATER`,
  `DISABLE_UPDATES`, `DISABLE_INSTALLATION_CHECKS`, `DISABLE_GROWTHBOOK`,
  `DISABLE_BUG_COMMAND`, `DISABLE_COST_WARNINGS`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `CLAUDE_CODE_DISABLE_VITALS_EMITTER`.
* Datadog specifically: `CLAUDE_CODE_BYOC_ENABLE_DATADOG`,
  `CLAUDE_CODE_DATADOG_FLUSH_INTERVAL_MS`,
  `CLAUDE_CODE_DD_ERROR_TRACKING_FLUSH_INTERVAL_MS`.
* Redirection, which is what ticket 25 actually cares about:
  `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_HOST`, `CLAUDE_CODE_API_BASE_URL`,
  `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`, `CLAUDE_CODE_PROXY_URL`,
  `CLAUDE_CODE_PROXY_RESOLVES_HOSTS`, `CLAUDE_CODE_CERT_STORE`,
  and — **`ANTHROPIC_UNIX_SOCKET`**.
* OpenTelemetry is wired but inert unless `CLAUDE_CODE_ENABLE_TELEMETRY` is set, in
  which case the full `OTEL_EXPORTER_OTLP_*` set applies and adds whatever host the
  operator points it at.

The binary also carries names it never contacted in these runs — `cdn.growthbook.io`,
`api.datadoghq.com`, `browser-intake-us5-datadoghq.com`, `a-api.anthropic.com`,
`a-cdn.anthropic.com`, `assets.claude.ai`, `claude.ai`, `code.claude.com`,
`api.github.com`, the Bedrock/Vertex/Foundry endpoints, `169.254.169.254`. A name
table built only from this spike covers the API-key, no-plugin, no-login path. Login,
plugin install, `/doctor`, web fetch and a subscription (non-API-key) deployment will
each want more.

---

## Cost

Model `claude-haiku-4-5-20251001` everywhere, prompt `Reply with exactly the word OK.`,
one turn each, result `OK`.

| run | model(s) | input | output | cache create | cache read | cost |
| --- | --- | --- | --- | --- | --- | --- |
| probe (untraced, identical to `run-plain`, run before `run.sh`) | `claude-haiku-4-5-20251001` | 10 | 45 | 6 800 | 13 708 | $0.010106 |
| `run-plain` | `claude-haiku-4-5-20251001` | 10 | 45 | 0 | 20 508 | $0.003240 |
| `run1` | `claude-haiku-4-5-20251001` | 10 | 46 | 6 800 | 13 708 | $0.011055 |
| `run2` | `claude-haiku-4-5-20251001` | 10 | 42 | 0 | 20 508 | $0.003240 |
| `run3` | `claude-haiku-4-5-20251001` + `claude-sonnet-5` | 10 + 1 174 | 44 + 14 | 9 520 | 13 708 | $0.015989 |
| | | | | | **total** | **$0.043629** |

Cap was $0.50. A trivial `-p` turn is not free: the system prompt and tool
definitions are ~20 500 cached tokens, which is 99.95% of the input.

---

## Surprises

1. **A second endpoint, unconditionally.** `http-intake.logs.us5.datadoghq.com:443`
   is contacted on a *fresh* HOME, with no opt-in, with the trivial prompt, on every
   run. A sentry table with `api.anthropic.com` alone will make a real agent runtime
   hang or retry on its log flush.
2. **A second model, in `run3` only.** The operator's configured HOME produced a
   1 174-token `claude-sonnet-5` call alongside the Haiku turn. Same host, so the name
   table is unaffected — but the token and cost model for ticket 26 is not "one call
   per turn".
3. **IPv6 first, always.** Every name is looked up `A` *and* `AAAA`, and the `AAAA`
   address is connected to first. On a v4-only sandbox that is a guaranteed
   `ENETUNREACH` per connection. The sentry must return something sane for AAAA
   rather than hanging.
4. **Three to four resolutions of the same name per run, seven to ten TCP connections.**
   Whatever the in-sentry table costs per lookup, multiply by that.
5. **The binary re-execs itself as ripgrep**, and forks `git` four times before the
   first model call. Ticket 26's sandbox needs `execve` of the agent's own path and
   of `/usr/bin/git`, or the agent degrades quietly.
6. **It listens on an AF_UNIX socket** under `/run/user/<uid>/cc-socks/`. The
   workload disk needs that directory.
7. **`ANTHROPIC_UNIX_SOCKET` exists in the binary.** If it does what its name says,
   the adapter may not have to intercept a TCP connect at all for the model endpoint
   — the client can be handed a unix socket directly. Worth one cheap experiment
   before ticket 25 commits to name interception for `api.anthropic.com`.
8. **No onboarding gate.** `-p` in a virgin HOME just works, which means a workload
   image does not have to ship a pre-seeded `.claude.json`.

---

## Files here

| file | what |
| --- | --- |
| `run.sh` | the four runs, exactly as run; the key comes from the environment |
| `derive.py` | strace → `table.md`; decodes DNS on the wire and the TLS SNI |
| `run1-strace.raw`, `run2-strace.raw`, `run3-strace.raw` | untrimmed traces |
| `run1.log`/`.err`, `run2.log`/`.err`, `run3.log`/`.err`, `run-plain.log`/`.err` | stdout/stderr per run (the `--output-format json` result objects) |
| `table.md` | the ordered network timeline per run, the path table, the binaries |
| `notes.md` | this file |
