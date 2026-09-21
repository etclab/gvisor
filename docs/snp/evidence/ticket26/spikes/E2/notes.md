# E2 — the exec sink's cost and reach: what X costs, and what identity it can actually name

Ticket 26's second experiment, run on the workstation on 2026-09-18, worktree
`/home/pniroula/Projects/gvisor-t26`, branch
`ticket-26-the-sandbox-honors-a-pushed-policy`. No sudo, no hardware, no
tunneld. **Nothing here spent money**: the Claude Code run is `--version` and a
prompt with no credential, run with `env -u ANTHROPIC_API_KEY`, in a sandbox
whose tunnel table names one host that is not `api.anthropic.com`.

The ticket asks three things: what the sink adds to an `execve`, what the hash
cache's hit rate is, and *whether `x` as `{path|sha256}` can name a real runtime
at all*. The third is the one with a surprise in it.

## Setup

| thing | value |
|---|---|
| runsc | `make runsc` `-c opt`, sha256 `6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819` |
| faketunneld | E1's stand-in, sha256 `872fd0889ad016e4750f3e45ac8fd9aaaa0052e046dc2430c238c81fc467bc50` |
| seccheck-receiver | `../../tools/seccheck-receiver/`, sha256 `d7be04465f899c4af6f5c94de2307cde5bd220679497db2455ea085189d509dd` |
| execbench | `execbench/`, static, sha256 `f4f6f8fb4f451802dfaf6d433f30939deabdc392093f80056dedddf5070f0e59` in the rootfs |
| busybox | sha256 `dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14` |
| `/bin/probe` | that busybox with a comment appended: sha256 `72ec1b730e6b9ad1425242a3f9760ff6e6054fe7a09c410582891413b278eaae` |
| Claude Code | `$HOME/.local/share/claude/versions/2.1.276`, sha256 `8a56c8a14bd3cb246e2bdb7e60aefe0f609bff78c8bbcc5ea6b1817c111c6145` |
| git | `/usr/bin/git`, sha256 `2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668` |

Reproduced by

    env -u ANTHROPIC_API_KEY ./run-e2.sh <runsc> <workdir> <faketunneld> \
        <seccheck-receiver> <execbench> [claude-elf]

and `output-01-cost-and-reach.txt` is the untrimmed transcript.

## The four runs

| run | policy pushed | trace session |
| --- | --- | --- |
| `a-no-sink` | none — no sink, and `PointExecve` is off entirely | none |
| `b-sink` | `x = [/bin/busybox, /bin/execbench]` | `egress_refused`, `exec_refused` |
| `c-sink-trace` | the same | the same plus `sentry/execve` with `binary_sha256` |
| `d-claude` | none | `sentry/execve` with `binary_sha256` — the identities, with nothing refused |

The policy pushed in (b) and (c) names every binary the busybox workload runs,
so nothing the benchmark does is refused and what is measured is the decision
and not a refusal. `/bin/probe` and `/e2-script.sh` are deliberately **not** in
it.

## 1. What the sink costs

`execbench` measures one `fork` + `execve` + `wait4` of a program that does
nothing, three rounds of 200 per run:

| run | median of the three rounds | p95 of the three rounds |
| --- | --- | --- |
| `a-no-sink` | 18.234, 18.515, 17.957 ms | 22.94, 22.56, 21.39 ms |
| `b-sink` | 18.491, 18.599, 19.145 ms | 22.51, 22.15, 22.35 ms |
| `c-sink-trace` | 18.101, 18.966, 19.036 ms | 22.00, 22.63, 22.58 ms |

**Median `fork+execve+wait` goes from ~18.2 ms to ~18.8 ms, about +0.5 ms or
+3%. The p95s are indistinguishable (21.4–22.9 ms in every configuration), and
the three rounds within one configuration spread by as much as the difference
between configurations does — which is the honest bound on this number.**

The sink's own share of that is small and is measured directly — it times
itself and says so every hundred decisions:

    exec sink: checked=600 refused=2 mean=4.342µs hash-cache hits=596 misses=4

Six hundred decisions at a **mean of 4.3–5.4 µs** is 0.03% of an 18 ms
process start. So the +0.5 ms is *not the decision*; it is the `sentry/execve`
point the sink has to turn on — `execveSeccheckInfo` copying argv and the
environment, `Stat`ing the binary and looking the hash up — plus everything a
registered sink then does with the message. The honest summary is:

- **the X decision itself: ~5 µs per exec, flat, cached;**
- **turning the execve point on to get the identity it decides about: under a
  millisecond per exec on this platform, of the order of 3% of a process start
  and at the edge of what this benchmark can separate from noise.**

`fork+execve+wait` under systrap is ~18 ms, which dwarfs both. A workload that
starts processes in a tight loop pays a few percent; one that starts a handful
pays nothing measurable.

## 2. The hash cache: one miss per distinct file, and nothing else

Over 600 decisions in run (b): **596 hits, 4 misses, 99.3%**. The four misses
are exactly the four distinct files the workload executed. The cache key is
`(MountID, Ino, Size, MtimeSec, MtimeNsec)`
(`pkg/sentry/seccheck/execve_hash_cache.go`), and on a read-only rootfs that is
a perfect key: the same file is hashed once and never again, no matter how many
times or under how many names it is executed.

    600 checks, 4 distinct binaries  ->  4 misses
    616 execs of /bin/busybox        ->  1 miss

The cache holds 512 entries, so a workload with more than 512 distinct
executables would start evicting; nothing measured here comes near it. **The
cache key covers every interpreter seen, and covers them by identity rather
than by name — see §3, which is why that matters.**

## 3. What identity the point actually reports — two findings

### (a) A symlink is reported as the file it resolves to, not as the name typed

The workload execs `/bin/uname`, `/bin/echo`, `/bin/cat` and `/bin/sh`, all
symlinks to `/bin/busybox`. Every one of them is reported as:

    execve path=/bin/busybox sha256=dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14

and the whole run has exactly four distinct identities:

    616 execve path=/bin/busybox   sha256=dbac288c…6ac14
      3 execve path=/bin/execbench sha256=f4f6f8fb…f0e59
      1 execve path=/e2-script.sh  sha256=dad7d456…db581
      1 execve path=/bin/probe     sha256=72ec1b73…8eaae

(616 execs against the sink's own count of 600: the sink starts counting at the
first push, and the shell had already run before it.)

**So an `x` that names `/bin/busybox` by path covers every applet symlink.**
That answers, in the affirmative, the open question ticket 26's two-guest
workload asks in its own `OBSERVE` lines
(`docs/snp/evidence/ticket26/snp/policy-probe.sh`): `/bin/uname` and `/bin/sh`
run under an `x` of `[{"path":"/bin/busybox"}]`.

### (b) A script with a shebang is reported as THE SCRIPT, not as its interpreter

`/e2-script.sh` is `#!/bin/sh` plus one `echo`. Executed directly, it is
reported as `path=/e2-script.sh` with **the script's own sha256**, and under the
policy in force it is **refused**:

    workload: --- an exec of a script, whose interpreter is what is opened first
    from a child shell
    /e2-workload.sh: line 29: /e2-script.sh: Permission denied

    exec refused: path="/e2-script.sh" sha256=dad7d456…db581 reason=not-in-x
    exec_refused path=/e2-script.sh sha256=dad7d456…db581 reason=not-in-x
                 time=2026-09-18T19:14:31.811535559Z container_id=… thread_id=13

while `/bin/sh -c 'echo from a child shell'` — the same interpreter, named
explicitly — runs, because that execve's first opened executable is
`/bin/busybox`.

This is the opposite of what the seam map predicted ("interpreter scripts
resolve to the first opened executable", meaning the interpreter). The
`AfterOpen` hook in `pkg/sentry/kernel/task_exec.go` retains the *first*
executable opened, and for a `#!` script the first file opened **is the
script**. It is arguably the better answer — the identity of what runs is the
script, not the shell — but it is not the documented one, and it has a
consequence a policy author must know:

> **An `x` that names an interpreter does not grant the scripts it runs. Every
> directly-executed script needs its own entry, by path or by digest.**

A run that used `x = [/bin/busybox]` and then executed `./setup.sh` would see
`EACCES` on the script and no hint that the shell was permitted.

### (c) The refusal carries the identity, and the errno is EACCES

Both refusals in the run are the same shape: a `W` line in the sentry's log and
a `sentry/exec_refused` point at the receiver, with the path, the digest and
`reason=not-in-x`, and the workload sees `Permission denied`. `/bin/probe` is
the control that matters: it is byte-for-byte a copy of a **permitted** binary
with a comment appended, at a path that is not in `x`, and neither its path nor
its digest matches — so it is refused. A copy of busybox with nothing appended,
at a new path, would have been *permitted*, because a digest entry matches
contents and not names.

## 4. Claude Code: two identities, both stable, and nothing spent

`d-claude` is the Claude Code ELF at `/usr/local/bin/claude` in a rootfs built
the way `attest/cmd/agent-probe/claude_test.go`'s `buildClaudeRootfs` builds one
— the ELF, the loader, glibc and the NSS modules, the CA anchors, `git` — with
**no API key in the environment** and a tunnel table that names only
`nowhere.example`. It was asked for `--version` and then for a prompt:

    2.1.276 (Claude Code)
    CLAUDE-VERSION-RC=0
    Not logged in · Please run /login
    CLAUDE-PROMPT-RC=1

It exec'd, in one run, exactly two distinct identities:

    5 execve path=/usr/local/bin/claude sha256=8a56c8a14bd3cb246e2bdb7e60aefe0f609bff78c8bbcc5ea6b1817c111c6145
    3 execve path=/usr/bin/git          sha256=2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668

Five of its own binary — the CLI re-execs itself, which is exactly what the
ticket asked about — and three of `git`. **There is no Node**: this build is a
single self-contained ELF, so an `x` for it is two entries and not a list of
interpreters. The re-execs all report the same path and the same digest, so a
digest entry covers them.

It also produced four pairs of `egress_refused protocol=dns
name=api.anthropic.com reason=unknown-name` — Go-style AAAA+A pairs — which is
the adapter refusing the one name a policy would have to grant. Nothing left the
sandbox and nothing was charged.

**Verdict on the ticket's question.** `x` as `{path|sha256}` can name a real
runtime: Claude Code is two identities, both stable across re-execs, and busybox
is one identity however many applets it is reached through. What it cannot name
cheaply is a workload that runs scripts directly — see §3(b).

## 5. A side effect the record must carry

**Installing X makes every `execve` visible to whatever remote sink is already
configured, whether or not that session asked for the point.**
`seccheck.State.SentToSinks` calls *every* registered sink's `Execve`, so the
moment the X sink turns `PointExecve` on, the pod-init remote sink starts
receiving one `MESSAGE_SENTRY_EXEC` per exec — argv and environment included.
Run `b-sink`'s trace session names only `egress_refused` and `exec_refused`, and
its receiver logged **621 `execve` lines** anyway. That is why runs (b) and (c)
measure the same thing and why their numbers agree: they *are* the same
configuration.

Consequences, recorded and not fixed:

1. A sandbox with a trace sink and a policy carrying an `x` exports the command
   line and environment of every process it starts. In this design the sink is a
   local socket the same operator owns, but it is not nothing.
2. The cost attributed to "the sink" above therefore includes a protobuf
   write per exec. The 4.8 µs figure does not; it is the decision alone.

## 6. Files

| file | what |
| --- | --- |
| `run-e2.sh` | the four runs, exactly as run |
| `e2-workload.sh`, `e2-script.sh` | the busybox workload and the shebang script §3(b) is about |
| `execbench/` | the fork+execve+wait benchmark, built static and copied into the rootfs |
| `output-01-cost-and-reach.txt` | the untrimmed transcript of all four runs |
| `../../tools/seccheck-receiver/` | the receiver, extended here to decode `sentry/exec_refused` (type 40) and `sentry/execve` (type 3) |
