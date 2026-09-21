# E4 — what `claude -p` resolves, connects to, and opens

Derived from the untrimmed traces in this directory by `derive.py`; nothing here is hand-edited.

Runs: `run1`, `run2`, `run3`. `run1` is a HOME that has never been used, `run2` is the same HOME warm, `run3` is the operator's own configured HOME.

## How to read the connect rows

A `connect()` on a **SOCK_DGRAM** socket to a destination port sends no bytes. It is glibc's `getaddrinfo` asking the kernel which source address it would pick for that destination, so that RFC 3484 can sort the candidate list. Those rows are there because a sandbox has to answer them, not because traffic left. The port on such a row is 0 when `getaddrinfo` was called without a service and 443 when it was called with one; both are address selection, not a session.

A `connect()` on a **SOCK_STREAM** socket that returns `EINPROGRESS` is the real thing: a non-blocking TCP connect that then completes. `ENETUNREACH` on the AF_INET6 rows is this workstation having no IPv6 route; the client tries v6 first every time and would use it if it were there.

The name in the last column comes from the DNS answers in the same trace. The `TLS ClientHello SNI` rows are the independent witness: what the client itself puts on the wire as the name it means to reach.

## The ordered host list

| run | order of first contact | ports | refused or failed |
| --- | --- | --- | --- |
| run1 | `api.anthropic.com` → `http-intake.logs.us5.datadoghq.com` | api.anthropic.com: 443; http-intake.logs.us5.datadoghq.com: 443 | api.anthropic.com -1 ENETUNREACH ×2; unix:/var/run/nscd/socket -1 ENOENT ×2 |
| run2 | `api.anthropic.com` → `http-intake.logs.us5.datadoghq.com` | api.anthropic.com: 443; http-intake.logs.us5.datadoghq.com: 443 | api.anthropic.com -1 ENETUNREACH ×2; unix:/var/run/nscd/socket -1 ENOENT ×2 |
| run3 | `api.anthropic.com` → `http-intake.logs.us5.datadoghq.com` | api.anthropic.com: 443; http-intake.logs.us5.datadoghq.com: 443 | api.anthropic.com -1 ENETUNREACH ×3; unix:/var/run/nscd/socket -1 ENOENT ×2 |

## run1 — every network event, in the order strace wrote it

| # | tid | event | name / address | port | socket | result / detail | host |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3895798 | execve | `/home/pniroula/.local/bin/claude` | — | — | -p Reply with exactly the word OK. --output-format json --model claude-haiku-4-5-20251001 | — |
| 2 | 3896370 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 3 | 3896370 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 4 | 3896370 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 5 | 3896370 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 6 | 3896370 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 7 | 3896370 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 8 | 3896370 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 9 | 3896370 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 10 | 3896370 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 11 | 3896370 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 12 | 3896903 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 13 | 3896903 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 14 | 3896903 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 11 | api.anthropic.com |
| 15 | 3896370 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 16 | 3896370 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 17 | 3896370 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 18 | 3896370 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 19 | 3896370 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 20 | 3896370 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 21 | 3896370 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 22 | 3896370 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 23 | 3895798 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 24 | 3895798 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 25 | 3895798 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 12 | api.anthropic.com |
| 26 | 3895798 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 13 | api.anthropic.com |
| 27 | 3897623 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 28 | 3897666 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 29 | 3897744 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 30 | 3897578 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 31 | 3897578 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 32 | 3897578 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 33 | 3897578 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 34 | 3897578 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 35 | 3897578 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 36 | 3897578 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 37 | 3897578 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 38 | 3898213 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --version | — |
| 39 | 3898218 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /tmp/pniroula/claude-253477/-home-p | — |
| 40 | 3898225 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677 | — |
| 41 | 3898246 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 42 | 3895798 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 43 | 3895798 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 44 | 3895798 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 45 | 3896903 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 46 | 3896903 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 47 | 3896903 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 23 | api.anthropic.com |
| 48 | 3895798 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 18 | api.anthropic.com |
| 49 | 3895798 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 21 | api.anthropic.com |
| 50 | 3895798 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 22 | api.anthropic.com |
| 51 | 3898044 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 52 | 3898044 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 53 | 3898044 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | http-intake.logs.us5.datadoghq.com |
| 54 | 3898044 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | http-intake.logs.us5.datadoghq.com |
| 55 | 3898044 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 34.149.66.165 | http-intake.logs.us5.datadoghq.com |
| 56 | 3898044 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2600:1901:0:9e23:: | http-intake.logs.us5.datadoghq.com |
| 57 | 3898044 | connect | `34.149.66.165` | 0 | AF_INET/SOCK_DGRAM | 0 | http-intake.logs.us5.datadoghq.com |
| 58 | 3898044 | connect | `2600:1901:0:9e23::` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | http-intake.logs.us5.datadoghq.com |
| 59 | 3895798 | connect | `34.149.66.165` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | http-intake.logs.us5.datadoghq.com |
| 60 | 3895798 | TLS ClientHello SNI | `http-intake.logs.us5.datadoghq.com` | 443 | AF_INET/SOCK_STREAM | fd 16 | http-intake.logs.us5.datadoghq.com |

Address → name, read off the DNS answers in this same trace: `160.79.104.10` → `api.anthropic.com`; `2600:1901:0:9e23::` → `http-intake.logs.us5.datadoghq.com`; `2607:6bc0::10` → `api.anthropic.com`; `34.149.66.165` → `http-intake.logs.us5.datadoghq.com`

## run2 — every network event, in the order strace wrote it

| # | tid | event | name / address | port | socket | result / detail | host |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3901751 | execve | `/home/pniroula/.local/bin/claude` | — | — | -p Reply with exactly the word OK. --output-format json --model claude-haiku-4-5-20251001 | — |
| 2 | 3902549 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 3 | 3902549 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 4 | 3902549 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 5 | 3902549 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 6 | 3902549 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 7 | 3902549 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 8 | 3902549 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 9 | 3902549 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 10 | 3902549 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 11 | 3902549 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 12 | 3902774 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 13 | 3902774 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 14 | 3902774 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 11 | api.anthropic.com |
| 15 | 3902819 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 16 | 3902850 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 17 | 3902883 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 18 | 3902883 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 19 | 3902883 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 20 | 3902883 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 21 | 3902883 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 22 | 3902883 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 23 | 3902883 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 24 | 3902883 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 25 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 26 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 27 | 3903055 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 28 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 14 | api.anthropic.com |
| 29 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 17 | api.anthropic.com |
| 30 | 3902884 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 31 | 3902884 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 32 | 3902884 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 33 | 3902884 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 34 | 3902884 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 35 | 3902884 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 36 | 3902884 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 37 | 3902884 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 38 | 3903236 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --version | — |
| 39 | 3903237 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /tmp/pniroula/claude-253477/-home-p | — |
| 40 | 3903256 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677 | — |
| 41 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 42 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 43 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 44 | 3902774 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 45 | 3902774 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 46 | 3902774 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 27 | api.anthropic.com |
| 47 | 3903489 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 48 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 19 | api.anthropic.com |
| 49 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 23 | api.anthropic.com |
| 50 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 24 | api.anthropic.com |
| 51 | 3902885 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 52 | 3902885 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 53 | 3902885 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 54 | 3902885 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 55 | 3902885 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 56 | 3902885 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 57 | 3902885 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 58 | 3902885 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 59 | 3901751 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 60 | 3901751 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 15 | api.anthropic.com |
| 61 | 3902273 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 62 | 3902273 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 63 | 3902273 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | http-intake.logs.us5.datadoghq.com |
| 64 | 3902273 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | http-intake.logs.us5.datadoghq.com |
| 65 | 3902273 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 34.149.66.165 | http-intake.logs.us5.datadoghq.com |
| 66 | 3902273 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2600:1901:0:9e23:: | http-intake.logs.us5.datadoghq.com |
| 67 | 3902273 | connect | `34.149.66.165` | 0 | AF_INET/SOCK_DGRAM | 0 | http-intake.logs.us5.datadoghq.com |
| 68 | 3902273 | connect | `2600:1901:0:9e23::` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | http-intake.logs.us5.datadoghq.com |
| 69 | 3901751 | connect | `34.149.66.165` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | http-intake.logs.us5.datadoghq.com |
| 70 | 3901751 | TLS ClientHello SNI | `http-intake.logs.us5.datadoghq.com` | 443 | AF_INET/SOCK_STREAM | fd 18 | http-intake.logs.us5.datadoghq.com |

Address → name, read off the DNS answers in this same trace: `160.79.104.10` → `api.anthropic.com`; `2600:1901:0:9e23::` → `http-intake.logs.us5.datadoghq.com`; `2607:6bc0::10` → `api.anthropic.com`; `34.149.66.165` → `http-intake.logs.us5.datadoghq.com`

## run3 — every network event, in the order strace wrote it

| # | tid | event | name / address | port | socket | result / detail | host |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3905253 | execve | `/home/pniroula/.local/bin/claude` | — | — | -p Reply with exactly the word OK. --output-format json --model claude-haiku-4-5-20251001 | — |
| 2 | 3905831 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 3 | 3905831 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 4 | 3905831 | connect AF_UNIX | `/var/run/nscd/socket` | — | AF_UNIX/SOCK_STREAM | -1 ENOENT (No such file or directory) | — |
| 5 | 3905831 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 6 | 3905831 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 7 | 3905831 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 8 | 3905831 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 9 | 3905831 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 10 | 3905831 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 11 | 3905831 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 12 | 3906087 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 13 | 3906087 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 14 | 3905508 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 15 | 3905508 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 16 | 3905508 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 17 | 3905508 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 18 | 3905508 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 19 | 3905508 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 20 | 3905508 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 21 | 3905508 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 22 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 23 | 3905502 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 24 | 3905502 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 25 | 3905502 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 26 | 3905502 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 27 | 3905502 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 28 | 3905502 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 29 | 3905502 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 30 | 3905502 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 31 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 15 | api.anthropic.com |
| 32 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 33 | 3907219 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 34 | 3907405 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 35 | 3907688 | execve | `/usr/bin/git` | — | — | -c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto= | — |
| 36 | 3908309 | execve | `/bin/sh` | — | — | -c ps -o command= -p 3121496 | — |
| 37 | 3908318 | execve | `/usr/bin/ps` | — | — | -o command= -p 3121496 | — |
| 38 | 3905502 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 39 | 3905502 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 40 | 3905502 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 41 | 3905502 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 42 | 3905502 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 43 | 3905502 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 44 | 3905502 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 45 | 3905502 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 46 | 3909627 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677 | — |
| 47 | 3909714 | execve | `/usr/bin/git` | — | — | -c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t | — |
| 48 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 49 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 50 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 51 | 3906087 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 52 | 3906087 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 53 | 3906969 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 54 | 3906969 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 55 | 3906969 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 56 | 3906969 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 57 | 3906969 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 58 | 3906969 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 59 | 3906969 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 60 | 3906969 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 61 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 62 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 16 | api.anthropic.com |
| 63 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 17 | api.anthropic.com |
| 64 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 19 | api.anthropic.com |
| 65 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 22 | api.anthropic.com |
| 66 | 3910136 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --version | — |
| 67 | 3910141 | execve | `/home/pniroula/.local/share/claude/versions/2.1.276` | — | — | --no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /home/pniroula/.claude/plugins/cach | — |
| 68 | 3906969 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 69 | 3906969 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 70 | 3906969 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | api.anthropic.com |
| 71 | 3906969 | DNS query | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | api.anthropic.com |
| 72 | 3906969 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 160.79.104.10 | api.anthropic.com |
| 73 | 3906969 | DNS answer | `api.anthropic.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2607:6bc0::10 | api.anthropic.com |
| 74 | 3906969 | connect | `160.79.104.10` | 0 | AF_INET/SOCK_DGRAM | 0 | api.anthropic.com |
| 75 | 3906969 | connect | `2607:6bc0::10` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 76 | 3905253 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 77 | 3905253 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 24 | api.anthropic.com |
| 78 | 3906087 | connect | `160.79.104.10` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | api.anthropic.com |
| 79 | 3906087 | connect | `2607:6bc0::10` | 443 | AF_INET6/SOCK_STREAM | -1 ENETUNREACH (Network is unreachable) | api.anthropic.com |
| 80 | 3906087 | TLS ClientHello SNI | `api.anthropic.com` | 443 | AF_INET/SOCK_STREAM | fd 26 | api.anthropic.com |
| 81 | 3907546 | netlink | `RTM_GETADDR` | — | AF_NETLINK/SOCK_RAW | — | — |
| 82 | 3907546 | connect | `127.0.0.53` | 53 | AF_INET/SOCK_DGRAM | 0 | — |
| 83 | 3907546 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE A | http-intake.logs.us5.datadoghq.com |
| 84 | 3907546 | DNS query | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | QTYPE AAAA | http-intake.logs.us5.datadoghq.com |
| 85 | 3907546 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | A: A 34.149.66.165 | http-intake.logs.us5.datadoghq.com |
| 86 | 3907546 | DNS answer | `http-intake.logs.us5.datadoghq.com` | 53 (127.0.0.53) | AF_INET/SOCK_DGRAM | AAAA: AAAA 2600:1901:0:9e23:: | http-intake.logs.us5.datadoghq.com |
| 87 | 3907546 | connect | `34.149.66.165` | 0 | AF_INET/SOCK_DGRAM | 0 | http-intake.logs.us5.datadoghq.com |
| 88 | 3907546 | connect | `2600:1901:0:9e23::` | 0 | AF_INET6/SOCK_DGRAM | -1 ENETUNREACH (Network is unreachable) | http-intake.logs.us5.datadoghq.com |
| 89 | 3905253 | connect | `34.149.66.165` | 443 | AF_INET/SOCK_STREAM | -1 EINPROGRESS (Operation now in progress) | http-intake.logs.us5.datadoghq.com |
| 90 | 3905253 | TLS ClientHello SNI | `http-intake.logs.us5.datadoghq.com` | 443 | AF_INET/SOCK_STREAM | fd 20 | http-intake.logs.us5.datadoghq.com |

Address → name, read off the DNS answers in this same trace: `160.79.104.10` → `api.anthropic.com`; `2600:1901:0:9e23::` → `http-intake.logs.us5.datadoghq.com`; `2607:6bc0::10` → `api.anthropic.com`; `34.149.66.165` → `http-intake.logs.us5.datadoghq.com`

## Paths, all runs

Everything under the run's `HOME`, everything under `/etc/ssl`, and `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/hosts`, `/etc/host.conf`, `/etc/gai.conf`. `/proc`, `/sys`, the loader's own files and the certificate-directory walk are collapsed into one row each; every other row is a single path.

| class | path | call | result | seen (run1, run2, run3) |
| --- | --- | --- | --- | --- |
| RESOLVER | `/etc/gai.conf` | openat | ok | 0/1/1 |
| RESOLVER | `/etc/host.conf` | openat | ok | 0/1/1 |
| RESOLVER | `/etc/hosts` | openat | ok | 3/5/5 |
| RESOLVER | `/etc/nsswitch.conf` | newfstatat | ok | 4/3/5 |
| RESOLVER | `/etc/nsswitch.conf` | openat | ok | 0/1/0 |
| RESOLVER | `/etc/resolv.conf` | newfstatat | ok | 4/5/3 |
| RESOLVER | `/etc/resolv.conf` | openat | ok | 0/1/0 |
| TLS | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | openat | -1 ENOENT | 1/1/1 |
| TLS | `/etc/pki/tls/cert.pem` | openat | -1 ENOENT | 1/1/1 |
| TLS | `/etc/pki/tls/certs` | openat | -1 ENOENT | 1/1/1 |
| TLS | `/etc/pki/tls/certs/ca-bundle.crt` | openat | -1 ENOENT | 1/1/1 |
| TLS | `/etc/ssl/ca-bundle.pem` | openat | -1 ENOENT | 1/1/1 |
| TLS | `/etc/ssl/cert.pem` | openat | -1 ENOENT | 2/3/2 |
| TLS | `/etc/ssl/certs` | openat | ok | 2/2/2 |
| TLS | `/etc/ssl/certs/ca-certificates.crt` | openat | ok | 1/1/1 |
| TLS | `/usr/share/ca-certificates` | openat | ok | 1/1/1 |
| HOME | `$HOME` | mkdir | -1 EEXIST | 13/1/3 |
| HOME | `$HOME` | newfstatat | ok | 13/1/3 |
| HOME | `$HOME` | openat | ok | 4/2/1 |
| HOME | `$HOME` | statx | ok | 48/20/58 |
| HOME | `$HOME/.claude` | mkdir | ok | 1/0/0 |
| HOME | `$HOME/.claude` | openat | ok | 6/7/2 |
| HOME | `$HOME/.claude` | statx | ok | 33/22/67 |
| HOME | `$HOME/.claude` | statx | -1 ENOENT | 18/0/0 |
| HOME | `$HOME/.claude.json` | openat | ok | 22/3/7 |
| HOME | `$HOME/.claude.json` | openat | -1 ENOENT | 2/0/0 |
| HOME | `$HOME/.claude.json` | readlink | -1 EINVAL | 8/1/3 |
| HOME | `$HOME/.claude.json` | readlink | -1 ENOENT | 1/0/0 |
| HOME | `$HOME/.claude.json` | statx | -1 ENOENT | 3/0/0 |
| HOME | `$HOME/.claude.json` | statx | ok | 14/7/8 |
| HOME | `$HOME/.claude.json.backup` | statx | -1 ENOENT | 2/0/0 |
| HOME | `$HOME/.claude.json.lock` | mkdir | ok | 8/1/2 |
| HOME | `$HOME/.claude.json.lock` | statx | ok | 11/0/1 |
| HOME | `$HOME/.claude.json.tmp.<pid>.<nonce>` | openat | ok | 10/1/1 |
| HOME | `$HOME/.claude/.config.json` | access | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/.credentials.json` | openat | ok | 0/0/16 |
| HOME | `$HOME/.claude/.credentials.json` | openat | -1 ENOENT | 10/9/0 |
| HOME | `$HOME/.claude/.credentials.json` | statx | -1 ENOENT | 4/3/0 |
| HOME | `$HOME/.claude/.credentials.json` | statx | ok | 0/0/7 |
| HOME | `$HOME/.claude/CLAUDE.md` | openat | -1 ENOENT | 1/1/0 |
| HOME | `$HOME/.claude/CLAUDE.md` | statx | -1 ENOENT | 1/2/0 |
| HOME | `$HOME/.claude/CLAUDE.md` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/agents` | statx | -1 ENOENT | 2/2/0 |
| HOME | `$HOME/.claude/backups` | mkdir | -1 ENOENT | 1/0/0 |
| HOME | `$HOME/.claude/backups` | mkdir | ok | 1/0/0 |
| HOME | `$HOME/.claude/backups` | mkdir | -1 EEXIST | 10/1/3 |
| HOME | `$HOME/.claude/backups` | newfstatat | ok | 9/0/1 |
| HOME | `$HOME/.claude/backups` | openat | -1 ENOENT | 2/0/0 |
| HOME | `$HOME/.claude/backups` | openat | ok | 12/1/2 |
| HOME | `$HOME/.claude/backups` | statx | ok | 1/1/0 |
| HOME | `$HOME/.claude/backups/** (collapsed)` | openat | ok | 1/0/0 |
| HOME | `$HOME/.claude/cache` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/cache/** (collapsed)` | openat | -1 ENOENT | 2/3/1 |
| HOME | `$HOME/.claude/cache/** (collapsed)` | openat | ok | 0/0/1 |
| HOME | `$HOME/.claude/commands` | openat | ok | 0/0/2 |
| HOME | `$HOME/.claude/commands` | statx | -1 ENOENT | 1/1/0 |
| HOME | `$HOME/.claude/commands` | statx | ok | 0/0/3 |
| HOME | `$HOME/.claude/commands/** (collapsed)` | openat | ok | 0/0/1 |
| HOME | `$HOME/.claude/commands/** (collapsed)` | statx | ok | 0/0/5 |
| HOME | `$HOME/.claude/daemon` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/ide` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/jobs` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/output-styles` | statx | -1 ENOENT | 0/1/1 |
| HOME | `$HOME/.claude/paste-cache` | openat | ok | 0/0/1 |
| HOME | `$HOME/.claude/paste-cache` | statx | ok | 0/0/1 |
| HOME | `$HOME/.claude/plans` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/plugins` | openat | ok | 0/0/2 |
| HOME | `$HOME/.claude/plugins` | openat | -1 ENOENT | 2/2/0 |
| HOME | `$HOME/.claude/plugins` | statx | -1 ENOENT | 6/6/0 |
| HOME | `$HOME/.claude/plugins` | statx | ok | 0/0/44 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | chdir | ok | 0/0/1 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | mkdir | -1 EEXIST | 0/0/1 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | openat | -1 ENOENT | 8/9/10 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | openat | ok | 0/0/50 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | openat | -1 EEXIST | 0/0/1 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | stat | -1 ENOENT | 0/0/4 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | statx | -1 ENOENT | 7/7/30 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | statx | ok | 0/0/253 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | unlink | ok | 0/0/1 |
| HOME | `$HOME/.claude/plugins/** (collapsed)` | unlink | -1 ENOENT | 0/0/1 |
| HOME | `$HOME/.claude/policy-limits.json` | openat | -1 ENOENT | 7/0/11 |
| HOME | `$HOME/.claude/policy-limits.json` | openat | ok | 0/3/0 |
| HOME | `$HOME/.claude/policy-limits.json` | statx | -1 ENOENT | 1/0/1 |
| HOME | `$HOME/.claude/policy-limits.json` | statx | ok | 0/1/0 |
| HOME | `$HOME/.claude/policy-limits.json.signature-iat.json` | openat | -1 ENOENT | 0/1/0 |
| HOME | `$HOME/.claude/policy-limits.json.signature.json` | openat | -1 ENOENT | 0/1/0 |
| HOME | `$HOME/.claude/policy-limits.json.signature.json` | unlink | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/policy-limits.json.stamp.json` | openat | -1 ENOENT | 8/0/11 |
| HOME | `$HOME/.claude/policy-limits.json.stamp.json` | openat | ok | 1/5/1 |
| HOME | `$HOME/.claude/policy-limits.json.stamp.json.tmp.<pid>.<nonce>` | openat | ok | 2/1/2 |
| HOME | `$HOME/.claude/projects` | openat | ok | 0/1/0 |
| HOME | `$HOME/.claude/projects` | statx | ok | 2/2/0 |
| HOME | `$HOME/.claude/projects/** (collapsed)` | mkdir | -1 ENOENT | 3/0/1 |
| HOME | `$HOME/.claude/projects/** (collapsed)` | mkdir | -1 EEXIST | 1/0/0 |
| HOME | `$HOME/.claude/projects/** (collapsed)` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/projects/** (collapsed)` | openat | ok | 9/9/8 |
| HOME | `$HOME/.claude/projects/** (collapsed)` | statx | -1 ENOENT | 3/3/1 |
| HOME | `$HOME/.claude/remote-settings.json` | openat | -1 ENOENT | 30/0/27 |
| HOME | `$HOME/.claude/remote-settings.json` | openat | ok | 1/3/1 |
| HOME | `$HOME/.claude/remote-settings.json` | statx | ok | 0/3/0 |
| HOME | `$HOME/.claude/remote-settings.json` | statx | -1 ENOENT | 47/0/58 |
| HOME | `$HOME/.claude/remote-settings.json.signature-iat.json` | openat | -1 ENOENT | 0/1/0 |
| HOME | `$HOME/.claude/remote-settings.json.signature.json` | openat | -1 ENOENT | 0/1/0 |
| HOME | `$HOME/.claude/remote-settings.json.signature.json` | unlink | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/rules` | openat | -1 ENOENT | 2/1/0 |
| HOME | `$HOME/.claude/rules` | statx | -1 ENOENT | 1/0/1 |
| HOME | `$HOME/.claude/session-env` | openat | ok | 0/0/1 |
| HOME | `$HOME/.claude/sessions` | mkdir | ok | 1/0/0 |
| HOME | `$HOME/.claude/sessions` | mkdir | -1 EEXIST | 1/2/0 |
| HOME | `$HOME/.claude/sessions` | openat | ok | 1/1/0 |
| HOME | `$HOME/.claude/sessions` | statx | ok | 1/1/0 |
| HOME | `$HOME/.claude/sessions/** (collapsed)` | openat | ok | 5/5/2 |
| HOME | `$HOME/.claude/sessions/** (collapsed)` | statx | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/sessions/** (collapsed)` | unlink | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/sessions/** (collapsed)` | unlink | ok | 2/3/3 |
| HOME | `$HOME/.claude/settings.json` | openat | ok | 0/0/18 |
| HOME | `$HOME/.claude/settings.json` | openat | -1 ENOENT | 10/12/0 |
| HOME | `$HOME/.claude/settings.json` | openat | -1 ENOTDIR | 0/0/1 |
| HOME | `$HOME/.claude/settings.json` | statx | -1 ENOENT | 13/18/0 |
| HOME | `$HOME/.claude/settings.json` | statx | ok | 0/0/13 |
| HOME | `$HOME/.claude/shell-snapshots` | openat | ok | 0/0/1 |
| HOME | `$HOME/.claude/skills` | openat | ok | 0/0/2 |
| HOME | `$HOME/.claude/skills` | openat | -1 ENOENT | 2/2/0 |
| HOME | `$HOME/.claude/skills` | statx | -1 ENOENT | 1/1/0 |
| HOME | `$HOME/.claude/skills` | statx | ok | 0/0/3 |
| HOME | `$HOME/.claude/skills/** (collapsed)` | openat | ok | 0/0/40 |
| HOME | `$HOME/.claude/skills/** (collapsed)` | openat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.claude/skills/** (collapsed)` | statx | -1 ENOENT | 1/0/2 |
| HOME | `$HOME/.claude/skills/** (collapsed)` | statx | ok | 0/0/98 |
| HOME | `$HOME/.claude/state/** (collapsed)` | openat | -1 ENOENT | 1/0/1 |
| HOME | `$HOME/.claude/telemetry` | openat | -1 ENOENT | 2/1/1 |
| HOME | `$HOME/.claude/telemetry/** (collapsed)` | statx | -1 ENOENT | 2/1/1 |
| HOME | `$HOME/.claude/themes` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.claude/workflows` | openat | -1 ENOENT | 1/1/0 |
| HOME | `$HOME/.config/anthropic/active_config` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.config/anthropic/configs/default.json` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.config/git/config` | access | -1 ENOENT | 4/4/4 |
| HOME | `$HOME/.config/git/config` | openat | -1 ENOENT | 1/1/1 |
| HOME | `$HOME/.config/git/ignore` | statx | -1 ENOENT | 1/0/1 |
| HOME | `$HOME/.gitconfig` | access | -1 ENOENT | 4/4/0 |
| HOME | `$HOME/.gitconfig` | access | ok | 0/0/3 |
| HOME | `$HOME/.gitconfig` | openat | -1 ENOENT | 1/1/0 |
| HOME | `$HOME/.gitconfig` | openat | ok | 0/0/3 |
| HOME | `$HOME/.local/bin/bun` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/deno` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/git` | stat | -1 ENOENT | 0/0/6 |
| HOME | `$HOME/.local/bin/node` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/npm` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/pnpm` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/ps` | newfstatat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/bin/yarn` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.local/share/ripwire/skills/ripwire-before-you-build` | statx | ok | 0/0/1 |
| HOME | `$HOME/.local/share/ripwire/skills/ripwire-fresh-eyes` | statx | ok | 0/0/1 |
| HOME | `$HOME/.local/share/ripwire/skills/ripwire-graph-query` | statx | ok | 0/0/1 |
| HOME | `$HOME/.local/share/ripwire/skills/ripwire-mcp` | statx | ok | 0/0/1 |
| HOME | `$HOME/.local/share/ripwire/skills/ripwire-write-tests` | statx | ok | 0/0/1 |
| HOME | `$HOME/.local/state/claude/locks` | mkdir | -1 EEXIST | 0/0/1 |
| HOME | `$HOME/.local/state/claude/locks` | newfstatat | ok | 0/0/1 |
| HOME | `$HOME/.local/state/claude/locks/2.1.276.lock` | openat | ok | 0/0/1 |
| HOME | `$HOME/.local/state/claude/locks/2.1.276.lock` | statx | ok | 0/0/1 |
| HOME | `$HOME/.nix-profile/bin/bun` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/deno` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/git` | stat | -1 ENOENT | 0/0/5 |
| HOME | `$HOME/.nix-profile/bin/node` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/npm` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/pnpm` | stat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/ps` | newfstatat | -1 ENOENT | 0/0/2 |
| HOME | `$HOME/.nix-profile/bin/yarn` | stat | -1 ENOENT | 0/0/2 |
| collapse | `/etc/ssl/certs/*.pem (the per-root walk)` | openat | ok | 46/46/46 |
| collapse | `/etc/ssl/certs/<hash>.N (the hashed-symlink walk)` | openat | -1 ENOENT | 2/2/0 |
| collapse | `/etc/ssl/certs/<hash>.N (the hashed-symlink walk)` | openat | ok | 77/77/77 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | access | -1 ENOENT | 1/1/0 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | newfstatat | -1 ENOENT | 0/0/17 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | newfstatat | ok | 0/0/859 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | open | ok | 3/4/3 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | openat | -1 EACCES | 0/0/815 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | openat | ok | 188/191/2838 |
| collapse | `/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)` | readlink | ok | 29/19/74 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | access | -1 ENOENT | 20/20/18 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | open | ok | 4/4/3 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | openat | -1 ENOENT | 4/5/5 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | openat | ok | 12/14/17 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | openat | -1 EACCES | 1/1/1 |
| collapse | `/sys/* (runtime: cgroup limits, cpu online, hugepages)` | statx | ok | 1/1/2 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | access | -1 ENOENT | 7/7/6 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | newfstatat | ok | 0/0/4 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | newfstatat | -1 ENOENT | 0/0/12 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | openat | ok | 36/38/49 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | openat | -1 ENOENT | 0/0/16 |
| collapse | `the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)` | statx | -1 ENOENT | 1/1/1 |

## Binaries executed

| binary | argv (after argv[0]) | seen (run1, run2, run3) |
| --- | --- | --- |
| `/bin/sh` | `-c ps -o command= -p 3121496` | 0/0/1 |
| `/home/pniroula/.local/bin/claude` | `-p Reply with exactly the word OK. --output-format json --model claude-haiku-4-5-20251001` | 1/1/1 |
| `/home/pniroula/.local/share/claude/versions/2.1.276` | `--no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /home/pniroula/.claude/plugins/cache` | 0/0/1 |
| `/home/pniroula/.local/share/claude/versions/2.1.276` | `--no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da5` | 1/1/0 |
| `/home/pniroula/.local/share/claude/versions/2.1.276` | `--no-config --files --hidden /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/e4/work1` | 1/1/0 |
| `/home/pniroula/.local/share/claude/versions/2.1.276` | `--no-config --files --hidden /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/scratchpad/e4/work3` | 0/0/1 |
| `/home/pniroula/.local/share/claude/versions/2.1.276` | `--version` | 1/1/1 |
| `/usr/bin/git` | `-c core.askPass= -c protocol.ext.allow=never -c submodule.recurse=false -c log.showSignature=false -c gc.auto=0 -c maintenance.auto=false -c core.hook` | 2/2/2 |
| `/usr/bin/git` | `-c core.hooksPath=/dev/null -c core.fsmonitor= -C /tmp/pniroula/claude-253477/-home-pniroula-Projects-gvisor-t25/77e098ee-da53-4677-85ec-c450ded9db44/` | 2/2/2 |
| `/usr/bin/ps` | `-o command= -p 3121496` | 0/0/1 |
