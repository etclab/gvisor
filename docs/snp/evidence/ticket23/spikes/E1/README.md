# E1 — what a trivial agent needs from the network, the filesystem and exec

**Question.** Before any sandbox is put under an agent, what does the smallest
possible tool-calling agent actually touch? One fixed three-step task, no
sandbox anywhere near it, under `strace`: the list of destinations and ports,
binaries executed and paths opened. That list is what `N`, `F` and `X` have to
be able to express — the model endpoint and the resolver included.

Nothing in the repository was changed by this spike. Everything it produced is
under this directory, and `attest/` is untouched.

---

## What ran

The agent is `agent.go` here: 294 lines, standard library only, its own nested
module so nothing in the tree builds it. Plain `net/http` against
`POST https://api.anthropic.com/v1/messages`, `x-api-key` from the environment,
`anthropic-version: 2023-06-01`. No SDK, no framework, no streaming, no
`thinking` parameter.

| what | value |
| --- | --- |
| model id | `claude-sonnet-5` |
| `max_tokens` | 4096 |
| tools | `fetch_url(url)` — GET, body truncated at 20 KB; `write_file(path, content)` |
| loop | send; while `stop_reason == "tool_use"`, run every `tool_use` block and return every `tool_result` in one user message; stop on `end_turn`; print and stop on `refusal` or `max_tokens` |
| prompt | one user message, the task below, verbatim in the source |

The task, fixed in `agent.go` so runs replay:

> Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a
> summary of it in at most five sentences, and save the summary to the file
> summary.txt in the current directory using write_file. Then reply with the
> word DONE.

`https://www.rfc-editor.org/rfc/rfc8446.txt` is reachable from this
workstation (`curl` returned 200, 337 736 bytes), so no substitution was
needed.

The commands, in order — `run.sh` is the same thing as a script:

```
go build -o $W/agent .
( cd $W && ./agent )                                                            > run-plain.log
( cd $W && strace -f -o run1-strace.raw -e trace=network,execve,openat -s 256 ./agent ) > run1.log
( cd $W && strace -f -o run2-strace.raw -e trace=network,execve,openat -s 256 ./agent ) > run2.log
( cd $W && strace -f -o run3-strace.raw -e trace=%network,%file,%process -s 256 ./agent ) > run3.log
python3 derive.py run1=… run2=… run3=… --host api.anthropic.com --host www.rfc-editor.org > table.md
```

The third run is there because the ticket says to try the wider filter if the
first form misses `connect()`. **It did not** — all fourteen `connect()` calls
and all 146 `openat()` calls are in both forms. What the narrow form misses is
`readlinkat`, `newfstatat` and `access`, which is the whole of why run 3 is
recorded: the certificate directory is walked through 246 `readlinkat` calls
that a policy written from `openat` alone would not know about.

## The result

Four runs, all four completed: `fetch_url`, then `write_file`, then `DONE`.
`summary-run1.txt` is what the third step wrote.

| run | strace | input tokens | output tokens | cost | wall |
| --- | --- | --- | --- | --- | --- |
| plain | none | 14 948 | 534 | $0.035236 | 6.515 s |
| 1 | `network,execve,openat` | 14 958 | 531 | $0.035226 | 7.189 s |
| 2 | `network,execve,openat` | 14 992 | 566 | $0.035644 | 7.358 s |
| 3 | `%network,%file,%process` | 14 998 | 571 | $0.035706 | 7.341 s |

Three requests per run every time — one to decide to fetch, one to summarise
and write, one to say DONE — priced at $2.00/M input and $10.00/M output for
`claude-sonnet-5`. About **$0.0355 a run**, and the input is dominated by the
20 KB of RFC 8446 that `fetch_url` puts into the second and third requests.
The whole conversation is resent each turn, which is why 657 input tokens
becomes 6 920 and then 7 421.

### The resource list

`derive.py` produces this from the raw strace. Counts are per run, in the order
run 1 / run 2 / run 3; a zero in the first two columns means the narrow filter
does not trace that call at all. Hostnames are attached by resolving the two
names at derive time and matching addresses — the strace itself carries
addresses and never a name, which is itself the point.

| kind | resource | protocol | seen (run1, run2, run3) | note |
| --- | --- | --- | --- | --- |
| destination | `104.18.20.81:443` | AF_INET/SOCK_STREAM | 1/1/1 | www.rfc-editor.org — -1 EINPROGRESS (Operation now in progress) |
| destination | `160.79.104.10:443` | AF_INET/SOCK_STREAM | 1/1/1 | api.anthropic.com — -1 EINPROGRESS (Operation now in progress) |
| destination | `127.0.0.53:53` | AF_INET/SOCK_DGRAM | 2/2/2 | — |
| destination | `104.18.20.81:0` | AF_INET/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — port 0: source-address selection, no bytes |
| destination | `104.18.21.81:0` | AF_INET/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — port 0: source-address selection, no bytes |
| destination | `160.79.104.10:0` | AF_INET/SOCK_DGRAM | 1/1/1 | api.anthropic.com — port 0: source-address selection, no bytes |
| destination | `2606:4700::6812:1451:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `2606:4700::6812:1551:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `2607:6bc0::10:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | api.anthropic.com — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `netlink:RTM_GETADDR` | AF_NETLINK/SOCK_RAW | 2/2/2 | — |
| destination | `unix:/var/run/nscd/socket` | AF_UNIX/SOCK_STREAM | 2/2/2 | -1 ENOENT (No such file or directory) |
| binary | `./agent` | execve | 1/1/1 | the only one |
| path | `/` | newfstatat | 0/0/1 | — |
| path | `/etc/gai.conf` | openat | 1/1/1 | — |
| path | `/etc/host.conf` | openat | 1/1/1 | — |
| path | `/etc/hosts` | openat | 2/2/2 | — |
| path | `/etc/ld.so.cache` | openat | 1/1/1 | — |
| path | `/etc/ld.so.preload` | access | 0/0/1 | -1 ENOENT (No such file or directory) |
| path | `/etc/nsswitch.conf` | newfstatat | 0/0/2 | — |
| path | `/etc/nsswitch.conf` | openat | 2/2/2 | — |
| path | `/etc/pki/tls/certs` | openat | 1/1/1 | -1 ENOENT (No such file or directory) |
| path | `/etc/resolv.conf` | newfstatat | 0/0/2 | — |
| path | `/etc/resolv.conf` | openat | 2/2/2 | — |
| path | `/etc/ssl/certs` | openat | 1/1/1 | — |
| path | `/etc/ssl/certs/ca-certificates.crt` | openat | 2/2/2 | — |
| path | `/lib/x86_64-linux-gnu/libc.so.6` | openat | 1/1/1 | — |
| path | `summary.txt` | openat | 1/1/1 | — |
| path | `/etc/ssl/certs/*.pem (the per-root walk)` | openat | 123/124/122 | collapsed |
| path | `/etc/ssl/certs/*.pem (the per-root walk)` | readlinkat | 0/0/121 | collapsed |
| path | `/etc/ssl/certs/<hash>.N (the hashed-symlink walk)` | readlinkat | 0/0/123 | collapsed |
| path | `/proc/* (Go runtime: maps, cgroup, mountinfo)` | openat | 3/3/3 | collapsed |
| path | `/sys/* (Go runtime: hugepage size, cpu.max, cpu/online)` | openat | 4/2/2 | collapsed |

### What the table says, in sentences

- **The model endpoint is one address.** `api.anthropic.com` resolved to
  `160.79.104.10` on every one of the three straced runs and on ten further
  `getaddrinfo` probes taken straight afterwards — one A record, no rotation
  observed. It also has one AAAA, `2607:6bc0::10`, which was tried and got
  `ENETUNREACH` because this box has no IPv6 route. An `n` entry that names
  one `/32` and port 443 would have carried every run here; an `n` entry that
  named *the name* would have carried all of them and the next one too.
- **The tool's endpoint is not one address.** `www.rfc-editor.org` is behind
  Cloudflare and resolves to two A records, `104.18.20.81` and `104.18.21.81`,
  and two AAAAs; which of the two is dialed is the resolver's choice per run.
  A policy pinned to an address would have been right by luck.
- **The resolver is a destination of its own.** `127.0.0.53:53` over UDP, twice
  a run — once per hostname. This is systemd-resolved's stub, not the real
  nameserver: what a policy has to permit on this box is a loopback datagram,
  and on another box it would be whatever `/etc/resolv.conf` names.
- **Resolution is glibc's, not Go's.** The binary is dynamically linked, so the
  cgo resolver runs: `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/gai.conf`,
  `/etc/hosts`, `/etc/resolv.conf`, a connect to `/var/run/nscd/socket` that
  gets `ENOENT`, and a netlink `RTM_GETADDR` dump to pick a source address.
  Five files and two non-IP sockets, none of which is in anybody's idea of "the
  agent talks to the model".
- **Source-address selection dials the destination with port 0.** Six of the
  fourteen `connect()` calls go to a real address on port 0 on a UDP socket and
  send nothing; they exist so glibc can ask the kernel which local address
  would be used. A rule set that matches on destination address alone will see
  them.
- **The trust store is a directory walk, not a file.** `/etc/ssl/certs`, its
  `ca-certificates.crt` bundle, then every `*.pem` in it — 122 to 124 `openat`
  calls a run — and, under the wider filter, 244 `readlinkat` calls resolving
  the hashed symlink names onto those files. `/etc/pki/tls/certs` is probed
  first and is `ENOENT`. `F` has to express this as a directory or the TLS handshake to the
  model does not happen.
- **One binary, no `exec`.** `execve` appears exactly once, for the agent
  itself. The 22 `clone3` calls are Go's own threads. `X` has nothing to
  express for an agent with these two tools — which is a fact about *these two
  tools*, and the first tool that shells out changes it.
- **One file written.** `summary.txt`, `openat` with `O_WRONLY|O_CREAT|O_TRUNC`
  in the working directory. That is the entire write side of the task.

## What broke, in what order

Nothing broke. Four runs, four completions, no retries, no non-200 response, no
`refusal` and no `max_tokens`. That is the finding E1 is for: with no sandbox
in the path the agent needs eleven destinations, one binary and about twenty
distinct paths, and every one of them was simply there.

The things worth carrying forward are not failures but the two mismatches
between this list and `(N, F, X)` as ticket 22 left it:

1. `n` is written as `{cidr, ports}`. Two of the three names here resolve to
   more than one address, and one of them is a CDN, so a CIDR is either wrong
   tomorrow or is `0.0.0.0/0`. What the agent knows is a **name**; what the
   policy can say is an **address**; the thing that turns one into the other is
   the resolver, which is itself a destination the policy has to permit.
2. The resolver's own inputs — `/etc/resolv.conf`, `/etc/nsswitch.conf`,
   `/etc/hosts`, `/etc/gai.conf`, `/etc/host.conf` — and the trust store are
   `f` entries that no author writing a policy about "this agent may reach the
   model" would think to write down. They are the price of the first TLS
   connection, not of anything the agent does.
