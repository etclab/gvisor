# A real agent on the contract, two hops

Ticket 23. Ticket 22 made tunneld the network boundary for whatever sandbox sits beside it and
made the boundary three verbs wide; its only client was the echo exercise. This is the first
real one: a tool-calling agent against the Claude API on `claude-sonnet-5`, at most three
network tools, no framework, run direct, then behind the null sandbox, then behind Deno, and
finally across two delegation hops with a policy pushed on each. The agent is untrusted and
unmeasured, holds no key and sees no trust decision — it gets a stream or an error. Nothing
under `pkg/` or `runsc/` changed. The four spikes this stands on are recorded under
`docs/snp/evidence/ticket23/spikes/E1`–`E4`, the two live runs of the promoted binary under
`docs/snp/evidence/ticket23/agent-probe/`, and the two live runs of the two hops under
`docs/snp/evidence/ticket23/twohops/`.

**In one sentence:** the contract carried the agent end to end, needing exactly one interface
change — the three deadlines on `Stream` — and no change to the wire; Deno enforced `N` for the
names an agent actually writes and nothing below names, so the resolver, the loader, the trust
store, `/proc`, netlink and the agent's own binary went unpoliced; and **"apply then ack" is not
enough when apply starts a process**, because the acknowledgement is a claim about the past.

---

## The resource list

The task is fixed in the source of every agent in this ticket — E1's `agent.go`, E3's and the
promoted `deno/agent.ts`, and `attest/cmd/agent-probe` — so that two runs are two runs of the
same thing. Verbatim:

> Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at
> most five sentences, and save the summary to the file summary.txt in the current directory
> using write_file. Then reply with the word DONE.

The model is `claude-sonnet-5`, `max_tokens` 4096, `anthropic-version: 2023-06-01`, against
`POST https://api.anthropic.com/v1/messages`; the two tools are `fetch_url(url)` — GET,
truncated at 20 KB — and `write_file(path, content)`; the loop is manual and there is no SDK.
Three requests a run every time: one to decide to fetch, one to summarise and write, one to say
DONE. E1's four runs, priced at $2.00/M input and $10.00/M output:

| run | strace | input tokens | output tokens | cost | wall |
| --- | --- | --- | --- | --- | --- |
| plain | none | 14 948 | 534 | $0.035236 | 6.515 s |
| 1 | `network,execve,openat` | 14 958 | 531 | $0.035226 | 7.189 s |
| 2 | `network,execve,openat` | 14 992 | 566 | $0.035644 | 7.358 s |
| 3 | `%network,%file,%process` | 14 998 | 571 | $0.035706 | 7.341 s |

About **$0.0355 a run**, dominated by the 20 KB of RFC 8446 that `fetch_url` puts into the
second and third requests: the whole conversation is resent each turn, so 657 input tokens
becomes 6 920 and then 7 421.

**The endpoints are not equally stable, and the difference is the whole argument about `n`.**
`api.anthropic.com` resolved to `160.79.104.10` on every one of the three straced runs and on
ten further `getaddrinfo` probes taken straight afterwards — one A record, no rotation observed
— plus one AAAA, `2607:6bc0::10`, tried and `ENETUNREACH` because the workstation has no IPv6
route. `www.rfc-editor.org` is behind Cloudflare: two A records, `104.18.20.81` and
`104.18.21.81`, and two AAAAs, and which of the two is dialed is the resolver's choice per run.
A policy pinned to an address would have been right by luck.

The list below is E1's table verbatim (`docs/snp/evidence/ticket23/spikes/E1/table.md`), derived
from the raw strace by `derive.py`. Counts are per run, run 1 / run 2 / run 3; a zero in the
first two columns means the narrow filter does not trace that call at all. Hostnames are
attached by resolving the two names at derive time and matching addresses — the strace carries
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

Eleven destinations, one binary and about twenty distinct paths, and with no sandbox in the path
every one of them was simply there: four runs, four completions, no retries, no non-200 and no
`max_tokens`. Three facts out of that table are carried by everything below. **Resolution is
glibc's, not Go's** — the binary is dynamically linked, so `/etc/nsswitch.conf`,
`/etc/host.conf`, `/etc/gai.conf`, `/etc/hosts`, `/etc/resolv.conf`, an `nscd` socket that is
`ENOENT` and a netlink `RTM_GETADDR` are the price of the first name being resolved at all.
**Source-address selection dials the destination on port 0** over UDP and sends nothing, so six
of the fourteen `connect()` calls exist only so glibc can ask the kernel which local address
would be used, and a rule set matching on destination address alone will see them. **The trust
store is a directory walk**, 122 to 124 `openat` and 244 `readlinkat` a run, so `F` has to be
able to say "a directory" or the TLS handshake to the model does not happen.

## What the contract could not express

E2 put E1's agent, byte-identical below the shared line, behind `Open(ctx, peer)` for every
outbound connection: two in-process tunnelds over loopback with the fake platform, a throwaway
exit at the far end, TLS end to end from the agent to the model so the exit sees a ClientHello
and then ciphertext. **Nothing broke.** Three runs, three completions, so the ticket's stop rule
was not triggered — the contract can carry the agent. What it could not do was *express* any of
it. Seven lines, each one what the contract ran out of and what the throwaway shim did instead:

| break | what the shim did | what this ticket did about it |
| --- | --- | --- |
| 1. name resolution does not happen on the agent's side at all — `DialContext` is handed `api.anthropic.com:443`, and a dialer that never resolves means the agent never resolves | resolved at the far end: `EXIT resolved and dialed api.anthropic.com:443 -> 160.79.104.10:443`. Every resolver row of E1's table moved to the exit | nothing, deliberately. It is recorded as a change in *whose policy the resolver is in*, and `attest/cmd/agent-probe`'s exit resolves and dials exactly as the shim did |
| 2. the contract cannot name the model endpoint: `Open` takes a peer name, a peer is a sandbox and `api.anthropic.com:443` is neither a peer nor attestable | invented a protocol the contract does not define — every dial asks for the one peer `"b"` and writes `CONNECT host:port\n` as the first line | promoted into `attest/cmd/agent-probe/exit.go` with one addition, an `OK host:port\n` / `REFUSED host:port\n` answer line, so a refusal is told apart from a destination slow to speak. The contract still carries no destination |
| 3. `sandbox.Stream` is not a `net.Conn`: no `LocalAddr`, no `RemoteAddr`, no three deadlines | fabricated the two addresses, which is harmless, and returned `nil` from the three deadlines, which is not: `net/http` and `crypto/tls` both believed it, so the agent had no I/O timeout at all | **fixed** — contract version 2, below. `conn.go`'s methods are delegations and no longer lies; the addresses are still fabricated and say `synthetic` |
| 4. HTTP/2 silently stops being used: an `http.Transport` with its own `DialContext` does not configure it unless `ForceAttemptHTTP2` is set | set the flag, so both experiments are comparable | set in `agent-probe` too; both live runs print `proto=HTTP/2.0`. Recorded as a thing moving an agent behind a contract would otherwise change quietly |
| 5. the tool fetch — same client, so the second `Open` and the exit's second dial | nothing | nothing; no new problem |
| 6. file writes are outside the contract entirely: `write_file` is `os.WriteFile` and there is no file verb, so `f` is a field in a document nothing between the agent and the disk ever sees | nothing | `f` is enforced by the sandbox that *starts* the workload (`attest/sandbox/deno`), not by the contract, which still has no file verb |
| 7. `CloseWrite`, end-of-file and keep-alive interact with nothing, but an exit cannot tell a peer that finished from a peer that gave up | nothing | nothing: ticket 22's own finding about the pump, arriving from the other side. There is still no reset |

The cost of the contract, for the record: 34–44 ms on the first `Open` — dial, both sides judge
the other's evidence, push, ack — and 164 µs and 277 µs on every later one, which is a QUIC
stream on a tunnel that is already there. E2's three runs were 7.807–8.448 s wall and
$0.036006–$0.036604 against E1's 6.5–7.4 s and $0.0352–$0.0357: **about one second on a
seven-second task**, nearly all of it the first `Open` plus two `net.Dial`s at the exit that E1
paid inside its own process. Four HTTP requests went over two `Open` calls, because
`http.Transport` pooled the connection; nothing in the contract decides that.

## Contract version 2

**What changed: the three deadlines, and nothing else.** `sandbox.Stream` gained `SetDeadline`,
`SetReadDeadline` and `SetWriteDeadline`. Neither implementation had to learn anything — a
`*net.UnixConn` has had them since before the package existed, and so has `*quic.Stream`, which
`tunnel.Stream` now delegates all three to (`attest/tunnel/tunnel.go:590`). The interface was
hiding a capability both ends already had. **The wire is unchanged, the local socket protocol is
unchanged, and the four `Attested` strings are unchanged**: a deadline is a fact about one
side's own blocked call and nothing about it goes anywhere, which is exactly what separates it
from a reset, which neither end can deliver. `docs/sandbox-contract.md` carries the amendment
and `TestAReadDeadlineOnAStreamExpires` (`attest/tunneld/sandbox_test.go:251`) is the assertion,
one subtest per implementation.

**What deliberately did not change, and why.**

- **A destination is still not part of `Open`.** A peer is a sandbox, not an exit: a name in the
  peer table maps to an address this tunneld dials and attests, and `api.anthropic.com:443` is
  neither. Putting a destination in `Open` would make tunneld the thing that decides where an
  untrusted agent may go, which is the one decision this design keeps out of the contract. An
  agent that wants the public internet from behind the contract needs **an exit at a peer** —
  `agent-probe -exit -network socket -sandbox-socket PATH -allow host:port,...` — and that
  `-allow` list is where `N` is enforced for that agent. An empty list refuses everything, which
  is the honest default for a process whose whole job is to be the place a destination is
  checked; a refused destination and an unreachable one are the same `REFUSED` line on purpose,
  because the agent is told a stream did not happen and never why. The `CONNECT` line is a
  protocol *above* the contract and the contract neither defines it nor sees it.
- **There is still no liveness verb.** E4 and the two hops say what it would be for and what it
  costs not to have one — the section on two hops, below, and "What is not built". It is
  recorded, not built: `Apply` returns once, a push waits for exactly one answer per tunnel, and
  a sandbox that learns its workload died has nothing to call. `deno.Sandbox.Done` and
  `.Exited` are what a caller in the same process gets instead, and watching is all they are.

## Deno as the enforcer

E3 ran the same task as a Deno script — `deno 2.9.6` (stable, x86_64-unknown-linux-gnu, v8
15.0.245.2-rusty, typescript 6.0.3), installed user-locally at `~/.deno/bin/deno` — under
permission flags derived from nothing but E1's table:

```
--allow-net=api.anthropic.com:443,www.rfc-editor.org:443 \
--allow-write=./summary.txt \
--allow-env=ANTHROPIC_API_KEY
```

**Not one flag had to be added.** Two rules hold for every command: always `deno run` and never
`deno eval`, which ignores permission flags entirely; and always `--no-prompt`, so a missing
capability is an immediate `NotCapable` rather than an interactive hang. Deno costs nothing
measurable — three runs at 14 963/537 `$0.035296`, 15 128/701 `$0.037266` and 14 983/556
`$0.035526`, against E1's $0.0352–$0.0357 direct and E2's $0.0360–$0.0366 behind the contract.

E1's list row by row, `docs/snp/evidence/ticket23/spikes/E3/table.md` verbatim. `express` is the
flag that says this row and nothing wider; `unpoliced` means the resource is still used and
Deno's permission model never sees it — the capability query says `prompt` and the syscall
happens anyway; `absent` means Deno does not touch the row at all.

| E1 row | Deno | the flag, or what happens instead |
| --- | --- | --- |
| `104.18.20.81:443` (www.rfc-editor.org) | **express** | `--allow-net=www.rfc-editor.org:443`. The check is against the **name** in the URL, before resolution, so the address never enters it — which is why a CDN's two A records cost nothing here and cost everything to a CIDR. |
| `160.79.104.10:443` (api.anthropic.com) | **express** | `--allow-net=api.anthropic.com:443`. |
| `127.0.0.53:53` (the resolver, UDP) | **unpoliced** | `fetch` resolves inside Rust and glibc; the query `net 127.0.0.53:53` is `prompt` on a run whose fetches all succeed. The same address through `Deno.connect` **is** checked (`NotCapable: Requires net access to "127.0.0.53:53"`), so the resolver is unpoliced exactly when it is the runtime's and policed when it is the script's. |
| `104.18.20.81:0`, `104.18.21.81:0`, `160.79.104.10:0` (source-address selection, UDP) | **unpoliced** | glibc's, inside `getaddrinfo`; present in Deno's strace exactly as in Go's. |
| `2606:4700::6812:1451:0`, `…:1551:0`, `2607:6bc0::10:0` (AAAA, ENETUNREACH) | **unpoliced** | same. |
| `netlink:RTM_GETADDR` | **unpoliced** | same. Deno has no netlink capability at all. |
| `unix:/var/run/nscd/socket` (ENOENT) | **unpoliced** | two `connect` calls a run, as in E1. `--allow-net` does not cover AF_UNIX, and there is no flag for this socket. |
| binary `./agent` (`execve`) | **cannot** | the binary is now `deno` itself, and Deno does not police its own exec. `--allow-run` governs children only; `X` for the agent process is whoever started `deno`. |
| `/etc/gai.conf`, `/etc/host.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/resolv.conf` | **unpoliced** | Deno opens all five (`run-strace.raw`); `read /etc/resolv.conf` and `read /etc/nsswitch.conf` both query `prompt` on the same run. |
| `/etc/ld.so.cache`, `/etc/ld.so.preload`, `/lib/x86_64-linux-gnu/libc.so.6` | **unpoliced** | the dynamic loader's, before any Deno code runs. Deno adds `libm`, `libdl`, `libgcc_s`, `libpthread`, `librt`. |
| `/etc/pki/tls/certs` (ENOENT), `/etc/ssl/certs`, `/etc/ssl/certs/ca-certificates.crt`, the 122-openat `*.pem` walk, the 244 `readlinkat` hashed-symlink walk | **absent** | **zero** cert files opened on a straced run that completed three TLS handshakes. Deno's roots are compiled into the binary, so the whole trust-store half of `F` disappears — and with it any way to say *which* roots this agent trusts. `read /etc/ssl/certs` queries `prompt` throughout. |
| `summary.txt` (`openat O_WRONLY\|O_CREAT\|O_TRUNC`) | **express** | `--allow-write=./summary.txt`. Exact path, resolved against the cwd at process start, and it works for a file that does not exist yet. A sibling (`./other.txt`) and an absolute elsewhere are both refused. |
| `/proc/*`, `/sys/*` (the Go runtime's maps, cgroup, hugepage, cpu.max) | **unpoliced** | Deno's equivalents: `/proc/self/maps`, `/proc/self/cgroup`, four `cpu.max` up the cgroup tree, `/proc/meminfo`, `/proc/sys/kernel/osrelease`, `/sys/devices/system/cpu/online`, `tsc_freq_khz`, six `/dev/urandom`. |
| — (not in E1) | **unpoliced** | **33** probes for `deno.json`, `deno.jsonc` and `package.json`, one triple per directory from the script's own up to `/`, plus `~/.npmrc`. Deno reads above the working directory as a matter of startup, and no `--allow-read` is involved. |
| — (not in E1) | **unpoliced** | `~/.cache/deno`: 11 opens — three SQLite databases (`dep_analysis_cache_v2`, `node_analysis_cache_v2`, `v8_code_cache_v2`) with their `-wal` and `-shm`, `latest.txt`, and the transpiled `gen/…/agent.ts.js`. These are **written** on every run under a flag set whose only write grant is `./summary.txt`. |
| — (not in E1) | **express** | `ANTHROPIC_API_KEY` is `--allow-env=ANTHROPIC_API_KEY`. E1 never listed it because `environ` is not a syscall; Deno makes the key a named resource, which is the one thing its model has that `(N, F, X)` has not. |

Three rows expressible, one that cannot be expressed at all, the trust store absent, thirteen
unpoliced, and two unpoliced rows Deno adds that E1 never saw.

**The exact sentences.** A CIDR parses, is a real mask, matches addresses correctly, and still
never meets the thing the agent names — `--allow-net=0.0.0.0/0:443` refuses
`www.rfc-editor.org:443` with `NotCapable: Requires net access to "www.rfc-editor.org:443", run
again with the --allow-net flag`, the same sentence as granting nothing, and so do
`--allow-net=0.0.0.0/0` and `--allow-net=:443`. An address grant is the same story from the
other side: under `--allow-net=160.79.104.10:443`, api's only A record, a fetch of
`https://api.anthropic.com/v1/messages` is refused with `NotCapable: Requires net access to
"api.anthropic.com:443", …`, and the same grant with the URL written as
`https://160.79.104.10/v1/messages` is **permitted** and then fails one layer down:
`TypeError: fetch failed`, `cause 1: Error: error sending request for url
(https://160.79.104.10/v1/messages): client error (Connect): received fatal alert:
HandshakeFailure`. A policy written in addresses does not merely fail to match, it fails where
nothing is a policy decision any more. A denied tool destination arrives in the transcript as
`fetch_url: NotCapable: Requires net access to "www.rfc-editor.org:443", run again with the
--allow-net flag`. A malformed host does not fail at run time at all: `--allow-net=nonsense///`
is `error: invalid host 'nonsense///': invalid char found in FQDN`, exit 1 before any code runs.
Two further spellings worth having in the record: a bare name grants **every** port, and
`--allow-net=www.rfc-editor.org:80` refuses 443.

**`--allow-run` matches by the literal spelling of the path and by nothing else.**
`--allow-run=/bin/true` permits `/bin/true --whatever -x 'rm -rf /'` — **arguments are not part
of the grant at all** — refuses `/bin/false`, refuses the PATH lookup `true`, and refuses
`/bin/true` when the grant reads `/usr/bin/true` although `/bin` is a symlink to `/usr/bin` and
the two are the same file: the match is on the string, not on the resolved path or the inode.
There is no digest: `--allow-run=sha256:f0b6a7b0c0d0` **fails open** into a grant that matches
nothing, with `Info Failed to resolve 'sha256:f0b6a7b0c0d0' for allow-run: cannot find binary
path` and a process that runs anyway, and `--allow-run=/bin/true@sha256:f0b6a7b0` makes the
suffix part of the name. And one granted `/bin/sh` is every command on the machine:
`--allow-run=/bin/sh` with `-c 'echo anything at all; id -un'` is `OK code=0`.

**Two things `(N, F, X)` had no letter for.** The first is the **environment**: the key is
`--allow-env=ANTHROPIC_API_KEY`, a capability by variable name, and it is the one thing on this
list that is unambiguously the delegator's to grant — the agent exits at line one without it.
The second surfaced only at two hops: the **delegation channel** itself. Carrying a real request
into the workload needs either a socket the script connects to, which needs a net grant, or two
files, which need `f` grants; only the arrangement in which the request is not carried at all
avoids paying for it (below). The one shape change the document needed before anything would run
is `n.host`: an entry has to carry the name, because the only enforcer in this study checks the
name before resolution.

**And a denied resource is not a failed task.** E3's negative run, with
`--allow-net=api.anthropic.com:443` and nothing else, did not crash: `fetch` threw `NotCapable`,
the tool caught it exactly as E1's Go tool catches a dial error, and it went back to the model as
a `tool_result` with `is_error: true`. The model did not retry and did not report failure — it
wrote a five-sentence summary of RFC 8446 from what it already knew, called `write_file`, said
DONE and exited 0, with `summary.txt` at 1106 bytes, indistinguishable in shape from the three
written after a real fetch. **Only the token count differs: 14 963 input tokens on the granted
run against 2 868 on the denied one**, because the 20 KB of RFC 8446 never entered the
conversation. E3's run at least appended a closing note that the document had not been fetched;
in both E4 passes and in both two-hop passes the final text was the bare word `DONE` with no
mention of the restriction at all. Whatever is watching a delegated agent has to read the tool
errors, not the outcome.

## The Deno sandbox as built

`attest/sandbox/deno` is E4's throwaway adapter promoted: a `sandbox.Sandbox` whose `Apply` is a
Deno 2.9.6 process under permission flags, the second implementation of the contract and the
first that enforces anything. It is a study instrument and not a plan — what it cannot express
is the input to the gVisor tickets, and the package's job is to be exact about which half is
which. `Open` and `Accept` are one-line pass-throughs to the `Network` behind it, on purpose: a
sandbox that filtered streams as well would be enforcing the same rule in two places that could
disagree.

**Atoms, not flag strings.** A policy becomes a sorted, deduplicated capability set —
`net:<host>:<port>`, `net:<host>`, `read:<path>`, `write:<path>`, `run:<path>`, `env:<NAME>` —
and the set is what a widening is judged on, so `--allow-net=a,b` and `--allow-net=b,a` are two
strings and one policy. The grammar is ticket 22's `n`, `f` and `x` with an `e` beside them, all
four unknown fields of a version 1 envelope, which is what the contract says a policy is; this
ticket does not define a `P`.

**Four things are refused at `Apply`, before the exec**, each because mapping it would grant
something the document did not say: an `n` entry with a `cidr` and no `host` (a name is in no
CIDR, so the entry grants exactly the destinations an agent never names — an entry carrying both
is read by its host); a host with a character Deno's FQDN parser refuses (`nonsense///` kills the
process at startup, which in E4 happened 43 ms *after* the ack, the one moment the package
cannot take back); an `x` entry with a `sha256` (Deno has nowhere to put a digest, and applying
the path alone would grant any binary that turns up at it); and any value with a comma in it,
because the flags are comma-separated lists and a comma is a second grant nobody wrote. A body
it cannot decode is refused too, and the split with tunneld is exactly where `policy.go` puts
it: tunneld owns "is this addressed to me", the sandbox owns "can I do this".

**The settle narrows E4's gap and does not close it.** `Apply` does not return until the process
has survived `Config.Settle`, `DefaultSettle` 50 ms, chosen against the 36–43 ms Deno took to
die on a flag its own parser rejects; the wait ends early when the process ends, so a larger one
is paid for only by a run that fails, and a process that dies inside it is a refusal carrying
its first line of stderr. A workload that dies a minute later is still a tunnel asserting
something this sandbox no longer believes, and the contract has no verb for saying so.
`Sandbox.Done` and `Sandbox.Exited` are what a caller in the same process gets instead.

**A widening push is refused** — the first `Apply` fixes the set, a later one whose atoms are not
a subset is `sandbox.ErrPolicyRefused` naming what widened, and the running process is untouched.
**A narrowing push restarts and loses the workload**: the flags are fixed at `exec`, so a second
policy is a second process, the running agent is killed mid-conversation, its message history
goes with it, and the replacement starts the task from turn one in the same working directory
over the same `summary.txt`. The package does that rather than refusing, because the contract
says a sandbox applies a policy its delegator narrowed to and has no way to answer "I am busy".
**The environment is built, not filtered**: the child gets exactly the variables `e` names,
copied from this process's, plus `PATH` and `HOME` which Deno itself needs. E4's adapter passed
`os.Environ()` and let `--allow-env` decide what the script could read, which put the API key in
the child's environ under every policy and made the flag a read gate on a secret the sandbox had
already handed over. A grant that names a variable has to be the reason the variable is there.

| what it asserts | test in `attest/sandbox/deno` |
| --- | --- |
| a policy becomes the flags Deno is started with | `TestAPolicyBecomesTheFlagsDenoIsStartedWith` |
| a CIDR is refused because Deno matches the name an agent asks | `TestACIDRIsRefusedBecauseDenoMatchesTheNameAnAgentAsks` |
| an `x` entry with a digest is refused because Deno has nowhere to put it | `TestAnExecEntryWithADigestIsRefusedBecauseDenoHasNowhereToPutIt` |
| a host Deno would reject at startup is refused before the exec | `TestAHostDenoWouldRejectAtStartupIsRefusedBeforeTheExec` |
| a body this sandbox cannot read is refused although the envelope is fine | `TestABodyThisSandboxCannotReadIsRefusedAlthoughTheEnvelopeIsFine` |
| a widening second policy is refused and the running process is untouched | `TestAWideningSecondPolicyIsRefusedAndTheRunningProcessIsUntouched` |
| a narrowing second policy restarts the process and loses the workload | `TestANarrowingSecondPolicyRestartsTheProcessAndLosesTheWorkload` |
| the same atoms in a different order are not a widening | `TestTheSameAtomsInADifferentOrderAreNotAWidening` |
| a process that dies during the settle is a refusal carrying what it said | `TestAProcessThatDiesDuringTheSettleIsARefusalCarryingWhatItSaid` |
| `Open` and `Accept` pass through to the network untouched | `TestOpenAndAcceptPassThroughToTheNetworkUntouched` |
| the package reaches no evidence, no key and no trust decision | `TestThePackageImportsOnlyTheStandardLibraryAndTheContract` |

Every one of them runs against a fake Deno binary, so the package's tests need no runtime and no
key; the live Deno is exercised by the two hops.

## Two hops

The ticket's last item, live, on the promoted pieces and with nothing copied in to run: the loop
in `attest/cmd/agent-probe`, the sandbox in `attest/sandbox/deno`, the push in `attest/tunneld`.
The harness is `attest/cmd/agent-probe/twohops_test.go`, `-run TestTwoHops`, skipped unless
`AGENT_PROBE_LIVE=1` and `AGENT_PROBE_DENO` names a Deno that exists. Two passes, both PASS in
24 s, Deno 2.9.6 at `~/.deno/bin/deno`, the model `claude-sonnet-5`, the task byte-identical to
every spike's.

```
  root                         a                              b
  ───────────                  ────────────                   ─────────────────────────
  tunneld                      tunneld                        tunneld
  PushPolicy = P0  ──push──▶   sandbox.Null                   sandbox/deno
                               (records P0, enforces nothing)  Apply = exec deno run --no-prompt
                                                                      --allow-net=… --allow-write=…
  Null.Open("a") ──"GO\n"──▶   agent-probe's loop                     --allow-env=ANTHROPIC_API_KEY
                               task=delegate, one tool
                               PushPolicy = P1  ──push──▶      Apply → the Deno agent starts HERE
                               delegate: Open("b"), "RUN\n"
                               ◀── the far transcript ──       one goroutine accepts the stream,
  ◀── a's final text ──        as a tool_result                 waits for Done(), answers with the
                                                                transcript and the exit status
                                                               b ── the agent's own fetches ──▶ net
```

**Deno is the only enforcer in the picture.** Neither tunneld filters a stream and a's sandbox
enforces nothing at all. Three tools at most, as the ticket requires: the agent on **a** is
offered exactly one, `delegate`, so the only thing it can reach is the peer its task names; the
agent on **b** is offered `fetch_url` and `write_file`. "A's agent asks for B" is a model
decision — the prompt names the peer, the model chooses to call the tool.

**Case (i), `P1 = P0`, and it is enough.** `⊑` is not `⊏`; equal sets are applied, and using the
same document on both hops leaves case (ii) as the only case in which `P1` is strictly narrower,
which is the variable being measured. b's Deno was started with
`--allow-net=api.anthropic.com:443,www.rfc-editor.org:443 --allow-write=./summary.txt
--allow-env=ANTHROPIC_API_KEY`, the task completed — fetch, write, `DONE`, exit 0 — and the
transcript travelled back over the stream as a tool result with `is_error=false`, which a's
model repeated to root. The same digest arrives on both hops, `sha256=857adfb9…`, which is what
"the same document" means on two consoles.

**Case (ii), `P1` without `www.rfc-editor.org:443`.** Deno denied the tool's destination
(`NotCapable`), `agent.ts` marked it `TOOL_ERROR`, the model was told, and the model worked
around it and said `DONE` anyway. At **a** it arrives as a failed tool call and as nothing else:
`tool_use delegate {"peer":"b"} -> 1370 bytes, is_error=true`, while `Open("b")` returned `nil`,
a's tunneld logged no refusal, b's tunneld logged no refusal, and nothing in a's view or root's
carries `PolicyNotApplied` or any other reason from the taxonomy. The denial is a tool error,
exactly as the ticket asks. What root read is four bytes: a's model, told to reply with the far
transcript "verbatim, and nothing else", answered with the far side's last word, `DONE`.

**Case (iii), a second pusher widens while b's workload is running.** `P2` is `P0` plus
`{"host":"example.com","ports":[443]}`, and it cannot be a's second push — a push is once per
tunnel — so the widening comes from a second tunneld on a second tunnel, which is E4's finding
repeated on the promoted package. It is refused: `sandbox: policy refused: it widens
[env:ANTHROPIC_API_KEY net:api.anthropic.com:443 net:www.rfc-editor.org:443 write:./summary.txt]
by [net:example.com:443]`, `Open` at the widening pusher is `ReasonPolicyNotApplied`, the detail
stays on b's console and never crosses the wire, and the running workload is untouched: `Done`
is not closed, the pid is the one the first push started, and the sandbox started exactly one
process in its life.

### The timings per hop

Each hop's **cold tunnel** is measured at the dialer around `Open` and contains the dial, both
sides judging the other's evidence, the push and the acknowledgement. **push+ack** is measured
at the pushed side, from entry to `Apply` to its return. **First tool call** is stamped by the
far agent itself, milliseconds from the start of its runtime; **agent end to end** is that
agent's own wall time.

| case (i) | run 1 | run 2 |
| --- | --- | --- |
| root→a cold tunnel | 46 ms | 46 ms |
| root→a push+ack at a (`Null.Apply`) | **88 µs** | **78 µs** |
| a→b cold tunnel | 100 ms | 92 ms |
| a→b push+ack at b (`deno.Apply`: parse, subset test, exec, 50 ms settle) | **53.005 ms** | **53.594 ms** |
| b: process start → first tool call | 1 495 ms | 1 498 ms |
| b: the agent, end to end | 6.707 s | 6.826 s |
| root → answer, total | 12.272 s | 12.21 s |

| case (ii) | run 1 | run 2 |
| --- | --- | --- |
| root→a cold tunnel | 43 ms | 43 ms |
| root→a push+ack at a | 88 µs | 95 µs |
| a→b cold tunnel | 103 ms | 84 ms |
| a→b push+ack at b | 51.979 ms | 51.627 ms |
| b: process start → first tool call | 1 523 ms | 1 416 ms |
| b: the agent, end to end | 8.692 s | 8.694 s |
| root → answer, total | 10.806 s | 10.706 s |

| case (iii) | run 1 | run 2 |
| --- | --- | --- |
| `Apply` at b, refusing the widening | 179 µs | 153 µs |
| `Open` at the second pusher, refused | 42 ms | 33 ms |

The shape to keep: **the second hop's cold tunnel is the first hop's plus the workload's `exec`
and its settle.** 46 ms against 100 ms, and the 53 ms between them is `Apply` — of which 50 ms
is the settle, so the exec itself is the ~3 ms E4 measured as ~2 ms without one. Everything the
Deno runtime spends afterwards, ~1.5 s to the first tool call, is after the acknowledgement and
outside the push entirely.

### Tokens and cost

`claude-sonnet-5`, $2.00/M input and $10.00/M output, as the loop prices it.

| | run 1 in / out | run 1 cost | run 2 in / out | run 2 cost |
| --- | --- | --- | --- | --- |
| (i) a — 2 requests, one `delegate` | 1 654 / 644 | $0.009748 | 1 661 / 656 | $0.009882 |
| (i) b — 3 requests, `fetch_url` + `write_file` | 14 929 / 515 | $0.035008 | 14 969 / 542 | $0.035358 |
| (ii) a — 2 requests, one `delegate` | 1 737 / 97 | $0.004444 | 1 693 / 53 | $0.003916 |
| (ii) b — 3 requests, the fetch denied | 2 851 / 684 | $0.012542 | 2 780 / 612 | $0.011680 |
| **the run** | | **$0.061742** | | **$0.060836** |

Case (iii) costs nothing of its own: it rides on case (i)'s workload. Case (ii)'s b is cheap for
the one reason that matters — the 20 KB of RFC 8446 never entered the conversation — which is
where the denial is visible in numbers even when it is not visible in the exit status.

### Is "apply then ack" enough when apply starts a process?

**No**, and E4 named the three reasons in the order they cost something.

1. **The ack is a claim about the past.** `Apply` can truthfully say the process started and can
   say nothing about whether it is still running. E4 case (iv): the ack left `Apply` 1.856 ms
   after `exec.Start`, the process was dead at 43 ms — 41 ms after that ack, thirty-five in run
   2 — and A's tunnel stayed up, holding a perfectly good connection to a sandbox with nothing
   in it, and only found out because it asked. Every failure mode of a process lands after the
   only moment the contract has for saying no.
2. **There is no way to re-ack and no way to un-ack.** `Sandbox.Apply` returns once, `push.go`
   waits for exactly one answer per tunnel and then never looks again, and a sandbox that learns
   its process died has nothing to call: no revocation verb, no event, no second exchange.
3. **The flags are fixed at `exec`, so a second policy is a restart.** Nothing in `Apply`'s
   signature distinguishes "I have adopted this policy" from "I have destroyed the workload you
   were talking to and started a new one under it", so a delegator that narrows mid-task
   silently discards the task.

The shape of what is missing is the same in all three: `Apply` is a request/response and the
thing it applies to has a **lifetime**. What is missing is **a liveness signal from sandbox to
tunneld**, so that a dead workload ends the tunnel the way a refused push does. The alternative
— an `Apply` that does not return until the workload is past the point where its flags can kill
it — is only a longer version of the same lie; `attest/sandbox/deno`'s 50 ms settle is exactly
that alternative, bought deliberately and small, and it narrows the window rather than closing
it.

### What the two hops left

1. **Nothing enforces `P1 ⊑ P0`.** a pushes the document it was configured with; no line on
   either side compares it with what root pushed at a, and `sandbox.Null` does not parse P0 at
   all. The containment here is two constants written to be contained. A leftover for the policy
   track.
2. **The workload starts at push time, not at request time.** `Apply` is `exec`, so the task
   begins when the policy lands, before any stream exists; the stream a opens carries only *give
   me the result*. A delegator that pushes and then decides not to ask has already paid for a
   run.
3. **The delegation channel is a resource `P` would have to grant.** Carrying a real request
   into the workload needs a socket (a net grant) or two files (`f` grants); only the
   arrangement in which the request is not carried at all avoids it, and that is the one used
   here.
4. **The model on b says `DONE` after a denied tool**, writes a summary from what it already
   knew and exits 0: `summary.txt` is 1 045 bytes in case (ii) against 1 009 in case (i), and
   the artifact, the exit status and the last word are all indistinguishable from a run that was
   not denied anything.
5. **a's model does not pass the tool error on.** Root read `DONE` in case (ii) in both runs.
   The `is_error: true` the contract delivered correctly to a stops at a's model, and root's
   view of a denied delegation is a four-byte answer. A delegator that wants to know has to be
   told by something other than the agent it delegated to.
6. **The peer name on an accepted stream is wrong on loopback.** `nameOf` matches the peer table
   on the address only, since an accepted connection comes from an ephemeral port; on loopback
   every peer is `127.0.0.1`, so a's single-entry table named **root's** stream `peer="b"`, and
   b, whose table is empty, saw `peer=""`. The measurement and the policy digest beside them are
   the identity; the name is decoration, and on one machine it is decoration that lies.
7. **a's own model requests do not go over the contract.** a reaches `api.anthropic.com`
   directly: what this measures is the delegation hop, and the model endpoint behind the
   contract is E2's measurement. An `a` whose own egress went through a tunnel would need an
   exit peer, which is a third hop and not this ticket's.

Two more are in the record and repeated above: `Attested.PolicyDigest` is still the peer's
*egress ceiling* and not the document it pushed, so nothing in what b is told about a says which
policy a pushed; and a widening refusal is still only reachable from a second pusher, because
one push per tunnel means a live tunnel has no second policy to refuse.

## Is `(N, F, X)` as typed enough for the policy track?

**No, in four places.** The provisional bytes ticket 22 left are `{format:"policy", version:1,
n:[{cidr, ports}], f:[{path, modes}], x:[{path|sha256}]}`. This ticket does not define `P`; what
it has is a measured agent, one enforcer that checks names and one that checks nothing, and each
of the four is a place where the shape and the measurement disagree.

**`N`: `{cidr, ports}` is the wrong type for an agent.** The agent names hosts. The CDN resolves
to two A records and two AAAAs and picks per run; the model endpoint resolved to one address
throughout this study, which is luck and not a guarantee. A CIDR grants exactly what the agent
never names — Deno parses the mask correctly, matches addresses against it correctly, and raises
every check against the name in the URL before resolution, so the two never meet. **`n` must
carry a name, `host:port`**, and two consequences come with it. The **resolver becomes an
implicit grant**: something has to turn the name into an address, and in E1 that was five
configuration files, an `nscd` socket, a netlink dump and a loopback datagram that no author
writing "this agent may reach the model" would think to write down. And the **name→address
binding becomes the enforcer's problem**: Deno checks the name pre-resolution and so is bound to
whatever the resolver returns, while an enforcer below the runtime sees addresses and would need
DNS pinning — the name it granted and the address it lets through have to be the same answer.
A CIDR, if it stays at all, is a second and weaker kind of entry for enforcers that see
addresses.

**`F`: the baseline is not writable as `f` entries.** The trust store is a directory walk of 122
to 124 `openat` and 244 `readlinkat`, and the resolver's five configuration files are the price
of the first TLS connection rather than of anything the agent does. Nobody writes those down.
Deno makes the point from the other side by compiling its roots in: on a run that completed
three TLS handshakes it opened **zero** cert files, so a policy listing `/etc/ssl/certs` would
describe a file the enforcer never opens, and an operator who wanted different roots could not
say so in `f` at all. Either the enforcer supplies the baseline and the policy may not name it,
or `F` needs a **"runtime baseline"** notion: a named set the policy can refer to and narrow,
distinct from the paths the workload's own task is about.

**`X`: `{path | sha256}` is enforceable only by a sandbox that controls exec.** A path is a
string match and not an identity — `/usr/bin/true` does not match `/bin/true` although `/bin` is
a symlink to `/usr/bin` and the file is the same file. Arguments are not part of it, which is
where the reach of an exec actually lives: one granted `/bin/sh` is every command on the
machine. And a digest has no enforcer below gVisor — Deno has nowhere to put one, and a grant it
cannot resolve is an `Info` line and a process that runs anyway, which is a failure open. The
form is not wrong so much as unenforceable by anything that is not the thing calling `execve`.

**A missing letter: `E`, the environment.** The agent exits at line one without
`ANTHROPIC_API_KEY`, and `(N, F, X)` cannot say `--allow-env=ANTHROPIC_API_KEY`. It is the one
resource on the whole list that is unambiguously the delegator's to grant, and it had to be
invented twice — once as E3's observation and once as a field E4 could not run without. The
letter also has to mean *constructed* and not *read-gated*: E4's throwaway put `os.Environ()` in
the child under every policy and let the flag decide what the script could read, which is the
failure the letter exists to prevent, and is why the promoted package builds the child's
environment from `e`.

**And one finding that is not a letter: liveness.** It belongs to the contract rather than to
`P`, and it is the reason "apply then ack" is not enough for any enforcer whose `Apply` starts a
process. Whatever `P` becomes, an acknowledgement of it is a statement with a lifetime.

**What did work, and should be kept: the widening rule over sets.** Comparing sorted,
deduplicated capability atoms rather than flag strings is what makes `--allow-net=a,b` and
`--allow-net=b,a` one policy, makes a narrowing and a reordering distinguishable, and makes the
refusal say *which* capability widened. It held across both spikes and both live two-hop runs
and cost 153–179 µs to decide.

## What gVisor must enforce that Deno could not

The input to the gVisor tickets. One line each, with one clause on whether gVisor plausibly can
— no design.

**The resolver and every socket that is not `fetch`'s.**

- `127.0.0.53:53` UDP, twice a run, the stub resolver on this box and whatever `/etc/resolv.conf`
  names on another — plausible: netstack sees every datagram, and the resolver is a destination
  like any other.
- The AF_UNIX `nscd` socket, `/var/run/nscd/socket`, two `connect` calls a run — plausible: a
  unix socket is a gofer path or a refused `connect`, both of which the sentry sees.
- Netlink `RTM_GETADDR`, which Deno has no capability for at all — plausible: netlink is a
  socket family the sentry implements rather than passes through.
- The `:0` source-address probes, six of E1's fourteen `connect()` calls, real addresses on port
  0 with no bytes — plausible, and the reason it matters is that a rule set matching on
  destination address alone will count them as contacts.
- The IPv6 attempts that got `ENETUNREACH` — plausible: whether an address family exists at all
  is netstack's answer to give.

**The process's own identity.**

- The `execve` of the runtime itself: Deno cannot express it, because `--allow-run` governs
  children and the process Deno is running in is not one — plausible, and the right form is a
  **measurement** rather than a flag, since the thing being identified is what the sandbox
  started.

**`--allow-run` semantics, done properly.**

- Identity by realpath or inode or digest instead of by the spelling of a path — plausible: the
  gofer resolves paths and knows what file it opened.
- The argument vector as part of the grant, because one granted `/bin/sh` is otherwise every
  command on the machine — plausible: the sentry sees `execve`'s arguments.

**The trust store as a baseline the policy can name.**

- The `/etc/ssl/certs` walk, which Deno makes disappear into its own binary — plausible: the
  gofer decides what is in the filesystem at all, so "these roots and no others" is a mount
  rather than a permission.

**The implicit filesystem.**

- `~/.cache/deno` written on every run under a flag set whose only write grant is one file —
  plausible: a write is a write to the gofer.
- The `deno.json` / `deno.jsonc` / `package.json` walk, 33 probes from the script's directory up
  to `/`, plus `~/.npmrc` — plausible, same reason, and it is reading *above* the working
  directory that no `--allow-read` was involved in.
- `/proc` and `/sys`, which both agents read and neither policy mentions — plausible: the
  sentry's own `/proc` is what a sandboxed process sees.

**The environment.**

- A constructed set rather than a read-gate over an inherited one, so that a secret is in the
  child because the policy named it — plausible: the sentry builds the initial process's
  environment.

**Destinations that are addresses rather than names.**

- Either address-level enforcement with DNS pinning, so the name granted and the address
  permitted are the same answer, or refusing IP-literal destinations outright — plausible:
  netstack sees both the DNS answer and the `connect`, which is exactly the pair Deno never has
  at once.

**Apply without restart.**

- A narrowing that reconfigures a netstack or a filter while the workload keeps running, instead
  of `exec` with new flags — plausible, and it is what makes "apply then ack" honest and a
  narrowing push something other than a state loss.

**Liveness.**

- The workload's exit visible to tunneld, so an acknowledged policy whose process died does not
  leave a tunnel asserting it — plausible: the sentry is the workload's parent and already knows.

**The delegation channel.**

- A channel that carries a request into the workload and is itself a resource the policy names,
  rather than an arrangement chosen to avoid needing a grant — plausible: it is a socket or a
  file, and both are things the sandbox creates.

**Enforcement that does not depend on the workload's runtime.**

- Deno enforces for TypeScript only, and a child started under `--allow-run` inherits none of it
  — plausible, and it is the single strongest argument for the kernel-level enforcer: the sentry
  sees every syscall of every descendant, whatever language it was written in.

## What proves it

| claim | where |
| --- | --- |
| the loop runs the tool calls the model asks for, in order, and prices the run | `TestTheLoopRunsTheToolCallsTheModelAsksForInOrderAndPricesTheRun` (`attest/cmd/agent-probe/agent_test.go`) |
| every tool result of one turn goes back in one user message | `TestEveryToolResultOfOneTurnGoesBackInOneUserMessage` |
| a refusal stops the loop with an error that names it | `TestARefusalStopsTheLoopWithAnErrorThatNamesIt` |
| a delegate result whose far transcript carries a tool error is an error at the delegating side | `TestADelegateResultWithAToolErrorInTheFarTranscriptIsAnError` |
| the whole loop runs through `Open` and the exit, and the destinations it named were checked against an allow list | `TestTheNullNetworkCarriesTheWholeLoopThroughOpenAndTheExit` (`attest/cmd/agent-probe/network_test.go`) |
| the exit refuses a destination the allow list does not name | `TestTheExitRefusesADestinationTheAllowListDoesNotName` |
| a read deadline set on the `net.Conn` adapter reaches the stream | `TestAReadDeadlineOnTheAdapterReachesTheStream` |
| a read deadline expires on both implementations of the contract — the tunnel's raw stream and the socketpair end a sandbox receives | `TestAReadDeadlineOnAStreamExpires` (`attest/tunneld/sandbox_test.go`) |
| the eleven claims about the Deno sandbox | the table in "The Deno sandbox as built" (`attest/sandbox/deno/deno_test.go`, `importgraph_test.go`) |
| two hops, live: the policy pushed on each, the task run under the far one, the denial visible at a as a tool error and as nothing else, and a widening refused while the workload runs | `TestTwoHops` (`attest/cmd/agent-probe/twohops_test.go`), `AGENT_PROBE_LIVE=1` and `AGENT_PROBE_DENO` set; recorded in `docs/snp/evidence/ticket23/twohops/{README.md,run1.log,run2.log}` |
| the promoted binary does the task against the live API, direct | `docs/snp/evidence/ticket23/agent-probe/run-direct.log`: 14 950 in / 523 out, $0.035130, 6.853 s, `proto=HTTP/2.0` |
| and behind the contract, with the exit resolving and dialing what the stream named | `run-null.log`: the same task over two `Open` calls at 12.383 ms and 13.317 ms, `EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443`, 14 970 in / 543 out, $0.035370, 6.467 s |
| the four spikes, with scripts and outputs | `docs/snp/evidence/ticket23/spikes/E1`–`E4` |

`go test ./... -count=1` in `attest/` passes, the two new packages in 0.096 s
(`cmd/agent-probe`) and 0.681 s (`sandbox/deno`); the live two-hop test is skipped in that run,
as it is anywhere without a key and a Deno.

`ripwire attest --quality-delta=ebbe8cba8..HEAD`:

```
<quality-delta baseline="ref-pair" regressions="52" minor="0" acked="7" stale="6"
preexisting-worse="0" new-symbol="52" gating="0" register-macro-excluded="0"
base_ref="ebbe8cba8e0f600fb5ba3db98e3f02cc610f9d19"
target_ref="743dfdc5d2493ee1694a9b2df107ac99898b760e" churn="unavailable" renames="0"
rename_window_commits="0" acked_by_rename="0" acked_by_content="0">
```

**`gating="0"` and `preexisting-worse="0"`**: nothing that existed at ticket 22's tip got worse.
All 52 regressions are `origin="new-symbol"` and are the debt of this ticket's own code — the
dead-code row every new test function and every new interface method produces, one duplication
group of four Deno refusal tests, and two verbosity rows in the live two-hop harness. The 7
acked rows are in `attest/.ripwire_quality_acks` with their reasons; nothing was acked for this
record.

## What is not built

- **No liveness verb.** The contract still has no way for a sandbox to say its workload died.
  `attest/sandbox/deno` narrows the window with a 50 ms settle and offers `Done` and `Exited` to
  a caller in the same process; neither crosses the contract, and a workload that dies a minute
  later leaves a tunnel asserting a policy nobody is under.
- **One policy for every peer.** `Config.PushPolicy` is one document, not a table keyed by peer
  name, exactly as ticket 22 left it. Both hops here push one document each.
- **Nothing enforces `P1 ⊑ P0`.** A delegate pushes the document it was configured with and no
  code compares it with the one pushed at the delegate. The containment in the two-hop record is
  two constants written to be contained; making it a rule belongs to the policy track.
- **The Deno agent never made a live call *from* `agent-probe` outside the two-hop test**, and
  that is fine: `deno/agent.ts` is started by `attest/sandbox/deno` and the binary's own live
  runs are the Go loop's, direct and behind the contract. The two are the same task, the same
  model id and the same arithmetic by construction, and the two-hop runs are where they meet.
- **`-network socket` was never run against a real tunneld.** The tunneld binary cannot serve on
  this workstation — there is no `/sys/kernel/config/tsm/report` to acquire evidence from — so
  every live measurement here is either direct, or over in-process tunnelds with the fake
  platform, or over the null network's local exit. A null run measures the contract's shape and
  not its cost.
- **Nothing on hardware.** No SEV-SNP guest, no TDX guest, no cloud. `docs/sandbox-contract.md`
  and `docs/policy-push.md` have the hardware runs of the contract and the push; the agent has
  none.
