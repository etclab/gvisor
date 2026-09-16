# E3 — the same agent, behind Deno

**Question.** E1's agent again, this time as a Deno script, under permission
flags derived from nothing but E1's table. Which of E1's resources can Deno
express, which can it not, and does `--allow-net` take the `n` entries ticket
22 left behind — `{"cidr":"0.0.0.0/0","ports":[443]}` — as written?

**Answer, up front: the flag set derived from E1's table ran the task with
nothing added.** Not one flag had to be appended to make it work. What that
buys is less than it sounds, and the rest of this record is why: three of E1's
rows are expressible, a dozen are unpoliced, the trust store has vanished into
the binary, and a CIDR is accepted, is real, and still never matches the thing
the agent actually dials.

Nothing in the repository was changed by this spike. Everything it produced is
under this directory, and `attest/` is untouched.

---

## What ran

`agent.ts` here is E1's `agent.go`, ported: no import of any kind, no npm
package, plain `fetch` to `POST https://api.anthropic.com/v1/messages` with
`x-api-key` from `Deno.env.get`, `anthropic-version: 2023-06-01`, the same two
tools, the same manual loop, the same arithmetic.

| what | value |
| --- | --- |
| runtime | `deno 2.9.6` (stable, x86_64-unknown-linux-gnu), v8 15.0.245.2-rusty, typescript 6.0.3 — the pinned install, `~/.deno/bin/deno` |
| model id | `claude-sonnet-5` |
| `max_tokens` | 4096 |
| tools | `fetch_url(url)` — GET, body truncated at 20 KB; `write_file(path, content)` |
| loop | send; while `stop_reason == "tool_use"`, run every `tool_use` block and return every `tool_result` in one user message; stop on `end_turn`; print and stop on `refusal` or `max_tokens` |
| task | byte-identical to E1's `spikeTask`, fixed in the source |

The task, for the record:

> Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a
> summary of it in at most five sentences, and save the summary to the file
> summary.txt in the current directory using write_file. Then reply with the
> word DONE.

Two rules hold for every command below, both from the install record: it is
always `deno run` and never `deno eval`, which ignores permission flags
entirely; and always `--no-prompt`, so a missing capability is an immediate
`NotCapable` rather than an interactive hang.

The flag set, **derived only from E1's table** — the two destinations it
dialed, the one file it wrote, and the environment variable the key lives in:

```
--allow-net=api.anthropic.com:443,www.rfc-editor.org:443 \
--allow-write=./summary.txt \
--allow-env=ANTHROPIC_API_KEY
```

The commands — `run.sh` is the same thing as a script:

```
deno run --no-prompt $FLAGS agent.ts                                    > run{1,2,3}.log
deno run --no-prompt --allow-net=api.anthropic.com:443 \
         --allow-write=./summary.txt --allow-env=ANTHROPIC_API_KEY agent.ts > denied-fetch.log
strace -f -e trace=%network,%file,%process -s 256 deno run --no-prompt $FLAGS agent.ts
                                                       > run-strace.log, run-strace.raw
deno run --no-prompt <varying flags> probe-perms.ts    > probes-perms.log
deno run --no-prompt <varying flags> probe-net.ts URL  > probes-net.log, probes-net2.log
deno run --no-prompt <varying flags> probe-connect.ts HOST PORT > probes-net3.log
deno run --no-prompt <varying flags> probe-run.ts CMD ARGS…     > probes-run.log
deno run --no-prompt <varying flags> probe-write.ts PATH        > probes-fsx.log
```

`probe-net.ts` grew its `cause` printing after `probes-net.log` was taken;
`probes-net2.log` is the re-run of the two cases where the cause is the answer.

## The flag list: every flag that had to be added, and why

**None.** The list is empty and that is the finding. Each of the four questions
the ticket asks, answered on its own line:

- **Does Deno's `fetch` need `--allow-read` for the CA store?** No. `read
  /etc/ssl/certs` queries `prompt` on the run that completed three TLS
  handshakes, and the straced run opens **zero** files matching `pem`, `cert`
  or `ssl` — against E1's 122-to-124 `openat` plus 244 `readlinkat` for the
  same handshakes. Deno's roots are compiled into the binary.
- **Does it need net access to the resolver, `127.0.0.53:53`?** No, and it
  cannot have it in any meaningful sense: `net 127.0.0.53:53` queries `prompt`
  on a run whose every fetch succeeds. DNS for `fetch` is outside the
  permission model. It is *inside* it for `Deno.connect`, which refuses the
  same address with `NotCapable: Requires net access to "127.0.0.53:53"`.
- **Does `--allow-write=./summary.txt` work for a file that does not exist
  yet?** Yes. The grant is on the path, not on an inode, and the path is
  resolved against the working directory at process start (the same flag run
  from `./sub` writes `./sub/summary.txt`). `summary.txt` and `./summary.txt`
  are the same grant; `./other.txt` and `/tmp/…` are refused.
- **Does it need anything for the environment?** Yes, and this is the one
  resource Deno names that E1 could not: the key is `--allow-env=ANTHROPIC_API_KEY`,
  a capability by variable name. `env PATH` stays `prompt` under it.

## E1's list, row by row

In `table.md`. The shape of it: **three rows expressible** (the two
destinations by name, and `summary.txt`), **one that cannot be expressed at
all** (the agent's own binary — `--allow-run` governs children, and the process
Deno is running in is not one), **the whole trust store absent**, and
**thirteen rows unpoliced** — the resolver and its five configuration files,
the source-address-selection connects, netlink, the `nscd` socket, the loader,
`/proc` and `/sys`. Deno adds two unpoliced rows E1 never saw: a walk for
`deno.json`/`deno.jsonc`/`package.json` in every directory from the script's up
to `/` (33 probes), and reads **and writes** in `~/.cache/deno` under a flag
set whose only write grant is `./summary.txt`.

## `--allow-net` and the provisional `n` entry

Ticket 22's `n` is `{"cidr":"0.0.0.0/0","ports":[443]}`. Every spelling of it,
with the exact text:

| flag | parses? | `fetch https://www.rfc-editor.org/…` |
| --- | --- | --- |
| `--allow-net=0.0.0.0/0:443` | yes | `NotCapable: Requires net access to "www.rfc-editor.org:443", run again with the --allow-net flag` |
| `--allow-net=0.0.0.0/0` | yes | the same sentence |
| `--allow-net=:443` | yes | the same sentence |
| `--allow-net=160.79.104.10:443` (api's only A record), URL `https://api.anthropic.com/v1/messages` | yes | `NotCapable: Requires net access to "api.anthropic.com:443", run again with the --allow-net flag` |
| `--allow-net=160.79.104.10:443`, URL `https://160.79.104.10/v1/messages` | yes | **permitted** — and then `TypeError: fetch failed`, `cause 1: Error: error sending request for url (https://160.79.104.10/v1/messages): client error (Connect): received fatal alert: HandshakeFailure`. The permission passed; TLS refused a certificate that does not name the address. |
| `--allow-net=www.rfc-editor.org` (no port) | yes | `OK status=200 bytes=337736` — a bare name grants every port |
| `--allow-net=www.rfc-editor.org:80` | yes | `NotCapable: Requires net access to "www.rfc-editor.org:443", …` |
| `--allow-net=nonsense///` | **no** | `error: invalid host 'nonsense///': invalid char found in FQDN`, exit 1 before any code runs |

**A CIDR is not inert, and it is still useless here.** Under
`--allow-net=0.0.0.0/0:443`, `Deno.permissions.querySync({name:"net",
host:"160.79.104.10:443"})` is `granted` and so is `104.18.20.81:443`; under
the narrower `--allow-net=160.79.104.0/24:443` the first is `granted` and the
second is `prompt`. A raw `Deno.connect` to `160.79.104.10:443` under the
CIDR succeeds, and to port 80 is refused. So Deno parses the mask and matches
addresses against it correctly. What it will not do is resolve: every check
raised by `fetch` and by `Deno.connect({hostname:"api.anthropic.com"})` is
against the **name as written**, and a name is never in a CIDR. The provisional
`n` entry therefore grants exactly the destinations an agent never names.

`--allow-net=:443` is worse than useless: it parses, and grants nothing at all
— every row of the query, by name or by address, stays `prompt`.

## `--allow-run`

The ticket asks specifically, so: no third tool was added. `probe-run.ts` is
two lines of `Deno.Command`, and the answer is that `x` as `{path | sha256}`
maps to `--allow-run` **by the literal spelling of the path, and by nothing
else**.

| grant | command | result |
| --- | --- | --- |
| `--allow-run=/bin/true` | `/bin/true` | `OK code=0` |
| `--allow-run=/bin/true` | `/bin/true --whatever -x 'rm -rf /'` | `OK code=0` — **arguments are not part of the grant at all** |
| `--allow-run=/bin/true` | `/bin/false` | `NotCapable: Requires run access to "/bin/false", run again with the --allow-run flag` |
| `--allow-run=/bin/true` | `true` (a PATH lookup) | `NotCapable: Requires run access to "true", …` |
| `--allow-run=true` | `true` | `OK code=0` |
| `--allow-run=true` | `/bin/true` | `NotCapable: Requires run access to "/bin/true", …` |
| `--allow-run=/usr/bin/true` | `/bin/true` | `NotCapable: Requires run access to "/bin/true", …` — although `/bin` is a symlink to `/usr/bin` here and the two are the same file. The match is on the string, not on the resolved path or the inode. |
| `--allow-run=/bin/sh` | `/bin/sh -c 'echo anything at all; id -un'` | `OK code=0 stdout="anything at all\npniroula\n"` |
| `--allow-run=sha256:f0b6a7b0c0d0` | `/bin/true` | `Info Failed to resolve 'sha256:f0b6a7b0c0d0' for allow-run: cannot find binary path`, then `NotCapable: Requires run access to "/bin/true", …`. The run still starts: an unresolvable grant is a notice, not a refusal. |
| `--allow-run=/bin/true@sha256:f0b6a7b0` | `/bin/true` | `NotCapable: Requires run access to "/bin/true", …` — the suffix is part of the name, so the grant matches nothing |

So: **no digest, no realpath, no argument vector.** `{path}` maps; `{sha256}`
does not map to anything and fails open into a grant that matches nothing;
and one granted `/bin/sh` is every command on the machine, which is the whole
of `X`'s enforcement value on an agent that is allowed a shell.

## The negative: the model endpoint granted, the tool's destination not

`denied-fetch.log`, run with `--allow-net=api.anthropic.com:443` and nothing
else. **It did not crash.** The refusal arrives as a thrown `NotCapable` inside
`fetch_url`, the tool catches it exactly as E1's Go tool catches a dial error,
and it goes back to the model as a `tool_result` with `is_error: true`:

```
  tool_use fetch_url {"url":"https://www.rfc-editor.org/rfc/rfc8446.txt"} -> 107 bytes, is_error=true
    the model is told: fetch_url: NotCapable: Requires net access to "www.rfc-editor.org:443", run again with the --allow-net flag
```

**And then the model routed around it.** It did not retry, did not stop and did
not report failure to the caller: it wrote a five-sentence summary of RFC 8446
from what it already knew, called `write_file` with it, and said DONE — and
only in its closing text mentioned that the document had not been fetched:

> Note: I was unable to actually fetch the live document due to a network
> access restriction in this environment (missing `--allow-net` permission), so
> the summary above is based on my existing knowledge of RFC 8446 (TLS 1.3)
> rather than the freshly fetched text. The summary has been saved to
> summary.txt.

Exit status 0. `summary.txt` written, 1106 bytes, indistinguishable in shape
from the three that were written after a real fetch. This is the finding of E3
that has nothing to do with Deno: **a denied resource does not become a failed
task.** The sandbox stopped the byte from leaving and did not stop the side
effect, and a caller reading only the exit status and the file would see a
completed job. Whatever is watching a delegated agent has to read the tool
errors, not the outcome.

## The three runs

All three completed: `fetch_url`, then `write_file`, then DONE.
`summary-run1.txt` is what the first wrote.

| run | input tokens | output tokens | cost | wall (agent) | wall (`/usr/bin/time`) |
| --- | --- | --- | --- | --- | --- |
| 1 | 14 963 | 537 | $0.035296 | 7.190 s | 7.26 s |
| 2 | 15 128 | 701 | $0.037266 | 8.422 s | 8.51 s |
| 3 | 14 983 | 556 | $0.035526 | 7.108 s | 7.18 s |
| straced | 14 993 | 566 | $0.035646 | 7.213 s | — |
| the negative (`denied-fetch.log`) | 2 868 | 800 | $0.013736 | 10.055 s | — |

Three requests per run, priced at $2.00/M input and $10.00/M output for
`claude-sonnet-5`. About **$0.036 a run**, against E1's $0.0352–$0.0357 direct
and E2's $0.0360–$0.0366 behind the contract: **Deno costs nothing measurable**
on either tokens or wall time. The negative run is cheaper only because the
20 KB of RFC 8446 never entered the conversation, and slower because the model
wrote 800 output tokens instead of 550.

## Deno's own resource use, once, under strace

`run-strace.raw`, 375 lines, against E1's 668 for the same task. Noted, not
analysed.

| | Go agent (E1 run 3) | Deno agent (E3) |
| --- | --- | --- |
| `openat` | 146 | **90** (37 of them `ENOENT`) |
| `readlinkat` / `readlink` | 246 | **22** |
| `execve` | 1 | 1 |
| `clone3` | 22 | 8 |
| cert/pem opens | ~123 `openat` + ~244 `readlinkat` | **0** |
| `deno.json`/`package.json` probes | — | **33** |
| DENO_DIR (`~/.cache/deno`) | — | 11 opens, and the SQLite `-wal`/`-shm` files are **written** each run |

So the Deno binary opens *fewer* files than the Go agent did, and the reason is
the one that matters: the trust store is inside it. Everything it opens that Go
did not is startup — the configuration walk up to `/`, the module cache, a
handful of `/proc` and cgroup files. The network syscalls are the same set:
the same `nscd` `ENOENT`, the same `127.0.0.53:53`, the same port-0
source-address selection, the same IPv6 `ENETUNREACH`.

## What broke, and in what order

1. **Nothing, on the first try.** The flag set derived from E1's table ran the
   task to completion at the first attempt. No flag was added.
2. **The CIDR broke, at the first fetch.** `--allow-net=0.0.0.0/0:443`,
   ticket 22's `n` entry spelled as a Deno flag, refuses
   `www.rfc-editor.org:443` with the same sentence as granting nothing. It is a
   real mask over addresses and the check is over names, so the two never meet.
3. **`:443` broke silently, at the flag parser.** It parses, grants nothing,
   and says so nowhere — the only difference between it and no flag at all is
   in the exit code of the fetch that follows.
4. **An address grant broke at TLS, not at the permission.** `--allow-net` by
   IP does let an IP-literal URL through; the certificate then does not name
   the address, so the failure moves from `NotCapable` to `HandshakeFailure`.
   A policy written in addresses does not merely fail to match, it fails one
   layer further down where nothing is a policy decision any more.
5. **`--allow-run` broke as a binding.** It matched the spelling and not the
   file, took no digest, and put no constraint on the argument vector: one
   `/bin/sh` is everything.
6. **The trust store broke by disappearing.** Nothing under `/etc/ssl` is read,
   so `F` has nothing to say about which roots this agent trusts and no way to
   change them; that decision is now a property of the Deno binary, which is to
   say of `X`.
7. **The denial did not break the task.** The model was told `NotCapable`, did
   the job from memory, wrote the file and exited 0.

## What this says for `(N, F, X)`

- `n` cannot stay `{cidr, ports}`. The one thing an agent knows is a **name**,
  and the only enforcer in this study that can check one checks it before
  resolution. An `n` entry has to carry a host, and a CIDR — if it stays at all
  — is a second, weaker kind of entry for enforcers that see addresses.
- `f` has to survive an enforcer that has already answered half of it in its
  own binary. Deno needs no trust-store grant because it ships the roots; a
  policy that lists `/etc/ssl/certs` would be describing a file the enforcer
  never opens, and an operator who wanted different roots could not say so in
  `f` at all.
- `x` as `{path | sha256}` maps to Deno at half strength: the path maps, by
  spelling; the digest maps to nothing, and Deno accepts a grant it could not
  resolve with an `Info` line and runs anyway. Neither form constrains
  arguments, which is where the reach of an exec actually lives.
- There is a fourth letter. The key is an **environment** resource, and it is
  the one thing on this list that is unambiguously the delegator's to grant.
  `(N, F, X)` cannot say `--allow-env=ANTHROPIC_API_KEY`.
