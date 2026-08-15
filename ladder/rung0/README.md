# Rung 0 — Ambient authority

Status: implemented
Deck: agent-sandbox/deck.html, slides 5–7
Tag: rung-0   Flags: none (config only)   Verified on: runsc `789cde57375e-dirty`, Linux 6.8.0-1010-intel, 2026-08-15

Config only. There is no gVisor patch in this rung, and `git diff` touches nothing
outside `ladder/`.

## Enforcement claim

Under `config/rung0/`, the agent process cannot:

1. **Credentials** — read cloud or API credentials from its environment. No secrets in
   env vars, no `~/.aws`, no mounted service-account file.
   *Check:* ENFORCED `ch1 creds`. *Evidence:* `no credential env vars or files present`.
2. **Network, deny-by-default** — reach any host other than the egress proxy.
   *Check:* ENFORCED `ch2 network` (metadata endpoint, non-allowlisted host).
   *Evidence:* `ENETUNREACH(101) Network is unreachable`.
3. **Network, allowlist** — reach a non-allowlisted host even via the one channel it
   does have. *Check:* ENFORCED `ch2 network: non-allowlisted host via the proxy`.
   *Evidence:* `http_403 PROXY_DENY host=evil.example.com not in egress allowlist`.
4. **Filesystem** — write anywhere except `/scratch`. The root filesystem is read-only
   and no host path is visible beyond scratch and the broker socket.
   *Checks:* ENFORCED `ch3 fs` × 4. *Evidence:* `EROFS(30) Read-only file system` for
   the root mount, `EACCES(13)` for `/etc`, `ENOENT(2)` for the host path the baseline
   bind-mounts, and a host-side check that the sandbox's `/tmp` write reached no host
   path.
5. **Exec** — run the cloud CLI or a shell. *Checks:* ENFORCED `ch4 exec` × 2.
   *Evidence:* `ENOENT(2) No such file or directory`. See the honesty note below —
   this is the weakest of the five.

And it can still do exactly one useful thing: call the broker over its unix socket, and
GET the one allowlisted host. *Check:* CONTROL, all five assertions.

**The complete set of world-effects a rung-0 agent can cause:** the broker's three
tools (`read_metrics`, `read_wiki`, `write_config`), HTTP GET to `wiki.corp`, and
writes under `/scratch` — and nothing else.

## Problem

An agent's *possible* actions are its environment's permissions; its *needed* actions
are its task's requirements. The gap between them is latent blast radius, and no
attacker is required to fall into it — a hallucinated "helpful" action is enough. The
BASELINE column of the demo is not a strawman: credentials in env vars because the SDK
reads them there, a credentials file because someone's tooling wanted one, a writable
root because the base image expects it, and one flat network because that is what "put
it on the VPC" produces. Every one of the five probes succeeds there.

## Mechanism

Docker with `--runtime=runsc`, driven by `demo.sh`. The configuration *is* the
deliverable: `config/baseline/agent.args` and `config/rung0/agent.args` are one
docker-run argument per line, commented, and are the two columns of the table.

| Channel | Where enforced | How |
|---|---|---|
| 1 credentials | `config/rung0/agent.args` | by absence: no `--env` secrets, no credential bind-mount |
| 2 network (deny-by-default) | docker `--internal` network | agent alone with the proxy on `ladder-agent`; everything else is off-net |
| 2 network (allowlist) | `common/world/proxy.py`, outside the sandbox | dual-homed proxy, allowlist from `config/rung0/egress-allowlist.txt` |
| 3 filesystem | `--read-only` + two bind mounts | read-only root; only `/scratch` and `/broker` are host paths |
| 4 exec | `common/images/Dockerfile.agent-enforced` | the cloud CLI and the shells are deleted from the image |
| broker (the open door) | `--annotation dev.gvisor.flag.host-uds=open` | gVisor refuses host unix sockets by default |

Two mechanism notes worth keeping:

**`host-uds` is settable per-container without operator cooperation.** gVisor's default
is `--host-uds=none`, so the broker socket is invisible to the sandbox out of the box —
the spike showed `ECONNREFUSED` before the annotation and a served request after it.
`host-uds` sits on runsc's `overrideAllowlist` (`runsc/config/flags.go:213`), the set of
flags a container author may change through an OCI annotation *without* the operator
enabling `--allow-flag-override`. That is why the demo needs no root and no
`daemon.json` edit.

**The egress filter is outside the runtime because runsc exposes no knob for it — not
because the runtime cannot filter.** `--network` accepts only `sandbox|host|none|plugin`
(`runsc/config/config.go:734-746`), and no runsc flag takes a host, address, or CIDR.
But netstack contains a full iptables implementation whose OUTPUT hook runs on every
locally-generated packet (`pkg/tcpip/network/ipv4/ipv4.go:581`, IPv6 twin at
`pkg/tcpip/network/ipv6/ipv6.go:828`) and which matches on destination prefix
(`IPHeaderFilter.Dst`/`DstMask`, `pkg/tcpip/stack/iptables_types.go:199-204`). It simply
defaults to ACCEPT. runsc even installs rules into that stack at boot, before the
container's first process exists: `--reproduce-nat` scrapes a table from the container's
netns and ships it over an FD (`runsc/sandbox/network.go:679-696` →
`runsc/boot/network.go:576`). It scrapes only the `nat` table
(`runsc/sandbox/network_unsafe.go:69-70`), so it can express redirection but not a
deny-by-default allowlist.

Upstream's own guidance is to enforce exactly where rung 0 does: "Network policy
controls should be applied at the container level to ensure appropriate network policy
enforcement. Note that the sandbox itself is not capable of altering or configuring
these mechanisms" (`g3doc/architecture_guide/security.md:173-176`). Rung 0 follows that;
rung 2 revisits it, and inherits more machinery than this rung first assumed — see
"Open questions".

## Threat model delta

**Assumes:** the host, the docker daemon, the broker, and the proxy are trusted and
outside the sandbox. The agent is untrusted from the first instruction — the demo does
not model "the agent was fine until it was hijacked", because rung 0's claim does not
depend on when the agent went wrong.

**Does not defend against:** anything the broker's tools can do (a rung-0 agent that
calls `write_config` with garbage has caused real damage through a sanctioned door);
exfiltration *to* `wiki.corp`, which is allowlisted for reading and will accept a POST;
a gVisor sandbox escape; or the agent doing something harmful with the metrics it is
allowed to read. It also does not defend against the agent exec'ing what remains in the
image — see below.

**Honesty note on the exec channel.** The enforced image still contains a Python
interpreter, because the interpreter *is* the agent. Deleting `awsctl`, `curl`, `wget`,
and the shells removes the tools that reopen channels 1–3, which is containment, not
authorization: nothing in rung 0 stops the agent from exec'ing what is present, and an
agent that can run Python can do most of what a shell could. The `ENOENT` rows are real
but they are the weakest of the five, and a syscall-level exec policy is deliberately
not attempted here — that is a later rung's shape.

## Demo

```
./demo.sh                          # baseline under runsc, permissive config
./demo.sh --baseline-runtime=runc  # baseline under plain runc instead
./demo.sh --keep                   # leave the world up for poking at
```

**Root is not required.** Membership in the `docker` group is, plus a `runsc` runtime
registered with the daemon. Offline: no internet, no API keys, no cloud account — every
host the agent can see is a local container, including the metadata endpoint. Runtime
about 40 seconds after images are built.

Both baseline runtimes pass with 23 checks and exit 0; transcripts for both are in
`expected/`. The two agree on every row, which is the point of offering the switch: the
BASELINE→ENFORCED difference is the configuration, not the runtime.

**The metadata probe is honest.** `169.254.169.254` is a real listener — a container
pinned at that address on a docker network with subnet `169.254.0.0/16` — and the
BASELINE check shows the probe fetching a token from it. Without that, "blocked" and
"nothing was listening" would be indistinguishable and the ENFORCED row would prove
nothing. On a real cloud VM the same probe would hit the real IMDS; the difference
between "no route" (what this demo produces) and "unreachable link-local address" is
noted here because on a cloud host the enforcement would have to come from the host's
routing or firewall rather than from docker's network topology.

## Spec corrections

Where `rung-0-ambient-authority.md` and `00-conventions.md` were wrong about this tree
or this box:

1. **`runsc` offers no *flag* for host/CIDR filtering — but netstack can filter.** The
   spec said "assume it does not until you confirm otherwise", and the flag surface
   confirms it: `--network` takes only `sandbox|host|none|plugin`
   (`runsc/config/config.go:734-746`) and nothing in the flag set takes an address or
   prefix. That is *not* the same as "the runtime cannot filter", which an earlier draft
   of this README claimed on the strength of the flag surface alone. netstack's iptables
   is always live on the egress path and already matches on destination prefix; what is
   absent is a way to configure it. Corrected after a documentation audit — the original
   reading was taken from flag definitions without opening `g3doc/` or the packet path.
2. **The broker socket needs `--host-uds=open`**, which the spec did not mention.
   Default `none` makes a bind-mounted unix socket unusable from inside the sandbox and
   the failure reads as `ECONNREFUSED`, which looks like a dead broker rather than a
   policy denial.
3. **`--overlay` is gone; `--overlay2` replaced it** (default `root:self`). Neither was
   needed: docker's `--read-only` plus explicit bind mounts was sufficient, as the spec
   suspected it might be.
4. **`/tmp` stays writable under `--read-only`.** gVisor gives the sandbox an internal
   tmpfs at `/tmp`, so the claim has to be phrased "no *host* path is writable except
   scratch". The demo proves the bytes reach no host path instead of leaving it as a
   footnote.
5. **Docker's embedded DNS (127.0.0.11) does not work under runsc.** It depends on NAT
   rules in the container's network namespace, which netstack does not inherit; name
   resolution fails outright on a user-defined network. The demo uses `--add-host`
   entries, applied identically to both configs.
6. **`AF_UNIX` paths are capped at 108 bytes**, which the broker socket path can exceed
   if the runtime directory is nested. The broker refuses to start with a clear message
   rather than letting it look like a permissions problem.
7. **The installed `runsc` is not built from this checkout.** `runsc --version` reports
   `789cde57375e-dirty`, a revision that does not exist in this repository. Rung 0 is
   config-only so stock runsc is what the spec asked for, but rungs 1+ must build runsc
   from this tree and register it as a docker runtime before their flags can exist.
8. **The fork's git history is upstream gVisor's**, whose commit style is sentence-case
   subjects. Conventions §2's `ladder(rungN): <what>` is used anyway, since the ladder
   work is distinct from upstream's and the prefix keeps it greppable.

## Explicitly NOT enforced (the crack → rung 1)

Every allowlist here — the egress hosts, the mounts, the broker's tool table — is fixed
**per agent at deploy time**, and each is necessarily the *union* of everything that
agent's role might ever need. The sandbox is minimal relative to the **role**, never to
the **task**.

The demo shows this directly: the CONTROL task only needs `read_metrics`, and it runs in
a sandbox that will also hand it `read_wiki`, let it call the mutating `write_config`,
and let it GET `wiki.corp`. Nothing about the task narrowed anything. `config/rung0/`
would be byte-identical for an agent asked to do something else entirely.

That is rung 1's problem. Do not fix it here.

## Open questions

- The proxy allowlists by hostname, so an agent that connects to `wiki.corp`'s IP
  directly would bypass the name check — topology is what stops it today. If rung 2
  moves the filter inside the runtime, is the enforcement point an address or a name?
- **Rung 2 inherits most of an in-runtime egress filter.** A documentation audit of this
  claim turned up more than rung 0 assumed. The interception point exists
  (`CheckOutput`, `pkg/tcpip/network/ipv4/ipv4.go:581`); destination-prefix matching
  exists and is tested (`test/iptables/filter_output.go:30`); the boot-time delivery
  channel exists (`NATBlob` over an FD, `runsc/boot/network.go:194-196`); and the
  consumer already dispatches on the `filter` table as well as `nat`
  (`pkg/sentry/socket/netfilter/netfilter.go:195-197`), so it needs no change. The one
  blocker is on the runsc side: `writeNATBlob()` hardcodes the table name `"nat\x00"`
  (`runsc/sandbox/network_unsafe.go:69-70`). Two properties would make an in-runtime
  filter stronger than this rung's proxy: rules land before the container's PID 1 exists,
  and with the default `--net-raw=false` the workload cannot reach the setsockopt that
  would remove them (CAP_NET_RAW is stripped from the bounding set,
  `runsc/specutils/specutils.go:387`). Two cautions: do not build on
  `pkg/tcpip/nftables` in this revision — it is behind `--TESTONLY-nftables` and
  self-declared not thread-safe (`pkg/tcpip/nftables/nftables_types.go:59-60`) — and give
  any new flag added to `overrideAllowlist` a `check` func so a container author can only
  tighten it, the way `checkQDiscTBFRate` does (`runsc/config/flags.go:270-280`).
  `flagReproduceNFTables` is currently on that list with no check (`flags.go:215`).
- The proxy refuses `CONNECT`, so the demo is plaintext HTTP end to end. A real
  deployment needs TLS through this door, and then the allowlist either terminates TLS
  or degrades to SNI matching. Neither is a rung-0 question, but rung 3's attested
  labels will have to travel over whatever is chosen.
- `write_config` is a mutating tool with no argument validation. Rung 0 deliberately
  puts no policy in the broker, so "the enumerated set of world-effects" includes
  arbitrary key/value writes. Rung 1 has to decide whether task scope narrows the tool
  list, the arguments, or both.
