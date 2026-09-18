# The adapter: an intercept in the sentry, a handoff to tunneld

Ticket 25. Ticket 24 put runsc inside the measurement and gave it a workload that printed a line
and exited; the guest's sandbox reached nothing, because `--network=none` is the boot ceiling. This
is the way through it: a table of host names given to the sentry at boot, a DNS responder inside
the sentry that turns those names into addresses that exist nowhere else, a `connect()` to one of
those addresses answered with a descriptor a helper on the host got from tunneld, and `ENETUNREACH`
plus a recorded event for everything else. The agent programs are not modified and do not know any
of it is there: on loopback the workload is `agent-probe -network plain`, which is
`&http.Client{}`, and on hardware it is busybox `wget`. **Tunneld is unchanged** — `git diff
ab26b518c..HEAD -- attest/tunneld attest/sandbox attest/ceiling attest/cmd/tunneld` is empty, so
the contract, the wire, the push and the ceiling are byte for byte what ticket 23 left. Four spikes
stand under it, under `docs/snp/evidence/ticket25/spikes/`: `E1` (the host strace study and its
in-sandbox half), `E2` (where a datagram arrives), `E3` (the urpc round trip), `E4` (Claude Code
headless, outside any sandbox). Work done 2026-09-18, base `ab26b518c`, 51 commits, tip
`a0b5a7c22`. Nothing merged, nothing pushed.

**In one sentence:** an FD-backed endpoint is enough for an unmodified Go and an unmodified Node —
the four calls it must answer are `getpeername`, `SO_ERROR`, a `getsockname` that differs from the
peer, and a `SHUT_WR` that actually reaches the peer — and the enforcement that matters is not at
`connect` at all but at the *resolver*, because a name that never becomes an address is a
destination a workload cannot even ask for; two SEV-SNP guests booted from one image, differing
only in a 64-byte JSON file on an unmeasured disk, each fetched the other's page through the
other's exit and were each refused the name in the other's table, `=== 52 passed, 0 failed ===`.

---

## The seam as built

**Four pieces, and the smallest of them is the one that decides anything.**

**The flag set.** `--tunnel-socket=PATH`, the AF_UNIX socket tunneld serves the sandbox contract
on, and `--tunnel-table=PATH`, the JSON document (`runsc/config/config.go:482,487`,
`runsc/config/flags.go:160-161`), refused unless they come together and unless `--network=none`
came with them (`config.go:518-523`). That is `config.Validate`, so it is `runsc run`'s own answer
before a sandbox exists: `tunnel-socket and tunnel-table require --network=none, got
--network=sandbox`, exit 128. Everything else in the guest's flag set is spike S1's, unchanged
(`docs/snp/image/init.rootfs:169-175`). The sentry holds a second copy of the ceiling and refuses
to install over a stack whose NICs are not all loopback (`tunnel.go:263-274`); it is unreachable
from the command line, because the first check already stopped it.

**The table** is `{"default_exit": PEER, "names": {NAME: {"port": N, "peer": PEER}}}`
(`pkg/sentry/socket/netstack/tunnel.go:76-87`). Keys are exact host names, folded to lower case and
stripped of a trailing dot; no wildcards and no addresses, `port` is the *one* TCP port that name
may be reached on, `peer` is the tunneld label whose exit dials it. `ParseTunnelTable` (`:91-123`)
refuses an unknown field, an empty table, an empty name, a `*` or `?`, a port outside 1–65535, an
entry with no peer and no default, and a duplicate once case is folded — at boot, because a table
that cannot be enforced should not become a sandbox that quietly reaches nothing.

**The helper** is `runsc tunnel-helper` (`runsc/cmd/tunnel_helper.go:54`), started beside the
sandbox by `Sandbox.startTunnelHelper` (`runsc/sandbox/sandbox.go:1914-2001`, from `:1061`) in
`maybeStartCheckpointGoferAndGetSocket`'s shape: one `socketpair`, the sentry's end donated as
`--tunnel-fd`, the child holding the other as fd 3. The table file is opened by runsc and donated
as `--tunnel-table-fd`, so the sentry reads the file runsc was pointed at rather than whatever the
path names later. The helper is a urpc **server** on fd 3 and a **client** of tunneld's socket: on
`TunnelHelper.Open` it asks tunneld for a stream to the peer, writes `CONNECT host:port\n`, reads
exactly one line and no byte more (`:249-266`; anything past the newline is the peer's first bytes
and it has nowhere to put them), and on `OK` hands the descriptor back (`:222-239`). It decides
nothing — the table was checked before the call arrived and the far end's list is ticket 23's. Its
one judgement is telling a refusal from an outage, because the sandbox gets a different errno for
each.

**The urpc object** is `boot.Tunnel` (`runsc/boot/tunnel.go:57`), registered on the existing
control server beside `debug` and `Network` (`runsc/boot/controller.go:250-252`), with
`Attach(*TunnelAttachArgs, *urpc.FilePayload)` at `:88`. Two callers reach one method: a supervisor
outside the sandbox over the control socket, and the sentry's own intercept in process through
`tunnelAttacher` (`:100-107`), a one-method interface (`netstack.TunnelAttacher`,
`tunnel.go:60-67`) so netstack gains no dependency on urpc. `Tunnel.permits` (`:170-191`) is
deliberately a second check: the intercept decides which of the sentry's own addresses a socket
asked for, and this decides whether the name, port and peer it ended up with are the ones the
operator wrote down. The table is read at `setupTunnel` (`:200`, from `loader.go:934-938`); the
adapter is installed at `installTunnel` (`:214`, from `loader.go:1285-1290`) only once the
sandbox's loopback NIC exists, because the ceiling check has nothing to look at before it.

**A finding, not a change: the helper re-implements the OPEN half of `attest/sandbox`'s local
socket protocol.** `runsc/cmd/tunnel_client.go` is 352 lines of what `attest/sandbox/client.go`
already is — a four-byte big-endian length, that many bytes of JSON, and for a stream reply one
descriptor in the ancillary data of the message carrying the length. It is written again rather
than imported because `attest/` is a separate Go module with no BUILD files and runsc is built by
bazel, so a runsc subcommand can carry nothing out of it (`tunnel_client.go:15-26`). Apply
callbacks from tunneld are logged and acknowledged and enforce nothing (`tunnel_helper.go:121-124`).

## The endpoint, and the four answers E1 said it had to give

**E1 asked whether an FD-backed endpoint can stand in for a TCP socket, and both halves answer that
it can.** E1a straced Go 1.26.3 and Node 18.19.1 / libuv 1.48.0 on the host with `strace -e
inject=` and measured what each tolerates being refused; E1b built the endpoint in the sentry and
ran both runtimes inside a `--network=none` sandbox against it. Four runs — {Go, Node} ×
{synchronous connect, `ErrConnectStarted`} — each completed a 256 KiB echo, a half-close and a TLS
1.3 HTTPS GET of the real `www.rfc-editor.org` with certificate validation, and **not one socket
call was refused**: the prototype logs a line whenever it answers `ErrUnknownProtocolOption` and
the count in every run's sentry log is zero. The ticket's alternative — a netstack loopback proxy
inside the sentry — is not needed.

| what the endpoint must do | why, from E1a | where |
|---|---|---|
| `getsockopt(SOL_SOCKET, SO_ERROR)` returns **0** | refusing it fails Go's dial with `getsockopt: protocol not available` (runs 10/11) and Node's with an uninitialised-stack garbage errno, `connect Unknown system error -28968` then `-31243` (runs 16/17), because libuv never checks the call's return value | `LastError` is nil, `tunnel_endpoint.go:579` |
| `getpeername` answers the AF_INET destination | Go's worst failure in the matrix: run 08 wedged inside `fd.pfd.WaitWrite()` for ever with no further syscall, the edge-triggered `EPOLLOUT` already spent. A hung workload, not an error | `GetRemoteAddress`, `:443` |
| `getsockname` answers an AF_INET address **differing from the peer's** | a refusal, an AF_UNIX answer or a local equal to the remote trips Go's `selfConnect` heuristic: run 07 closed the connection and dialled twice more — two wasted handoffs per dial | one port per connection from `nextLocal` (`tunnel.go:291-299`) over `100.64.0.1` (`:153`) |
| `shutdown(SHUT_WR)` reaches `shutdown(2)` | Node issues it on every `.end()`; run 18 shows refusing it raises no error and stalls the exchange until the client's own 5 s timeout, 6.05 s against ~1 s | `Shutdown`, `:382-422` |

Everything else may be refused and the refusal is never reached: Go's five post-connect `setsockopt`
calls are all discarded errors (run 09 completes with every one refused), libuv issues none, and
neither runtime ever issues an `ioctl` or an `fcntl` on the socket. The keepalives are remembered
anyway so Go's four look honoured (`:472-502`).

**`connect` returns success synchronously** (`tunnel.go:401-403`). Both modes pass, so this is not
correctness; it is the smaller contract. The handoff cost is paid inside `connect(2)` either way,
because the helper is asked *before* the endpoint is swapped in, so `ErrConnectStarted` does not
make the dial asynchronous — it changes the errno, costs three extra syscalls per connection, and
puts the dial on the one path that *depends* on `SO_ERROR` being answered zero (Go's zero-return
path skips `SO_ERROR` and the name lookups entirely, `net/fd_unix.go:50-60`, while libuv asks for
`SO_ERROR` either way). When `Helper.Open` becomes asynchronous, `ErrConnectStarted` is right and
the writable notification must fire after the dial and not before it.

**Two buffers are load-bearing, and the spike had to get both right to pass at all.** `rbuf`
(`tunnel_endpoint.go:94-97`): `Endpoint.Read` is handed an `io.Writer` with no declared capacity,
so a short user buffer would otherwise drop the rest of a 64 KiB host read. `wbuf` (`:98-101`):
`Endpoint.Write` takes ownership of what it reads from the `Payloader`, so bytes the descriptor
will not take cannot be handed back and the sandbox — which may be waiting for a reply and never
write again — would lose them; the backlog is drained from the notification path (`:157-171`),
which is the only place it can be. Two more came out of the review. **The half-close is deferred
behind the backlog**: a `SHUT_WR` issued while the tail of a request is still in `wbuf` would end
the stream in the middle of it, so it is remembered in `pendingShutWr` and issued by the flush path
once the backlog drains (`:102-108,398-410`). And **the endpoint swap happens under a lock**:
`sock.Endpoint` is read through `sock.ep()` under a leaf `RWMutex` (`netstack.go:442,486-493`) and
the adapter *claims* the socket before it asks the helper (`tunnel.go:408-419`), so a second
`connect(2)` is `EISCONN` or `EALREADY`, two racing threads produce one stream rather than two, and
neither is leaked.

## The resolver, and why the addresses are ones nothing else can be

**E2 found that the obvious intercept does not fire, and that is why there is a responder at all.**
An unconnected `sendto` does reach `sock.SendMsg` with its address parsed, for all four
destinations including the two that are unreachable. But glibc's resolver and Go's pure resolver
both `connect()` the UDP socket first and then `write(2)`, which lands in `sock.Write` with no
address at all — the address was given earlier, at `Connect`. A DNS intercept cannot live in
`SendMsg` alone. E2 then measured the cheaper alternative: a UDP endpoint bound inside the sentry
on the sandbox's own loopback stack at `127.0.0.53:53` is reachable by every client style tested,
needs no intercept, and returns whatever answer the adapter chooses — with the control in the same
run that the identical query to `127.0.0.1:53` still gets `ECONNREFUSED`, so the responder is
reached at exactly the address it binds. That is what is built (`tunnel_dns.go:45-51,78-91`), and
`nameserver 127.0.0.53` is what `/etc/resolv.conf` says in the loopback bundle, in the SNP workload
bundle (`snp/make-bundle.sh:57`) and on a stock Ubuntu workstation alike.

**The addresses come from `100.64.0.0/10` because it is the one block no real destination uses.**
RFC 6598 shared address space is not public, is not routed anywhere, and nothing inside a
`--network=none` sandbox can reach it any other way, so an address out of it arriving at
`sock.Connect` is always the adapter's and can never be masking a pre-existing success — E2's
baseline made into a property (`tunnel.go:142-147`). Names are sorted and allocated from
`100.64.1.0` upward (`:206-232,254-259`), sorted so one table produces the same addresses on every
boot and the evidence of one run can be read against another. The local address every attached
socket answers `getsockname` with is **`100.64.0.1`** (`:149-153`), deliberately *below* the first
name's address and so outside the range remotes are drawn from: it differs from every remote by
construction, which is E1a run 07's requirement discharged once rather than per connection. The
range holds 65,280 names and a larger table is refused at install.

**AAAA is answered NOERROR with no records, because of E4.** A shipped agent runtime looks every
name up `A` *and* `AAAA` and connects to the v6 address first, every time; on a v4-only sandbox
that is a guaranteed `ENETUNREACH` per connection, so the sentry has to answer something sane
rather than hang. NXDOMAIN would be wrong the other way — it denies the name itself and makes the A
query pointless — so the answer is "this name exists and has no v6 address"
(`tunnel_dns.go:172-177`). **A name the table does not carry is NXDOMAIN plus an event**
(`:154-159`), as is a query in another class or of a record type the responder has no opinion about
(`:178-182`). One line per query goes to the sentry's log (`:189-194`) and it has to, because
gVisor's `--strace` formats a `sendto` buffer as a pointer (`pkg/sentry/strace/linux64_amd64.go`)
so a query's payload never reaches the syscall log: that line is the only place the list of names a
workload asked for exists.

**One honest correction to the ticket's own wording.** It says "every other name fails immediately
with `ENETUNREACH`". As built it does not and cannot: a name is refused at the *resolver*, so what
the workload sees is a resolution failure, never an errno on a socket. `ENETUNREACH` is what an
address literal, a wrong port or a non-loopback datagram gets. Both halves are in one six-run check
(`adapter-check/notes.md:99-110`):

```
WRONG-PORT   error=dial tcp 100.64.1.1:80: connect: network is unreachable   errno=ENETUNREACH
UNKNOWN-NAME addrs=[] error=lookup example.com on 127.0.0.53:53: no such host
RAW-ADDRESS  error=dial tcp 8.8.8.8:443: connect: network is unreachable     errno=ENETUNREACH
UDP-CONNECT  error=dial udp 8.8.8.8:53: connect: network is unreachable      errno=ENETUNREACH
UDP-SENDTO   error=network is unreachable                                    errno=ENETUNREACH
```

The loopback control's words are `dial tcp: lookup api.anthropic.com on 127.0.0.53:53: no such
host`; the SNP controls are `wget: bad address 'web.peer-a'`. The effect the ticket wanted holds —
nothing leaves — but a reader grepping transcripts for `ENETUNREACH` will not find the name
refusals and should not expect to.

## The refusal, and the event it writes

**The errno is always `ENETUNREACH`, on purpose** (`tunnel.go:467-474`): it is what a
`--network=none` sandbox already answers for an address it has no route to, so a workload cannot
tell the adapter's refusal from the absence of a network. The far exit's own `REFUSED` is the one
exception — `ECONNREFUSED`, and **nothing recorded**, because that refusal is ticket 23's and is
recorded where the decision is made (`tunnel.go:381-387`, `runsc/boot/tunnel.go:155-166`). The
check confirms it with `refused.example`, which is in the table, resolves, and gets `dial tcp
100.64.1.0:443: connect: connection refused` with no `egress_refused` event anywhere in that run.

The event is a new trace point, `sentry/egress_refused` (`pkg/sentry/seccheck/metadata.go:343-346`),
carrying `context_data`, `protocol` (`tcp`, `udp` or `dns`), `address`, `port`, `name` and `reason`
(`seccheck/points/sentry.proto:192-218`), through the sink machinery that already exists
(`tunnel.go:505-532`, `seccheck/sinks/remote/remote.go:274-275`). Six reasons:

| reason | what it refused |
|---|---|
| `not-in-table` | an address the sentry never allocated: an IP literal, or a datagram to one |
| `wrong-port` | a name's address on a port that is not the one the table permits |
| `not-a-tcp-stream` | a name's address reached by a datagram or a non-`AF_INET` socket — no stream to hand |
| `unavailable` | the helper or tunneld could not produce a stream, or the endpoint would not start |
| `unknown-name` | a query for a name the table does not carry |
| `unknown-type` | a query in another class, or for a record type the responder has no opinion about |

**The receiver is part of the evidence and not part of the design**: a standalone Go program under
`docs/snp/evidence/ticket25/tools/seccheck-receiver/`, `examples/seccheck/server.cc` in Go,
decoding the eight-byte wire header and enough protobuf by hand to need nothing generated. The
loopback control is where it earns its place:

```
connected: the sentry speaks wire version 1
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T15:04:11.817556769Z
egress_refused protocol=dns name=api.anthropic.com reason=unknown-name time=2026-09-18T15:04:11.822416964Z
```

Two events for one name, because Go asks AAAA and A. **DNS refusals carry no `container_id` and no
`thread_id`**: the responder answers on its own goroutine and has no task to take them from, so it
records the time and the name and nothing it would have to invent (`tunnel.go:498-532`). The check
shows the other shape beside it — the TCP and UDP refusals carry both — and two UDP events for one
address, because a client can send a datagram both ways: the `connect(2)` one arrives at
`sock.Connect` and the `sendto(2)` one at `sock.SendMsg`, E2's finding 2 and the reason the adapter
hooks both (`netstack.go:855-861` and `:3451-3457`).

**Loopback inside the sandbox is left exactly as `--network=none` has it**, and that is not a hole:
`127/8`, `::1`, the unspecified address and v4-mapped forms of them are classified as not-egress
and passed through (`tunnel.go:306-332`). Nothing crosses the sandbox boundary on that path — the
stack has one NIC and it is `lo` — so there is nothing to refuse, and it is precisely what makes
the responder reachable at `127.0.0.53:53`. Every sandbox run in the check printed `LOOPBACK
echoed="ping\n" n=5 err=<nil>`.

## The loopback transcript

Two runsc sandboxes, one after the other. Two tunnelds `a` and `b` in the test's own process with
the fake SNP platform; ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — attached to
`b` with `-allow api.anthropic.com:443,www.rfc-editor.org:443`. The workload is
`attest/cmd/agent-probe` built `CGO_ENABLED=0` and run as `-network plain -task summarize`: net/http's
default transport, Go's own resolver, no contract and no dialer of its own. The bundle, the rootfs,
the binary, the tunnelds, the exit and its allow list are the same objects in both runs and **the
only thing that differs is the table** — the second leaves out `api.anthropic.com` — so the refusal
is attributable to the table and to nothing else. The harness is
`attest/cmd/agent-probe/adapter_test.go`, a test in the tree and not a file copied in to run.

| run | its table | runsc | wall | `tunnel_open` | `first_connect` | `first_byte` | `task_end` |
|---|---|---|---|---|---|---|---|
| workload | `api.anthropic.com:443`, `www.rfc-editor.org:443` | 0 | 9.867 s | 539 ms | 551 ms | 580 ms | 9.867 s |
| control | `www.rfc-editor.org:443` | 1 | 615 ms | never | never | never | 615 ms |
| workload, pre-review binary | same | 0 | 9.881 s | 518 ms | 531 ms | 553 ms | 9.881 s |
| control, pre-review binary | same | 1 | 624 ms | never | never | never | 624 ms |

All four are measured from the moment `runsc` started, and three are taken at the exit because that
is the only place the harness and the bytes meet. The agent completed its task: three requests,
`proto=HTTP/2.0` on each, `fetch_url` then `write_file`, **`final text: DONE`**, 14,933 in / 508
out, $0.034946, 9.332 s of its own wall time. What the exit saw is host, port and ciphertext, and
its last two lines are how it ends; beside it, the sentry's account of the same two connections:

```
EXIT dialed api.anthropic.com:443 -> 160.79.104.10:443    tunnel dns: q="api.anthropic.com" type=A answer=100.64.1.0
EXIT dialed www.rfc-editor.org:443 -> 104.18.20.81:443    tunnel dns: q="api.anthropic.com" type=AAAA answer=noerror-empty
EXIT www.rfc-editor.org:443 ended                         tunnel attach: api.anthropic.com:443 -> peer "b": ok in 61.434797ms, host fd 37, local 100.64.0.1:40001
EXIT api.anthropic.com:443 ended                          tunnel dns: q="www.rfc-editor.org" type=A answer=100.64.1.1
                                                          tunnel attach: www.rfc-editor.org:443 -> peer "b": ok in 39.03074ms, host fd 44, local 100.64.0.1:40002
```

**The control got no further than its first name**: four resolver lines, all NXDOMAIN, two events,
no stream at the exit, and `agent-probe: request 1: Post "https://api.anthropic.com/v1/messages":
dial tcp: lookup api.anthropic.com on 127.0.0.53:53: no such host` on stderr, in 615 ms.

**The key never goes to disk and the debug logs carry it anyway.** The bundle's `config.json` holds
`ANTHROPIC_API_KEY` in `process.env`, is written under a 0700 directory on `/dev/shm` and is
removed when the test ends; the rootfs the sandbox executes holds no secret. But the sentry writes
the container spec into its debug log, so the boot, gofer and run logs match every time — leftover
15, and each run's README names the files left behind.

## The SNP transcript

**One image, two SEV-SNP guests, one boot pair, through the job spool, both consoles captured:
`=== 52 passed, 0 failed ===`.** Two guests rather than one guest and the model API, because there
is no internet on the segment: the destination has to be something a guest can serve, so each guest
runs busybox `httpd` on its own `127.0.0.1:80` over an `/srv/index.html` that is inside the
measurement, with one line appended naming the `sandbox_id` off its config device, and each guest's
sandbox fetches the *other* guest's page. `httpd` binds loopback and nothing else, so the only
route to B's page is B's own exit at the far end of a tunnel B admitted A on.

```
launch measurement    81dbfc3818d9918c061e27c32cfb9694d06d06bc51df323d8f3436d0612a85e
                      182e8f06b14a39ca1eff3ed7375a6add9  (predicted offline twice; reported by both guests)
verity root hash      7c131c2e36648159e3f7de533b441d5bd7ec2af1ac87343ff8317269722e30ec (21,905 data blocks)
runsc                 ea305e126ab20e4abc525317f8ab7c04179b0cf0e08a517de6c3799a4b3c4ba0, 108,957,306 bytes
agent-probe           cee5c9abee948d024d754cf5837bd9e74ab79630ce52f43b24effc3c583c59e0
tunneld               57d56c404a0fa5a12186af3b93c046f4ad47bf543866e27d071680f45cdea24c
ceiling digest        197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973
workload disk         59570b7819c6e12683555ec2b39d435cfe0ad3d6436a33622f209810e535c691
```

**The measurement was computed from the four measured files before anything booted, and again on
its own, and is the number both guests reported.** No register, policy digest or peer measurement
was pinned by hand and nothing was read off a booted machine. The ceiling digest is ticket 22's
unchanged — runsc is not in `attest/ceiling` — so what a guest presents as its policy did not move.

**Init's order changed, and it is the one property ticket 24 had that this ticket trades.** With a
tunnel table on the config device, `/sbin/init` starts tunneld *before* the workload and waits for
the sandbox socket rather than sleeping on it, then the exit, then httpd, then runsc
(`init.rootfs:116-122,255-300`). Ticket 24's order put the workload first, which is the one moment
at which something can run with the ceiling installed and no link at all to leave by. That cannot
survive here — a sandbox on the adapter has no network of its own and its only way out is the
socket tunneld serves — so the guest's `eth0` is up while the workload runs. What replaces the old
property is that the workload has no interface, address or route of its own, because it is a
`--network=none` sandbox whose stack is loopback and whose one exit is the measured sentry.

**The four files that are the whole difference between the two guests** are on the config devices,
outside the measurement. A table says what that guest's sandbox may reach; an exit-allow says what
that guest's exit will dial for somebody else — the two ends of one hop, which is why each table
names the *other* guest's page.

| file | what it says |
|---|---|
| `a/tunnel-table.json` | A's sandbox may reach `web.peer-b`, port 80, through peer `guest-b` |
| `a/exit-allow` | A's exit will dial `web.peer-a:80` for a peer, and nothing else |
| `b/tunnel-table.json` | B's sandbox may reach `web.peer-a`, port 80, through peer `guest-a` |
| `b/exit-allow` | B's exit will dial `web.peer-b:80` for a peer, and nothing else |

`exit-allow` is a file rather than a field in `tunneld.json` because the run configuration refuses
unknown fields (`attest/cmd/tunneld/runconfig.go:289-302`), so a new field would mean changing the
measured binary for something that is not tunneld's business: the list belongs to the exit, which
is another process, and `-allow` is its flag. An absent file is an empty list, refusing everything.

**The two hops, in the guests' own words** (console line numbers):

```
A:611  tunnel dns: q="web.peer-b" type=A answer=100.64.1.0
A:613  tunnel attach: web.peer-b:80 -> peer "guest-b": ok in 109.085389ms, host fd 40, local 100.64.0.1:40001
A:586  served-by: guest-b
B:572  EXIT accepted a stream from peer="guest-a" vendor=amd-sev-snp measurement=81dbfc38…add9 policy_digest=197d4aae…b973
B:573  EXIT dialed web.peer-b:80 -> 127.0.0.1:80
```

and the mirror image: `B:613-615` resolving and attaching `web.peer-a` in 44.277268 ms, `B:592
served-by: guest-a`, `A:594-596` the exit's three lines. The measurement in those `EXIT` lines is
the number predicted offline for this image. **The four controls are four names that never became
addresses**: `A:614 q="web.peer-a" answer=nxdomain`, `A:616 q="not-in-the-table.example"
answer=nxdomain` and B's pair, with `wget: bad address '…'` in the sandbox each time. `web.peer-a`
resolves on B and does not resolve on A, from one image, one workload disk and one page: the 64
bytes that differ are on a disk in no measurement, and the thing that enforced them is in it. **The
relay's marker is the page's own text**, because there is no exercise in this scenario:

```
l2relay: RELAYED a_to_b_frames=49 b_to_a_frames=48 a_to_b_bytes=32116 b_to_a_bytes=31666
l2relay: MARKER not found hits=0 marker='served-by: guest-' in 97 frames carrying 63782 bytes
  ethertypes : IPv4=93, ARP=4   ip protocols: UDP=93   arp targets : 10.14.0.2, 10.14.0.3
```

Both pages crossed this segment and the machine copying every frame found neither. The harness's 52
assertions, as it groups them:

| group | what it asserts | A | B |
|---|---|---|---|
| the right run, 10 per guest | the measured image booted and ran the packaged tunneld; no writable path is executable; the author key read from inside the measurement; the set and chain read off the config device; the table put this guest on the adapter path; **tunneld started before the workload**; runsc launched with the adapter's two flags; httpd serving and init fetching its own page; powered off rather than stopped | PASS | PASS |
| attested, 7 per guest | evidence acquired from the platform; the config device's chain bundled; listening; **the sandbox socket up for the helper to dial**; the socket handed to another process; the exit attached holding its list; the peer admitted, nobody refused | PASS | PASS |
| the two hops | A's sandbox served B's page through B's exit and B's served A's; the exit dialled its one permitted destination and recorded the attested identity of the peer it served; the fetching process was inside a gVisor sandbox | PASS | PASS |
| the controls | the name in nobody's table did not resolve; the peer name in the *other* guest's table did not resolve | PASS | PASS |
| the segment | the exchange went through the relay; the relay could not find the page's text; no guest looked for a gateway or anything off the segment | PASS | — |

| off init's own clock | A | B | run 1 A / B |
|---|---|---|---|
| `no writable path is executable` | 3.13 s | 3.31 s | 3.03 / 2.80 |
| tunneld up, ahead of the workload | 3.49 s | 3.79 s | 3.50 / 3.23 |
| sandbox socket up | 4.00 s | 4.29 s | 4.01 / 3.73 |
| exit serving, runsc started | 4.08 s | 4.38 s | 4.19 / 3.80 |
| workload exited 0 | 5.31 s | 5.52 s | 5.48 / 5.28 |
| **the sandbox** | **1.23 s** | **1.14 s** | 1.29 / 1.48 |
| attach | 109.1 ms | 44.3 ms | 52.8 / 128.8 |

**Run 1 is kept whole and is the fuller failure record**: the same topology on the pre-review
binary `ab593dc254fe9617…4f70`, measurement `697bbdcd…186e`, scoring `51 passed, 2 failed`. The two
failures are two log lines that did not survive guest B's serial console, not two things that did
not happen: the missing pair is the longest the exit writes (~230 characters), due at the exact
instant B's own workload was writing A's page body to the same port and tunneld was writing its
`PEER` line, and what B *does* have is `EXIT web.peer-b:80 ended`, which `serveConnect` writes only
after `net.Dial` succeeded and the pump finished (`attest/cmd/agent-probe/exit.go:153-170`). **The
assertions were not edited after the fact**; they were fixed before run 2, as `exit_served` in
`docs/snp/tunnel-on-two-guests.sh:1398-1400`, which accepts either line, because an assertion that
names one of two equivalent lines is asserting something about a serial port. Replayed against run
1's consoles it turns those failures into passes; run 2 would have passed under the old assertions
anyway. Run 1 also carries the pair before it that a spooled harness stranded, in
`run/segment-down/` — a real SNP boot in which everything local worked and only the segment was
missing, and the one place `tunnel attach: … unavailable in 5.02039148s` is shown on hardware.

**The two runs differ in one file and five lines follow from it**: `/usr/bin/runsc`
(`ab593dc2…4f70`, 108,931,400 B → `ea305e12…4ba0`, 108,957,306 B, **+25,906**), and so
`rootfs.img`, the verity data-block count (21,898 → 21,905), `cmdline.txt` and the measurement.
Tunneld, `agent-probe`, the kernel, the firmware, the initrd, `/etc/hosts`, `/srv/index.html` and
every applet are identical, and the workload disk is the same file. **The seven review fixes show
in the console in exactly one way** — the resolver's line now quotes the name, two lines moved:

```
run 1   tunnel_dns.go:190] tunnel dns: q=web.peer-b   type=A answer=100.64.1.0     tunnel.go:381
run 2   tunnel_dns.go:193] tunnel dns: q="web.peer-b" type=A answer=100.64.1.0     tunnel.go:400
```

**`--debug --debug-log=/run/runsc-debug/` is now inside the measured flag set**
(`init.rootfs:174`) and costs about half a second of sandbox start: 16,900 bytes of `run` log on
the rehearsal against 16 MB across the three logs here. That is the price of the `tunnel dns:` and
`tunnel attach:` lines existing at all, and they are the only direct evidence of what the adapter
decided — without them the stranded pair could not have been diagnosed. They go to files on a tmpfs
and init greps those two line shapes back onto the console afterwards (`init.rootfs:308-310`),
because `--debug` on a serial port would bury the workload's own output. `/run` is `rw,noexec` and
a log file is not an exec, so the image's rule has nothing to say about it.

One bug was caught on a free control boot before the hardware: `opening the tunnel table
"/config/tunnel-table.json": permission denied`, because `mkconfigdev.sh` owned only the root
directory and this session's umask is 077. The table is the first file on that device read from
*inside* runsc's user namespace, which maps one id, and a capability over a file is only a
capability when the owner is mapped (`capable_wrt_inode_uidgid`, `user_namespaces(7)`); every
previous reader was tunneld, root in the initial user namespace. Ticket 24's `mkworkloaddev.sh`
finding one device over, same fix (`docs/snp/image/mkconfigdev.sh:79-126`). It would have cost the
hardware pair, because the harness runs the guests as root and root would not have seen it.

## What a hop costs

| | loopback | in the SNP guest |
|---|---|---|
| first attach, cold | 61.4 ms (agent-probe), 67.2 ms (Claude Code) | 109.1 ms (A), 44.3 ms (B); run 1: 52.8 / 128.8 |
| later attaches, warm | 39.0 ms (second name), 13.7–18.7 ms (same name, eight of them) | not measured: one attach per guest |
| `tunnel_open` → `first_connect` | 12 ms, both workloads | — |
| `first_connect` → `first_byte` | 29 ms (agent-probe), 25 ms (Claude Code) | — |
| the sandbox, start to workload exit | — | **1.14–1.48 s** over four guests |

**The cold attach is the tunnel and the warm one is not.** The first `Attach` contains the dial,
both sides judging the other's evidence and the push; a second name on the same tunnel is 39 ms,
and Claude Code's eight later attaches are 13.7–18.7 ms, a QUIC stream on a tunnel that already
exists plus the exit's own `net.Dial` of a public host. E3 measured the transport underneath at
1.34 ms for `Helper.Open` including its dial and 116 MiB/s round trip through a host TCP hop, so
essentially none of these numbers is the handoff itself. **The sandbox costs 1.14–1.48 s in the
guest against ticket 24's 0.85–0.90 s**, and the difference is `--debug` writing 16 MB to a tmpfs
rather than anything the adapter does: run 2's 25,906 extra bytes and seven fixes sit inside run
1's spread in both directions. Every fetch succeeded on its first attempt.

## What Claude Code asked for

**E4 measured it outside any sandbox first**: `claude -p`, version 2.1.276, under `strace`, four
runs, cheapest model, empty working directory. The list is two names, identical in all three traced
runs and in the same order every time — **`api.anthropic.com`** and
**`http-intake.logs.us5.datadoghq.com`**, both on **443**. No CDN, no update check, no plugin
marketplace, no MCP connector: with an API key the CLI prints that claude.ai connectors are
disabled and never reaches those hosts. The Datadog log intake is contacted on a *fresh* HOME with
no opt-in on every run, so a table with the model endpoint alone would make a real agent runtime
retry its log flush. Both names are resolved through glibc against `127.0.0.53:53`, `A` and `AAAA`
back to back, and the `AAAA` address is connected to first; each connection's name has two
witnesses in the trace, the DNS answer and the SNI in the ClientHello, and they agree everywhere.
Three to four resolutions and seven to ten IPv4 connections per name per run: it opens a pool.

**The rehearsal put the ELF under a stock runsc with no adapter**, to separate "the binary runs
here" from "the adapter carries it". It started, forked `git`, re-exec'd itself as ripgrep, bound
its unix socket and reached a JSON result — an error result, `API Error: Can't reach the API server
— check your internet or DNS (EAI_AGAIN)`, after 3m5.767s, which is what a `--network=none` sandbox
should produce. Recorded, not a failure.

**Through the adapter it completed the task.** Table: the two names E4 found, port 443 each.
`runsc` exit 0 in 9.037 s, `tunnel_open=2.505s first_connect=2.517s first_byte=2.542s`. The result
is `"result":"OK"`, `"is_error":false`, 1 turn, **$0.010855**, 2,547 ms wall of which 2,609 ms API,
on `claude-haiku-4-5-20251001`. The resolver was asked for `api.anthropic.com` eight times and the
intake twice, A and AAAA each; nine streams reached the exit, eight to the model endpoint and one
to the intake, every one by name because the sandbox never had an address of its own to give.
Fourteen `AF_INET` sockets, five `AF_NETLINK`, three `AF_UNIX`, 15 datagrams to `127.0.0.53:53`.
Two syscalls the sentry does not implement were asked for and shrugged off — `rseq` eight times and
`copy_file_range` once, both `ENOSYS` — and the run completed anyway.

**What the rootfs had to carry**, none of it a change to the agent: the loader and the six
libraries `ldd` names, plus `libnss_dns.so.2` and `libresolv.so.2`, which are not insurance —
`nss_dns` is what turns `hosts: files dns` into a query and it is linked against `libresolv`, so a
glibc workload without them resolves nothing at all; `/usr/bin/git`, forked four times before the
first model call, with its own two libraries; and a **writable** rootfs, because the CLI writes a
HOME, `mkdir`s a lock directory and binds an AF_UNIX socket. E4 predicted
`/run/user/<uid>/cc-socks/<pid>.sock`; with no `XDG_RUNTIME_DIR` set the CLI's own fallback chose
**`/tmp/cc-socks/1.sock`**, and `bind` then `listen(512)` both returned 0. The environment is built
from four variables rather than inherited, so E4's `CLAUDE_CODE_*` strip list is unnecessary here.

**What it cost, and the cap.** E4 $0.043629 over four runs; the pre-review loopback-and-smoke pair
$0.035706 + $0.010815 = $0.046521; the post-review pair $0.034946 + $0.010855 = $0.045801.
**$0.135951 in all**, against a $5 cap across tickets 25 and 26. Model ids: `claude-sonnet-5` for
every `agent-probe` run, `claude-haiku-4-5-20251001` for every Claude Code run, with one
`claude-sonnet-5` call in E4's `run3`, which used the operator's own HOME. The controls cost
nothing: they failed before a request left.

## What this ticket did not do

No TDX: no cloud instance was created, no TD booted, and nothing here says anything about RTMR2 or
about two TDX guests, which is ticket 26's. No enforcement of a *pushed* policy — the table is a
boot-time input and the only rule is "in the table or refused"; the helper accepts an `Apply` from
tunneld, logs it and acknowledges it, and nothing narrows anything. No change to tunneld, to the
contract, to the wire or to the ceiling. No change to the agent programs: `agent-probe` gained a
`-network plain` mode that is byte for byte the `direct` client plus one log line
(`attest/cmd/agent-probe/main.go:214-222`), and Claude Code is the shipped ELF. The provisional
`(N, F, X)` bytes are untouched and no format change is proposed.

## Leftovers

The first thirteen are the adapter check's own list, unchanged (`adapter-check/notes.md:202-240`).

1. **A restored sandbox gets no adapter.** It is installed from `Loader.run`'s `created` path only.
2. **`tunnelEndpoint` is not stateify-savable**, so a checkpoint of a sandbox with an attached
   stream fails. A descriptor to a host socket is not state that can be written down.
3. **An `AF_INET6` socket, or a v4-mapped destination, is refused** with `not-in-table` rather than
   a reason saying the adapter is v4-only. The AAAA answer means a runtime should never reach it.
4. **The notifier callback takes the endpoint's mutex** while `Read` holds it across the copy into
   the caller's buffer, so a wakeup can wait on a slow copy.
5. **Bytes left in `rbuf` raise no new readable edge.** Under `EPOLLET` a reader that stopped short
   could sleep on data the sentry already holds; both runtimes read until `EAGAIN`.
6. **`SIOCINQ`/`SIOCOUTQ` report only the sentry's own buffers**, not what the descriptor holds.
7. **Table names are not charset-validated**, and the exit's answer is matched by prefix without
   checking that the destination it echoes is the one that was asked for.
8. **DNS refusals carry no task context.** The responder has no task.
9. **The ceiling is checked once, at install.** A NIC added afterwards would not be noticed;
   nothing in the sandbox can add one.
10. **Refusal events are not rate-limited**: one per refused connect, datagram or query.
11. **The descriptor from the helper is duplicated with a plain `dup(2)`**, which carries no
    `FD_CLOEXEC`. Nothing is dropped — urpc's transport never sets it — and the sentry's seccomp
    filter permits `fcntl` only for `F_GETFL`, `F_SETFL` and `F_GETFD`, so a CLOEXEC-preserving
    duplicate is not available to it; the sentry execs nothing after boot.
12. **The sentry's call into the helper is a blocking Go call** serialised by one mutex, bounded at
    30 s (`runsc/cmd/tunnel_helper.go:165`) but **not interruptible by a signal**, so a workload
    thread inside `connect(2)` cannot be woken early.
13. **No seccomp filter on the helper**, matching `runsc/checkpointgofer`.

Seven more the rest of the ticket found.

14. **`tunneld: SANDBOX attached` appears twice per guest**: the exit and the tunnel helper are both
    clients of one socket. Nothing went wrong — the exit is the only one that calls `Accept` and the
    helper only calls `Open` — but **a pushed policy in this arrangement would go to whichever
    `sandbox.Host` picked it up**. No policy was pushed in any run here.
15. **The key is in runsc's debug log, always**, because runsc logs the container spec and
    `process.env` is in it. The practice that stands in for a fix: the bundle's `config.json` lives
    on `/dev/shm` under a 0700 directory and is removed at the end, every captured file is searched
    for the key before it is copied, one that carries it is left behind with a `.redacted` copy in
    its place, and the count per file is in the run's README.
16. **The measured guest's console drops lines under contention**, which is new: no scenario before
    this had four processes writing to `/dev/console` at once. The lesson is the general one —
    anything a future run must prove should be read out of a file in the guest and printed once.
17. **`-timeout 30m` is a number inside the measurement.** The exit is started with it
    (`init.rootfs:279`), so a scenario held open longer than half an hour would leave the guest
    listening with nothing behind the socket. A longer run needs `init.rootfs` changed and a new
    measurement; `-quick` is two orders of magnitude inside it.
18. **`attest/` has no BUILD files**, which is why `runsc/cmd/tunnel_client.go` exists at all.
    Reported, not fixed: 352 lines of runsc now track a protocol defined in another module.
19. **The `(N, F, X)` format is untouched, and this ticket has two things to say to whoever changes
    it.** A name in `n` has to carry its port, because the unit the adapter enforces is `host:port`
    and a row with a name and no port grants every port on it — the check's `wrong-port` row is that
    distinction being made. And **the resolver is now inside the enforcer**: ticket 23 recorded that
    a name-checking enforcer is bound to whatever the resolver returns while an enforcer below the
    runtime sees addresses and would need DNS pinning; here the two are one program, the binding is
    allocated by the thing that enforces it, and the address it hands out cannot have come from
    anywhere else. Nothing is proposed.

## Evidence

| what | where |
|---|---|
| E1a, the host strace study: the per-runtime call table, six fault injections, the verdict | `docs/snp/evidence/ticket25/spikes/E1/` (`notes.md`, `run.sh`, `output-01`–`output-19`) |
| E1b, the same question inside the sandbox: four runs, PASS, no call refused | `.../spikes/E1/sandbox/` (`notes.md`, two `.diff`s, `run-e1b.sh`, eight outputs) |
| E2, where a datagram arrives and where a responder must sit | `.../spikes/E2/` (`notes.md`, two `.diff`s, `udpprobe.go`, `output-01`–`output-04`) |
| E3, the urpc + `FilePayload` round trip, its sizes, timings and end-of-life signals | `.../spikes/E3/` (`notes.md`, `supervisor.go`, four outputs; run 1 kept for its failure) |
| E4, what Claude Code asks the network for, outside any sandbox | `.../spikes/E4/` (`notes.md`, `table.md`, `derive.py`, three raw traces) |
| the adapter check: six runs, two runtimes, the refusals, the validation, the seven fixes | `.../adapter-check/` (`notes.md`, `output-01`, `output-02`, `faketunneld/`, `adapterclient/`, `adapternode.js`) |
| the loopback proof, final binary, and the same proof on the pre-review one | `.../loopback/20260918-110411/README.md`, `.../20260918-103148/README.md`, `loopback/run.sh` |
| Claude Code through the adapter, final and pre-review, and the stock-runsc rehearsal | `.../claude-smoke/20260918-110454/README.md`, `.../20260918-103238/README.md`, `.../rehearsal-stock-runsc/README.md`, `claude-smoke/run.sh` |
| the SNP run the record names: 52 of 52, both hops, four controls, no line loss | `.../snp/run-2/` (`notes.md`, `capture/`, `jobs/`, `manifest.txt`, `predicted-measurement-independent.txt`) |
| the first SNP pair, 51 of 53, and the stranded pair before it | `.../snp/run/` (`notes.md`, `capture/`, `segment-down/`) |
| the rehearsal, the runbook, and the four config-device files | `.../snp/rehearsal/notes.md`, `.../snp/RUNBOOK.md`, `.../snp/config/README.md` |
| the receiver the `egress_refused` lines come from | `.../tools/seccheck-receiver/` |
| the sentry's half | `pkg/sentry/socket/netstack/tunnel.go`, `tunnel_dns.go`, `tunnel_endpoint.go`, `netstack.go:430-493,855-861,3451-3457`, `pkg/sentry/seccheck/metadata.go:343-346`, `points/sentry.proto:192-218` |
| the boot and host halves | `runsc/boot/tunnel.go`, `controller.go:250-252`, `loader.go:928-938,1285-1290`, `runsc/cmd/tunnel_helper.go`, `runsc/cmd/tunnel_client.go`, `runsc/config/config.go:479-523`, `flags.go:160-161`, `runsc/sandbox/sandbox.go:1061,1914-2001` |
| the image, the init and the scenario | `docs/snp/image/init.rootfs:116-320`, `build-image.sh`, `package-tunneld.sh`, `mkconfigdev.sh:79-126`, `docs/snp/tunnel-on-two-guests.sh:1375-1535`, `.../snp/make-bundle.sh` |
| the two harnesses and the plain mode | `attest/cmd/agent-probe/adapter_test.go`, `claude_test.go`, `main.go:214-263` |

The unit tests are ten in `pkg/sentry/socket/netstack/tunnel_test.go` (the table, the address
arithmetic, the loopback classification, the per-connection local port, and the four endpoint
assertions the review's fixes are argued on), seven for the responder in `tunnel_dns_test.go`, two
for the flags in `runsc/config/tunnel_test.go`, and two for the plain mode in
`attest/cmd/agent-probe/network_test.go`. `ripwire attest --quality-delta=ab26b518c..HEAD`:

```
<quality-delta baseline="ref-pair" regressions="15" minor="0" acked="0" stale="6"
preexisting-worse="0" new-symbol="15" gating="0" register-macro-excluded="0"
base_ref="ab26b518c46f8880ede46d354f933079ee3d708d"
target_ref="a0b5a7c227467c978c04d0b9f32a943f1cc4d537" churn="unavailable" renames="0"
rename_window_commits="0" acked_by_rename="0" acked_by_content="0">
```

**`gating="0"`, `acked="0"` and `preexisting-worse="0"`**: nothing that existed at ticket 24's tip
got worse, and nothing was acked for this record. All 15 regressions are `origin="new-symbol"` and
all 15 are in the two live harnesses — the complexity, verbosity and dead-code rows a gated
integration test and its capture code produce. The 6 stale rows are ticket 23's acks whose findings
are gone; the ledger was not edited.
