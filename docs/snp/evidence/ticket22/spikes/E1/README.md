# Spike E1 — can a QUIC stream cross a process boundary as a file descriptor?

Ticket 22 makes tunneld a sandbox-agnostic boundary with a local contract to a
sandbox process beside it: `Open(peer) (stream, error)` and
`Accept() (stream, Attested)`. A later sandbox (runsc) consumes those streams
as FD-backed endpoints **in a different process**. The shape of `Open` and
`Accept` therefore depends on one question:

> Can tunneld hand a peer's QUIC stream to the sandbox process as a descriptor
> (SCM_RIGHTS), or must the contract proxy bytes through a socketpair that
> tunneld pumps?

## Result

**Stream-as-FD: not possible.** A QUIC stream is not a kernel object. attest
pins `github.com/quic-go/quic-go v0.59.0` (`attest/go.mod:9`), a userspace QUIC
stack: `quic.Stream` is `{receiveStr *ReceiveStream; sendStr *SendStream;
sender streamSender; mutex; two bools}`
(`quic-go@v0.59.0/stream.go:53`), the two halves are in-process reorder buffers
and flow-control state (`receive_stream.go`, `send_stream.go`), and the whole
exported method set is `StreamID, Read, Peek, Write, SetReliableBoundary,
CancelRead, CancelWrite, Context, Close, SetReadDeadline, SetWriteDeadline,
SetDeadline` — no `File`, no `SyscallConn`, nothing that yields a descriptor.
The only kernel object in the picture is the transport's UDP socket,
`quic.Transport.Conn net.PacketConn` (`transport.go:70`), and quic-go says in
that file what passing it would mean: "QUIC demultiplexes connections based on
their QUIC Connection IDs, not based on the 4-tuple. This means that a single
UDP socket can be used for listening for incoming connections, as well as for
dialing an arbitrary number of outgoing connections" — so that one descriptor
is every connection and every stream on it at once, and it still would not
carry a stream, because the TLS 1.3 keys, the packet-protection state, the
reassembly buffers and the flow-control windows all live in tunneld's heap, not
in the socket. **Socketpair proxy: works.** A parent process holding the QUIC
stream creates `socketpair(AF_UNIX, SOCK_STREAM)`, passes one end to a separate
child process over a unix socket with SCM_RIGHTS, and pumps
stream↔socketpair with two `io.Copy` goroutines; the child turns the received
descriptor into a plain `net.Conn` with `net.FileConn` and does its
request-responses through it. Round trips were verified byte for byte — 0
mismatches across every phase of every run of both invocations recorded here.
**Cost:** one extra hop each way. On this (deliberately unhelpful) host a bare
64 B socketpair round trip to the child costs 21 µs at best and 34–41 µs at the
median, and the proxy pays that twice per request-response: measured
+72–84 µs on a best-case 64 B round trip and +200–232 µs at the median
(1.7–2.3× a loopback QUIC round trip that is itself only 106–193 µs here), and
0–24 % of single-stream bulk throughput, which stays in the 100–135 MiB/s band
either way.

## Numbers

Seven runs per invocation; each cell is the median across runs of that run's own
figure. "best" is the fastest round trip seen, which is the least host-noise-
contaminated view of the structural cost; "median"/"p90" include this host's
scheduling jitter. Two independent invocations are shown because the medians
move run to run and the reader should see that.

| phase | metric | direct | proxied | delta | ratio |
|---|---|---|---|---|---|
| lat-64B | median RTT (µs) | 193.18 | 393.84 | +200.66 | 2.04 |
| lat-64B | best RTT (µs) | 106.32 | 189.97 | +83.66 | 1.79 |
| lat-64B | p90 RTT (µs) | 316.10 | 619.32 | +303.22 | 1.96 |
| lat-4KiB | median RTT (µs) | 508.05 | 781.75 | +273.70 | 1.54 |
| lat-4KiB | best RTT (µs) | 277.92 | 427.40 | +149.47 | 1.54 |
| lat-4KiB | p90 RTT (µs) | 706.46 | 1089.50 | +383.04 | 1.54 |
| bulk-up-64MiB | throughput (MiB/s) | 124.95 | 116.48 | −8.46 | 0.93 |
| bulk-down-64MiB | throughput (MiB/s) | 120.03 | 120.91 | +0.88 | 1.01 |

Repeat invocation (`run-2.log`, `results-2.json`):

| phase | metric | direct | proxied | delta | ratio |
|---|---|---|---|---|---|
| lat-64B | median RTT (µs) | 175.30 | 407.56 | +232.26 | 2.33 |
| lat-64B | best RTT (µs) | 109.12 | 181.12 | +72.00 | 1.66 |
| lat-4KiB | median RTT (µs) | 532.83 | 748.40 | +215.56 | 1.41 |
| lat-4KiB | best RTT (µs) | 290.55 | 382.23 | +91.68 | 1.32 |
| bulk-up-64MiB | throughput (MiB/s) | 134.57 | 102.96 | −31.61 | 0.77 |
| bulk-down-64MiB | throughput (MiB/s) | 133.25 | 117.76 | −15.49 | 0.88 |

The floor the proxy pays, measured separately with no QUIC underneath it at
all — a 64 B round trip to the same child over a bare socketpair:

| invocation | median | best | p90 |
|---|---|---|---|
| `run.log` | 40.88 µs | 21.20 µs | 59.70 µs |
| `run-2.log` | 34.48 µs | 21.23 µs | 53.30 µs |

Two of those hops per request-response (out and back) is 42 µs at best and
70–82 µs at the median, which is most of the measured delta; the rest is the
pump's own two goroutine wakeups inside tunneld.

Read the absolute latencies as an upper bound on the cost, not as a
measurement of QUIC: the host runs the `conservative` cpufreq governor at a
load average around 3, and a loopback QUIC round trip on it already costs
106–193 µs where a quiet machine would be well under 100 µs. What transfers to
another host is the shape — one extra socketpair hop in each direction, two
copies, two wakeups — not these microseconds.

## The one direct variant that exists: pass the UDP socket

Step 4 of the spike dups the QUIC connection's UDP socket (`unix.Dup` of the
`*net.UDPConn` fd) and passes *that* to the child. The child can hold it and
learn nothing useful from it, which is the point:

| probe | result |
|---|---|
| `getsockname` | `127.0.0.1:35001` — the parent's QUIC local address: this is the connection's (in fact the whole transport's) socket, not a stream's |
| `SO_TYPE` | `2` = `SOCK_DGRAM` |
| `getpeername` | `ENOTCONN`, "transport endpoint is not connected" — quic-go sends with `WriteTo`, so the socket has no peer |
| `write(fd, …)` | `EDESTADDRREQ`, "destination address required" — the child cannot even emit bytes, let alone stream bytes |
| `recvfrom(MSG_DONTWAIT)` | `EAGAIN` — and a blocking read here would *steal* QUIC packets from the parent's stack |

Even handed the peer address, everything on that socket is QUIC packets under
AEAD packet protection whose keys are in tunneld's memory; the child would have
to be a second QUIC endpoint on the same connection to read a stream out of
them, which is not a thing.

## What this decides for the contract

- `Open(peer) (stream, error)` returns **one end of an `AF_UNIX SOCK_STREAM`
  socketpair** (as an `*os.File`/fd for a separate sandbox process, or a
  `net.Conn` in-process); `Accept() (stream, Attested)` yields the same plus
  the peer's verdict. The type in the contract is a descriptor, never a
  `*quic.Stream` — the QUIC type cannot cross the boundary and must not appear
  in a contract whose whole purpose is that tunneld is sandbox-agnostic.
- **tunneld pumps.** Per accepted or opened stream it runs two `io.Copy`
  goroutines. The pump also carries the *end* of the byte stream in each
  direction — socketpair EOF becomes `Stream.Close()` (a FIN), stream EOF
  becomes `CloseWrite()` on the socketpair — a copy loop that moved only bytes
  would leave each side waiting on an end that never comes.
- The handoff needs no fork/exec relationship: every child here was already
  running and received the descriptor over a unix socket
  (`child pid … received fd 7 over SCM_RIGHTS` in the logs), so tunneld can
  hand streams to a sandbox that started independently.
- Budget the cost as **~40–80 µs of added round-trip latency and ≲25 % of
  single-stream bulk throughput**, spent on every stream, unconditionally. That
  is the price of the boundary; there is no cheaper variant to hold out for,
  because the bytes are in tunneld's userspace either way (no `splice`, no
  zero-copy shortcut applies to a userspace QUIC stack) and the only way to
  avoid the hop is to put the QUIC stack in the sandbox process, which is
  exactly what ticket 22 refuses.
- Two follow-ups this spike does not settle: how a QUIC **reset**
  (`CancelRead`/`CancelWrite`) should appear to the sandbox — `SOCK_STREAM` has
  no signal for "reset" other than closing, so an abnormal end and a clean end
  look alike unless the contract adds one — and that `attest/tunnel` today
  exposes no stream at all (`Conn.Exchange`, `tunnel.go:479`, is one framed
  request-response returning `[]byte`; `Conn.Serve`, `tunnel.go:515`, answers
  them). `Open`/`Accept` will need a stream-level accessor on `tunnel.Conn`
  over the `OpenStreamSync`/`AcceptStream` it already calls internally.

## What is here

| file | what |
|---|---|
| `fdhandoff.go` | the spike, one `main` package (782 lines with the licence header and comments, 641 of code): QUIC peer, echo protocol, client loop, SCM_RIGHTS handoff, the pump, the measurement harness, the socketpair baseline, and the UDP-socket probe |
| `go.mod`, `go.sum` | a nested module, deliberately outside the gvisor root module and outside `attest/`, pinning the same `quic-go v0.59.0` that `attest/go.mod` pins |
| `run.sh` | rebuild and rerun, capturing host conditions into the log |
| `run.log`, `results.json` | the primary invocation: human-readable log, full per-run JSON |
| `run-2.log`, `results-2.json` | the repeat invocation |

How it is wired: the parent process plays tunneld — it owns both ends of a
loopback QUIC connection (two `quic.Transport`s over two UDP sockets in one
process) and holds the streams. For the **direct** baseline the parent runs the
client loop straight on `*quic.Stream`. For the **proxied** measurement it
opens another stream, creates a socketpair, re-execs itself as a child
(`-mode=child`), passes one end over a unix socket with SCM_RIGHTS, and pumps;
the child runs the identical client loop over its `net.FileConn`. Both modes
run the same warmup first and alternate order run to run, so neither is
systematically the one on the colder connection.

## Rebuild and rerun

```sh
cd docs/snp/evidence/ticket22/spikes/E1
./run.sh 7                     # writes run.log and results.json here
TAG=2 ./run.sh 7               # writes run-2.log and results-2.json
```

Or by hand:

```sh
export PATH="/usr/local/go/bin:$PATH"
cd docs/snp/evidence/ticket22/spikes/E1
GOPROXY=off go build -o /tmp/fdhandoff .
/tmp/fdhandoff -runs=7 -out=/tmp/results.json
```

`go vet ./...` is clean. Nothing here is imported by, or importable from, the
gvisor or attest modules.
