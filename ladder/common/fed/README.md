# `ladder-fed` — the federation substrate

Built for rung 5a; shared verbatim with rung 5b when it lands. One Go binary, run once
per host, on the **host**, outside every sandbox — like the broker, the postbox and the
capability authority before it.

It is a separate Go module on purpose. Conventions §1 says nothing outside `ladder/`
should change, and adding quic-go and wormhole-william to the runtime's `go.mod` would
change the tree the ladder is meant to leave alone. It also keeps the answer to "did
rung 5a touch the gVisor tree?" a simple **no**.

## The two-layer stamp

The one thing to understand before reading any file here.

| Layer | Written by | Carries | This package |
|---|---|---|---|
| inner, 256 bytes | the **sending sandbox's kernel** (`pkg/sentry/ladder/attest.go`) | identity, taint, grants, chain, origin | copies it, hashes it, **never writes one** |
| outer, the envelope | this proxy | routing, expiry, sequence, channel binding, the attenuated capability | writes and signs it |

Moving the inner layer out here to simplify the proxy would reopen the problem rung 3
already rejected — a host-side stamper needs `runsc ladder-status` per message, which is
root-only and live-sandbox-only — and would shrink the runtime's role from "holds facts
nothing else can" to "is one more participant". `stamp.go` may *believe* a stamp. It may
not *produce* one; the only function in the package that writes stamp bytes lives in
`attack.go`, where it is a forgery tool.

`StampLen` is a wire contract shared by **four** implementations now, and nothing detects
a disagreement at runtime — a reader using the wrong width silently sees a stamp as body
or a body as stamp. All four move together or none do:

| Where | Constant |
|---|---|
| `pkg/sentry/ladder/attest.go` | `StampLen` — the writer |
| `common/postbox/postbox.py` | `STAMP_LEN` — the relay |
| `common/fake_agent/fake_agent.py` | `STAMP_LEN` — the reader, and the forger |
| `common/fed/stamp.go` | `StampLen` — the federation carrier |

## Files

| File | What |
|---|---|
| `identity.go` | the long-term Ed25519 key, its throwaway X.509 envelope, and the pin check that is the entire authentication policy |
| `registry.go` | the enrolment registry — the whole trust root, and it is a text file |
| `transport.go` | the two planes: cached QUIC connections per host pair, one stream per exchange |
| `envelope.go` | the framing, the signature, the ten receive-side checks, and their codes |
| `replay.go` | the bounded sequence window, plus an honest note on what it is worth next to the channel binding |
| `rolescope.go` | the receiving service's deploy-time ceiling; `chaind.subset` in Go |
| `proxy.go` | the `serve` command: gateway in, QUIC out, QUIC in, postbox out, recycle policy |
| `plain.go` | what `--ladder-fed` **off** means, and the MITM the demo puts on the wire |
| `enroll.go` | the SPAKE2 ceremony over a self-hosted mailbox |
| `attack.go` | the enrolled-but-misbehaving sender that exercises the per-message checks |
| `bench.go` | the latency table and the concurrent burst |

## The ten checks, in order

Each has its own code and its own line of demo evidence. Nothing reaches `postbox.py`
until all ten pass, which is acceptance criterion §7: *substrate rejections happen in the
proxy before any agent sees bytes*.

| # | Check | Code |
|---|---|---|
| 0 | the peer's key is in the registry | refused **at the handshake**, before any stream |
| 1 | magic and framing well-formed | `bad-frame` |
| 2 | nothing after the body | `trailing-bytes` |
| 3 | signed by the key that authenticated **this connection** | `signature-invalid` |
| 4 | bound to this channel's exporter output | `not-exporter-bound` |
| 5 | not expired | `expired` |
| 6 | sequence fresh for this (host, peer) | `replayed` |
| 7 | body hash matches | `body-tampered` |
| 8 | addressed to a service this host fronts | `unknown-service` |
| 9 | the capability claim ⊆ that service's role scope | `outside-role-scope` |

Check 3 is stricter than it looks: it verifies against the **connection's** peer key, not
against a key looked up from `from_host`. Without that, an enrolled host C could relay
host A's envelope and have it verify.

## Two things the code says that prose would blur

**A network attacker cannot produce checks 1–7 once the channel is up.** That is what the
transport is for. The party that can is one holding an *enrolled* key — which is exactly
the residual rung 5a leaves open. `attack.go` is that adversary, used as the harness, and
it says so at the top rather than dressing the cases up as network attacks. The two cases
that genuinely *are* network-attacker cases — the impostor and the MITM — are marked.

**The channel binding does the replay work; the sequence window is the narrow half.** A
captured envelope replayed onto a fresh connection dies on the exporter comparison before
the sequence check runs. The window catches a replay onto the *same* connection, which is
a real but smaller case. The demo runs both and asserts them separately, because
collapsing them would credit the sequence number with the exporter's work.

## Spec corrections recorded here

1. **Go has no RFC 7250.** `crypto/tls` has no `client_certificate_type` /
   `server_certificate_type` extension at any version available here. The Ed25519 key is
   wrapped in a self-signed certificate that is *only* a serialization envelope: no chain
   is built (`VerifiedChains` is empty on both sides), no name is checked, and the
   validity dates are set a century wide so nobody mistakes certificate expiry for a
   control. See `identity.go`.
2. **`quic.Dial` returns a nil error even when the server is about to reject you.** In
   TLS 1.3 the client's handshake completes once it has *sent* its Certificate/Finished;
   the server has not looked at the client's key yet. The rejection surfaces on the first
   stream operation as `CRYPTO_ERROR 0x12a`. `Dialer.dialConfirmed` forces one
   application round trip before handing the connection back — without it, the demo's
   impostor "connects".
3. **A refused handshake never becomes a connection**, so the accept loop has nothing to
   report. The evidence line is written from inside the pin-check callback
   (`peerAuth.onReject`), which is the only place that knows.
4. **`ExportKeyingMaterial` has a pointer receiver and `ConnectionState()` returns a
   value**, so the obvious one-liner does not compile. Bind to a local first.
5. **quic-go's `Stream.Close()` *is* `CloseWrite`** — it shuts the send direction only.
   The receiver's read-to-EOF, and therefore the trailing-bytes check, depends on it.

## Building

```
cd ladder/common/fed && GOFLAGS=-mod=mod GOPROXY=off go build -o ladder-fed .
```

or `make -C ladder fed`. Versions are pinned in `go.mod`; after one warm fetch the build
is fully offline, and nothing at demo time reaches the network. The module declares
`go 1.25.0` because quic-go v0.59.0 and `golang.org/x/crypto` both require it — the
gVisor tree's own `go.mod` already declares newer, so any checkout that builds runsc
builds this. Set `LADDER_GO` to point at a specific toolchain if the one on `PATH` is
older.
