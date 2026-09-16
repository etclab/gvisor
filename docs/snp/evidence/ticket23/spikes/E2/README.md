# E2 — the same agent, behind the null sandbox

**Question.** E1's agent, unchanged, with every outbound TCP connection it
makes going through the contract's `Open(ctx, peer)` instead of a direct dial.
What breaks first, and in what order?

**Answer, up front: nothing broke.** Three runs, three completions. The agent
fetched RFC 8446, summarised it, wrote `summary.txt` and said DONE, with every
byte it sent to `api.anthropic.com` and to `www.rfc-editor.org` carried over an
attested QUIC tunnel to a second tunneld and out through a throwaway exit. So
the ticket's stop rule is **not** triggered: the contract can carry the agent.

What the contract could not do is *express* any of it. Four things had to be
supplied by the shim, and each one is a line in the list below. Nothing in
`attest/` was changed, and no fix was made.

---

## What ran

Two in-process `tunneld.Tunneld` instances over loopback with the fake
platform, started exactly as `attest/tunneld/sandbox_test.go` starts them — the
tunneld *binary* cannot serve on this workstation, which has no
`/sys/kernel/config/tsm/report` (ticket 22's spike E4, first section). A is
`sandbox-a` running `imageA`, B is `sandbox-b` running `imageB`, each admitting
the other's measurement.

```
agent → http.Transport.DialContext → boxA.Open(ctx, "b") → QUIC stream → B
                                                              ↓
                       the exit: read "CONNECT host:port\n", net.Dial it,
                       pump bytes both ways
```

TLS runs end to end from the agent to `api.anthropic.com` over that stream, so
the exit sees a ClientHello and then ciphertext and never a request.

A is configured with `Config.PushPolicy`, which is `tunneld -push-policy`
without the command: one document to every peer it dials, once, before it hands
out a stream. The document is ticket 22's provisional shape narrowed to what E1
measured:

```json
{"format":"policy","version":1,"n":[{"cidr":"0.0.0.0/0","ports":[443]}],"f":[],"x":[]}
```

B's null sandbox acknowledged it on every run, at the same digest:

```
B SANDBOX applied format=policy version=1 bytes=86 sha256=8218d19995d73e12fd704da2c2e203e221fdc9158e134800f10b45330dc7543a
```

**and enforced nothing.** `sandbox.Null.Apply` reads the envelope and records a
digest; `n`, `f` and `x` are unread by every line of code in this tree. The run
would have been byte-for-byte the same with `"n":[]`.

The commands:

```
cp e2_agent_on_the_contract_test.go.txt attest/tunneld/spike23_e2_test.go
cd attest && go test ./tunneld/ -run TestSpike23E2 -v -count=1 -timeout 15m   # ×3
rm attest/tunneld/spike23_e2_test.go
```

The agent is E1's, not a second one. Everything below the line
`// ===== the agent, shared verbatim by E1 and E2 =====` is byte-identical in
`../E1/agent.go` and in the harness here — `sha256
a7087e713c4789e08deb512d4c0791ac1e22473d3638269931223372fe825a3a` over that
part of both files. The only difference between the two experiments is the
`*http.Client` handed to `spikeRunAgent`.

## The result

| run | requests | Open 1 (cold) | Open 2 (warm) | input tokens | output tokens | cost | wall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 model + 1 fetch | 34 ms | <1 ms | 15 061 | 636 | $0.036482 | 8.115 s |
| 2 | 3 model + 1 fetch | 44.389 ms | 164 µs | 15 023 | 596 | $0.036006 | 7.807 s |
| 3 | 3 model + 1 fetch | 39.892 ms | 277 µs | 15 072 | 646 | $0.036604 | 8.448 s |

E1, for comparison, was 6.5–7.4 s wall and $0.0352–$0.0357 a run. **The
contract costs about 1 second on a 7-second task**, and essentially all of it
is the first `Open`: 34–44 ms of tunnel establishment — dial, both sides judge
the other's evidence, the policy is pushed and acknowledged — plus, per run,
two `net.Dial`s at the exit (10–33 ms each) that E1 paid inside its own
process. Every later `Open` is a QUIC stream on the tunnel that is already
there: 164 µs and 277 µs.

**Four HTTP requests went over two `Open` calls.** `http.Transport` pooled the
connection, so the three model requests shared one stream and the one
`fetch_url` opened the second. Nothing in the contract decides that; the
agent's HTTP client does, and a client that disabled keep-alive would have
asked for four.

## What broke, and in what order

Each line is what the contract ran out of, at the point it ran out, and what
the throwaway shim did instead. None of these is fixed.

1. **Name resolution — it does not happen on the agent's side at all.**
   `DialContext` is handed `"api.anthropic.com:443"`, a host and a port and not
   an address: Go's `net/http` resolves *inside* the dialer it is given, so a
   dialer that never resolves means the agent never resolves. Every row in E1's
   table about the resolver — `127.0.0.53:53`, `/etc/resolv.conf`,
   `/etc/nsswitch.conf`, `/etc/hosts`, `/etc/gai.conf`, `/etc/host.conf`, the
   `nscd` socket, the netlink `RTM_GETADDR` — moved to the far end and is now
   the exit's. The log line `EXIT resolved and dialed api.anthropic.com:443 ->
   160.79.104.10:443` is that, recorded. This is a change in *who* resolves, so
   it is a change in whose policy the resolver is in.
2. **The model endpoint — the contract cannot name it.** `Open` takes a peer
   name. A peer name is a key in a peer table that maps to an address this
   tunneld dials and attests; `api.anthropic.com:443` is neither a peer nor
   attestable. There is no verb, no argument and no field anywhere in
   `attest/sandbox` that carries a destination. **The shim supplied a protocol
   the contract does not define**: every dial asks for the one peer `"b"` and
   writes `CONNECT host:port\n` as the first line of the stream. That line is
   the whole of the addressing, it is invented here, and it is the single
   biggest thing E2 says the contract lacks.
3. **`net.Conn` — the contract's `Stream` is not one.** `sandbox.Stream` is
   `Read`, `Write`, `Close`, `CloseWrite`. `net.Conn` additionally wants
   `LocalAddr`, `RemoteAddr`, `SetDeadline`, `SetReadDeadline` and
   `SetWriteDeadline`. The two addresses were fabricated (`spikeAddr`), which
   is harmless. **The three deadlines return `nil` and do nothing, which is
   not**: `net/http` and `crypto/tls` both set deadlines to enforce timeouts
   and to interrupt a blocked read when a context is cancelled, and both
   believe the shim. Behind this contract an agent has no I/O timeout and a
   cancelled request cannot free the goroutine waiting on the stream. The
   contract carries the *end* of a stream in each direction and nothing about
   *when*.
4. **HTTP/2 — the client silently stops using it.** An `http.Transport` with a
   `DialContext` of its own does not configure HTTP/2 unless
   `ForceAttemptHTTP2` is set, and E1 ran over HTTP/2. It is set here, so both
   experiments are comparable; had it been left alone, moving an agent behind
   the contract would have quietly changed its wire protocol and the number of
   streams it opens.

And two that did not break, recorded because the ticket asks:

5. **The tool fetch — same path, no new problem.** `fetch_url` goes through the
   same client, so it is the second `Open` and the exit's second `net.Dial`.
   The 20 KB of RFC 8446 came back over the tunnel unchanged.
6. **File writes — untouched, because they are outside the contract.**
   `write_file` is `os.WriteFile` and the contract has no file verb at all: `f`
   is a field in the document that is pushed and nothing in the path between
   the agent and the disk ever sees it. Everything in E1's path list —
   `summary.txt`, the trust store, the resolver's files — is exactly as
   unconstrained behind the contract as in front of it.
7. **`CloseWrite`, end-of-file and keep-alive — no interaction.** One `Open` is
   one stream and one TCP connection at the exit, and HTTP/2 kept all three
   model requests on the first. The stream ends when the client closes it, the
   exit's `io.Copy` returns a clean `<nil>`, and the half-close is carried each
   way. The thing to note is what the exit cannot tell: `SOCK_STREAM` and this
   contract both carry "the stream ended" and not "why", so an exit has no way
   to distinguish a peer that finished from a peer that gave up — which is
   ticket 22's own finding about the pump, arriving here from the other side.

## Two further things the run showed

- **The exit is not told who it is serving.** `Attested.Peer` was `""` on every
  accepted stream, because B's peer table is empty and an accepted connection
  arrives from an ephemeral port — a normal state, by the contract's own
  documentation. What the exit had was the vendor, the measurement
  (`1111…`, A's `imageA`) and the policy digest. None of those says anything
  about the destination in the `CONNECT` line, so an exit that wanted to check
  the one against the other has nothing to check with.
- **A sandbox built on `sandbox.Null` cannot enforce a policy even in
  principle.** `Null.Apply` keeps a `Record` — format, version, length, digest
  — and drops the bytes. There is no accessor for the document that arrived.
  Anything that wants to act on `n` has to implement `sandbox.Sandbox` itself
  rather than compose the null one, which is a fact about the code and not
  about the design: the contract hands `Apply` the full bytes.

## What this means for the ticket

The contract carried the agent, so the gVisor tickets keep their shape. What
the definition of done now has to decide is where the four missing things go:
a destination in `Open` (or a second verb), deadlines on `Stream`, a
`net.Conn`-shaped adapter somebody owns, and whether a sandbox is allowed to
read back the policy it acknowledged.
