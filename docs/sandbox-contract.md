# A contract between tunneld and its sandbox

Ticket 22. Tunneld is now the network boundary for whatever sandbox sits beside it, in its
process or in another one, and the boundary is three verbs wide: open a stream to a named peer,
accept an incoming stream with the peer's attested identity on it, receive a pushed policy and
acknowledge it. The echo exercise Milestone 3 runs is the first client of it. Nothing under
`pkg/` or `runsc/` changed, and neither did the exchange framing: an exchange's bytes are what
they were before this ticket existed.

**Contract version 2** is ticket 23's amendment to the Go interface and nothing else: `Stream`
gained the three `net.Conn` deadlines, and the wire protocol, the local socket protocol and the
four `Attested` strings are exactly what version 1 made them.

**Contract version 3** is ticket 26's, and it is one message: `alive`, from the sandbox, with no
reply, carrying the digest of the policy it is enforcing. It is the verb version 2 did not have
for the present tense — an acknowledgement is a claim about the past, and ticket 23 measured
exactly how short a past that is. Nothing else changed: the three verbs, the stream, the
descriptor, the pump and the four `Attested` strings are what version 1 made them.

**In one sentence:** a sandbox sees no evidence, no key and no trust decision — it gets a stream
or an error, and a policy or nothing — and the shape of the contract is fixed by the thing that
cannot cross a process boundary, since a QUIC stream is not a kernel object (spike E1) and what
a sandbox in another process receives is therefore one end of a socketpair that tunneld pumps.

The two spikes this stands on are recorded under `docs/snp/evidence/ticket22/spikes/`: **E1**,
which established that stream-as-descriptor is impossible and measured what the socketpair costs
(40–80 µs of added round-trip latency, under a quarter of single-stream bulk throughput), and
**E2**, which established that one unchanged framed `Exchange` carries a policy push and its
acknowledgement in under a millisecond, and which found the manufactured-`Channel` panic this
ticket closes.

---

## The invariant

> A sandbox sees no evidence, no key and no trust decision. It gets a stream or an error, and a
> policy or nothing.

Every export in `attest/sandbox` is chosen to make that checkable rather than aspirational:

| what a sandbox gets | what it does not get |
| --- | --- |
| a byte stream, with an end in each direction | the evidence, which stays below the vendor seam |
| four public strings naming the peer | any key; tunneld's identity key never leaves `attest/ratls` |
| an error saying the stream did not happen | the reason a peer was refused — a refusal is an aborted handshake and an operator's log line, and there is no stream for it to arrive on |
| the bytes of a pushed policy | the reference value that admitted the peer, which is a fact about this side's allow-list |

The import graph says it too: `attest/sandbox` imports nothing from `gvisor.dev/gvisor/attest`
— only the standard library and `golang.org/x/sys/unix`. Package `tunneld` is what adapts, and
the two guard tests in `attest/cmd/tunneld` still hold, so none of this is inside the launch
measurement by accident.

## The interface

`attest/sandbox/sandbox.go`:

```go
type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type Network interface {
	Open(ctx context.Context, peer string) (Stream, error)
	Accept(ctx context.Context) (Stream, Attested, error)
}

type Sandbox interface {
	Network
	Apply(ctx context.Context, policy []byte) error
}
```

`Network` (`sandbox.go:188`) is tunneld's half and `*tunneld.Tunneld` implements it
(`attest/tunneld/sandbox.go:62`, `:84`). `Sandbox` (`sandbox.go:206`) is the whole contract;
`*sandbox.Null` implements it in process (`null.go:46`) and `*sandbox.Host` implements it with a
process boundary in the middle (`host.go:46`). A `context.Context` is on each method because
`Accept` blocks and Go has one way of saying so; nothing else was added to the three verbs.

`Apply` returns `nil` for an acknowledgement and an error for a refusal. Refusals of the
envelope wrap `sandbox.ErrPolicyRefused` (`policy.go:54`). Its caller is a peer: a delegator
pushes the policy over the tunnel once that peer has been admitted, and the `nil` or the error
here is what becomes the acknowledgement or the refusal on the wire — `docs/policy-push.md`.

`CloseWrite` is the half that makes `Stream` more than an `io.ReadWriteCloser`, and it is not
decoration: every protocol a sandbox will run over a stream ends a request by saying it has
finished sending, and the exercise's own round trip is exactly that
(`attest/cmd/tunneld/exercise.go`, `roundTrip`). One end of a socketpair satisfies `Stream` as
it stands — `*net.UnixConn` already has `CloseWrite` — and so does package tunnel's raw stream
(`attest/tunnel/tunnel.go:554`), and neither had to learn about the other.

**The three deadlines are ticket 23's**, and they are there because the first thing anybody puts
on a stream is a protocol somebody else wrote. Spike E2
(`docs/snp/evidence/ticket23/spikes/E2`, break #3) put an agent's `http.Transport` behind this
contract and had to fake `net.Conn`'s deadlines as no-ops: `net/http` and `crypto/tls` are both
`net.Conn` consumers, and each sets deadlines to bound a read or a write that may otherwise
never finish. Both believed the shim, so an agent behind the contract had no I/O timeout at all:
a cancelled request still ended, because the transport closes the connection on cancellation,
but nothing set by `SetDeadline` ever fired, and a server listening on such a stream would have
lost its read and write timeouts the same silent way. Neither implementation had to learn anything to fix that: `*net.UnixConn`
has had the three methods since before this package existed and so has `*quic.Stream`, which
`tunnel.Stream` now delegates all three to (`attest/tunnel/tunnel.go:590`). The interface was
hiding a capability both ends already had rather than adding one they did not — which is exactly
what separates a deadline from a reset, which neither end can deliver. **The wire is unchanged,
the local socket protocol is unchanged, and the four `Attested` strings are unchanged**: a
deadline is a fact about one side's own blocked call and nothing about it goes anywhere.

## What `Attested` carries, and why nothing more

`sandbox.go:154`. Four strings, and that is the whole of what a sandbox is told about who is at
the other end of a stream:

| field | what it is |
| --- | --- |
| `Peer` | the name the peer table gives this peer, or empty |
| `Vendor` | `amd-sev-snp` or `intel-tdx` |
| `Measurement` | the peer's launch measurement in lowercase hexadecimal — the SEV-SNP launch digest, or RTMR2 for TDX |
| `PolicyDigest` | the digest of the signed policy the peer presented, lowercase hexadecimal |

All four are public. The measurement and the digest are in the reference value sets on both
sides' config devices, which are untrusted media by construction (ADR-0004), so a sandbox
holding them holds nothing it could not have read off a disk somebody else wrote. They are at
full width and never abbreviated, because the whole use of either is comparing it with a number
an operator wrote down elsewhere and a truncated identity is one an attacker gets to choose
collisions in.

`Peer` is empty more often than the other three, and that is a normal state rather than a
failure. An accepted connection arrives from an ephemeral source port, so the peer table can
only be matched on the address: exactly one entry matching gives the name, and none or several
give nothing (`attest/tunneld/sandbox.go:210`). Naming binds to nothing (spec, *Reference values
and naming*) — what identifies the peer is the measurement and the digest sitting beside the
name in the same value.

Where the measurement comes from is worth one paragraph, because it is the only field that is
not on the certificate. The verdict is reached inside the TLS handshake, in
`ratls.PeerVerifier`, which hands it to nothing: a refusal goes to the refusal log and an
acceptance goes nowhere, because until a sandbox had to be told who opened a stream, nothing
above needed it. The listening side asks nothing further of a peer — whom this sandbox *dials*
is its own policy's business, and that check is on the dialing configuration — so its admission
hook was free, and tunneld uses it to keep the verdict rather than adding a second way for one
to leave the handshake (`verdictBook`, `attest/tunneld/sandbox.go:252`). It is keyed by the
caller-supplied bytes the evidence was acquired over, which is a hash over the binding context,
the policy digest and the public key TLS proved possession of, and which
`attest.Verification.Verify` has already refused the peer unless the evidence carries precisely
it (`attest/verification.go:142`). Looking a connection's certificate up under that key
therefore finds the verdict for that certificate or finds nothing. Nothing is re-verified and
nothing is decided a second time.

## The stream, and the four bytes that mark it

`attest/tunnel` exposed one framed `Exchange` per stream and nothing else. It now also has a raw
stream: `Conn.OpenStream` (`tunnel.go:605`), `Conn.AcceptStream` (`tunnel.go:623`) and the
`Stream` type over them (`tunnel.go:554`), whose `CloseWrite` is QUIC's own FIN and whose
`Close` is that plus a `STOP_SENDING`.

The two kinds are told apart by the four bytes every stream opens with, and by nothing else. An
exchange opens with a big-endian payload length, which is at most `maxFramePayload`
(`tunnel.go:348`, 16 MiB), so **every value above that bound was already a framing violation** —
"peer declared N bytes, over the maximum" — and exactly one of them is now a stream kind
instead: `rawStreamMarker = 0x52415731`, `"RAW1"` (`tunnel.go:375`).

That is the whole of the wire change, and it is a change no existing exchange can see. A sender
still writes a length it could always have written and a receiver still reads it the same way,
so an exchange is byte-identical to what it was; what changed is only the fate of a peer that
writes `0x52415731` where a length belongs, which was a torn-down connection and is now a stream
the sandbox may accept. The one test that puts an oversized length on the wire uses
`math.MaxUint32` (`attest/tunneld/framing_test.go:150`) and still gets its framing violation.

Only the side running `Conn.Serve` recognises the marker (`tunnel.go:679`), which is the side
that accepted the connection, so a raw stream is opened by the dialer and accepted by the
listener exactly as an exchange is; bytes then flow both ways on it. A marker arriving where an
exchange *response* was expected is still a framing violation, because `Conn.Exchange` reads a
frame and nothing else. Reading the four bytes is the first thing done to any stream either way,
so neither kind pays for the other's existence.

Above that, `Channel.OpenStream` (`attest/tunneld/sandbox.go:101`) is `Channel.Exchange`'s
neighbour: same cache, same re-dial, same re-attestation before further use. `Tunneld.Accept`
takes streams from every accepted tunnel in the order they arrive, which is why it is on the
tunneld rather than on a channel — a channel is a handle on a peer this sandbox dialed, and an
incoming stream belongs to a peer that dialed it.

**The manufactured channel, closed.** `Channel` is an exported struct whose fields are all
unexported, so `&tunneld.Channel{}` compiles, and spike E2 recorded that calling `Exchange` on
one panicked with a nil pointer dereference rather than refusing. It now returns
`tunneld.ErrNoTunneld`, and so does `OpenStream`. No bytes ever left the process either way;
what changed is that it says so.

## The local socket protocol

For a sandbox in another process. Tunneld listens on an `AF_UNIX SOCK_STREAM` socket
(`sandbox.Listen`, `host.go:70`, mode 0600, the directory created if missing, a socket left by a
previous run replaced and anything else at the path refused). Every message is a four-byte
big-endian length and that many bytes of JSON — the same framing package tunnel uses on a
stream, and deliberately the dullest thing that works.

| message | direction | carries |
| --- | --- | --- |
| `{"id":1,"type":"open","peer":"b"}` | sandbox → tunneld | the peer's name |
| `{"id":1,"type":"stream"}` | tunneld → sandbox | **one descriptor**, in `SCM_RIGHTS` |
| `{"id":2,"type":"accept"}` | sandbox → tunneld | nothing; blocks until a peer opens a stream |
| `{"id":2,"type":"stream","attested":{…}}` | tunneld → sandbox | **one descriptor**, plus the four `Attested` fields |
| `{"id":n,"type":"error","error":"…"}` | tunneld → sandbox | tunneld's own sentence, unchanged |
| `{"id":7,"type":"apply","policy":"<base64>"}` | tunneld → sandbox | the opaque policy bytes |
| `{"id":7,"type":"ack"}` | sandbox → tunneld | the acknowledgement |
| `{"id":7,"type":"refusal","error":"…"}` | sandbox → tunneld | the sandbox's refusal |
| `{"id":0,"type":"alive","digest":"<64 hex>"}` | sandbox → tunneld | the digest of the policy in force — **no reply** (v3) |

The last of them is the only message here that is neither a request nor a reply, and its id is 0
because it numbers nothing: it goes nowhere near either side's reply table, and a reply table
that grew a slot per second would be the one part of this socket that leaked. See *Liveness*,
below.

Requests travel in both directions — the sandbox asks for streams, tunneld pushes policy — so
each side numbers its own requests and a reply carries the id of the request it answers. The two
id spaces never collide, because the types say which direction a message came from: nothing the
sandbox sends is a type tunneld sends. Requests may be outstanding concurrently and are answered
as they finish; in particular an `apply` sent while an `accept` is waiting for a peer is
answered without waiting for it, which the test asserts by pushing exactly there.

A declared length over 4 MiB is refused (`socket.go:101`) for the same reason package tunnel
bounds a frame. `error` messages carry tunneld's own text — an unknown peer, an unreachable one,
a handshake that did not complete — which is the same text an in-process sandbox is handed; no
refusal reason travels in it, because none reaches the contract in the first place.

**The descriptor.** A `stream` reply is written with one `sendmsg` carrying one end of a
socketpair in its ancillary data; tunneld keeps the other end and pumps. This relies on one
guarantee about unix stream sockets: the kernel never merges bytes written with descriptors
attached into a read of bytes written without them, so a receiver that reads a four-byte header
gets that message's descriptor with it and never the next message's (`wire.readHeader`,
`socket.go:198`). A descriptor sent the other way is closed on arrival: descriptors travel one
way.

The client half is `sandbox.Dial` (`client.go:62`), which is a `Network`, so a sandbox written
against the in-process contract runs unchanged over the socket. That is the property the whole
boundary exists for, and the composition is three lines:

```go
var null *sandbox.Null
c, err := sandbox.Dial(path, func(ctx context.Context, p []byte) error { return null.Apply(ctx, p) })
null = sandbox.NewNull(c, logf)
```

In the command, `-sandbox-socket` turns it on; the conventional path is
`/run/tunneld/sandbox.sock` (`attest/cmd/tunneld/nullsandbox.go:48`). It is **off by default**,
which is a deliberate departure from "a path under the run directory": a tunneld with nobody to
attach would otherwise create a socket at every start, including inside the measured image where
there is no second process, and every recorded scenario would carry a line about it. With a
socket configured the command's own echo stands down and the attached sandbox accepts, because
there is one queue of incoming streams and a sandbox in another process is *the* sandbox.

## The pump

`sandbox.pump` (`socket.go:278`), the shape `fdhandoff.go` proved in E1: two `io.Copy`
goroutines, and a half-close carried at the end of each.

```
socketpair EOF  →  Stream.CloseWrite()   (a FIN on the QUIC stream)
stream EOF      →  UnixConn.CloseWrite() (end-of-file for the sandbox)
```

Both, and not one: the sandbox finishing what it had to say must reach the peer, or the peer
waits for a request it has already received; the peer finishing its answer must reach the
sandbox, or the sandbox waits for a response it already has. A copy loop that moved only bytes
would deadlock both sides of every request-response protocol anybody would put over this. When
both directions have ended, both ends are closed.

**What the pump cannot carry is a reset.** `SOCK_STREAM` has no signal for one, so a peer that
cancelled a stream and a peer that finished it look alike from inside a sandbox in another
process (E1, *What this decides for the contract*). The contract does not pretend otherwise: it
carries the end of the stream in each direction and leaves "why it ended" out, rather than
inventing an in-process signal that cannot be delivered out of process. A protocol over this
that needs to tell a truncated answer from a complete one has to say so in its own bytes.

The cost is E1's and is paid per stream: one extra hop each way, ~40–80 µs of added round-trip
latency, and ≲25 % of single-stream bulk throughput. There is no cheaper variant to hold out
for, because the bytes are in tunneld's userspace either way.

## The subset check

A delegation narrows: a node pushed P0 and pushing P1 onward may hand on no more than it was
given, and until ticket 26 nothing in this tree checked it (the finding is recorded at
`attest/cmd/agent-probe/twohops_test.go:35`). The check is now the contract's, in
`attest/sandbox/policy.go`, because the rule is the format's and not one sandbox's:

* `sandbox.Atoms(policy)` — the grant set, sorted and deduplicated, in ticket 23's grammar:
  `net:<host>:<port>`, `net:<host>` (every port), `read:<path>`, `write:<path>`, `run:<path>`,
  `run:sha256:<hex>`. A CIDR is refused, because every check this design makes on a destination
  is against the name that was asked for and a name is in no CIDR.
* `sandbox.Widening(prev, next)` — the atoms of `next` that `prev` does not grant, grouped by
  component. It has no notion of a first push: a nil `prev` is the empty grant, since the two
  are indistinguishable after `Atoms` and a checker that guessed would wave through exactly the
  push that widens from nothing.
* `sandbox.CheckNarrows(prev, next)` — the document-level form, refusing with
  `sandbox.ErrPolicyRefused` and the sentence `it widens n by [...]`, naming the component.

The set and not the document is compared, for the reason ticket 23 gave: two documents naming
the same hosts in a different order are the same grant. The Deno sandbox keeps its own atomiser,
because three of its rules are facts about Deno — it has an `e` letter the policy format has
not, it refuses a digest it has nowhere to put, and it refuses a host its flag parser would
refuse after the exec rather than before it.

## Liveness

An acknowledgement is a claim about the past. Ticket 23 measured how short a past: the ack left
`Apply` 1.856 ms after `exec.Start`, the workload was dead at 43 ms, and the tunnel was still up
— going on asserting something the sandbox no longer believed, with no verb in the contract for
saying so. Version 3 is that verb.

> A sandbox that has acknowledged a policy sends `alive` with that policy's digest every
> `sandbox.DefaultPulse`, until it closes. Liveness is lost when an attachment that acknowledged
> has sent none for `sandbox.DefaultMisses` consecutive intervals, sends one whose digest is not
> the one that was pushed, or closes its socket.

The constants are **1 s** and **3**, and spike E3 (`docs/snp/evidence/ticket26/spikes/E3/`) is
why. A pulse costs 30 µs to send and 255 µs of CPU to receive at one hertz — 0.026 % of one core
— so cost decides nothing and must not be argued as though it did. The worst lateness of a pulse
over a minute was 2.865 ms on a machine at load average 24, so measured jitter would justify two
misses; the third is bought by the transients a one-minute sample does not contain (a guest
paused, a sentry stalled) and by what a false positive costs, which is a tunnel closed and a
handshake burned. Teardown, measured ten times per case: **≤250 ms** when the socket closes or
the digest does not match, and **2.10–3.25 s** when the sandbox simply goes quiet, the spread
being how old the last pulse already was.

**Who sends it.** A client that acknowledges starts pulsing the SHA-256 of exactly the bytes it
acknowledged, which is the number tunneld computed over the bytes it pushed and the number the
null sandbox already prints. A sandbox that enforces something *other* than those bytes — a
supervisor forwarding a policy to a sentry that answers with the digest it accepted — says so
with `Client.Alive(digest)`, and the last thing it said is what it pulses.

**Who watches, and who does not.** Only `sandbox.Host` implements the optional interface
(`sandbox.Live`: one method, `Watch(ctx, digest) <-chan error`), so only a sandbox across a
process boundary is watched. A sandbox in tunneld's own process — the null one, and the Deno one
— has no liveness question: it *is* the process, and a caller wondering whether it is still
running has been answered by the fact that it asked. Tunneld starts a watch after a push it
acknowledged and closes that tunnel when the watch fires, under the taxonomy's eleventh reason
(`docs/policy-push.md`).

**Every attachment that acknowledged must be live**, for the same reason `Host.Apply` returns the
first refusal rather than the last: two sandboxes on one socket are two things enforcing the
policy, and one of them stopping is the policy no longer being enforced. In a guest that pair is
the agent and the exit, which `agent-probe` runs as two clients on one socket, and the test
watches both acknowledge and both pulse.

**The workload's exit ends liveness, and it is the fast case.** The workload ends, the sandbox's
client closes, the attachment goes, and the loss is reported at the next quarter-pulse — which
is the 250 ms above and not the three seconds. The case the ticket was written for is the quick
one.

**What a sandbox that refused is not.** A watch is over the attachments that acknowledged. One
that refused claimed nothing it could stop claiming, so it is not watched.

## The null sandbox, and the exercise inside it

`sandbox.Null` (`null.go:46`) passes streams through to the `Network` it was given and records
the policies pushed at it: format, version, length and the SHA-256 of exactly the bytes that
arrived, one line per push —

```
SANDBOX applied format=policy version=1 bytes=69 sha256=8c1062e8310ede7c8b9c0ff20057b17681fa6d6f6e8b236535ae2bc75978cea4
```

— which is what makes "B acknowledged the policy A pushed" a claim a console transcript can
support: the digest on both sides is the same number, or the push carried something else. Since
ticket 22's other half that line is written when a peer pushes, beside the delegator's own
`push policy … sha256=…` (`docs/policy-push.md`); the two numbers are the claim. It parses
nothing beyond the envelope and never looks at `n`, `f` or `x`.

It is not a placeholder for a sandbox that will do more. A sandbox is not where anything is
enforced in this design — enforcement is the netfilter rule set the signed policy implies
(`docs/policy-binding.md`) and the reference value set that admits a peer at all — so a sandbox
that records a policy and says it has it is the honest implementation of the contract.

**The envelope, checked at the boundary.** A pushed policy is opaque versioned JSON,
`{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}`. Tunneld reads two fields of it and
nothing else, before the sandbox is woken: `tunneld.PolicyChecked`
(`attest/tunneld/sandbox.go:121`) wraps the sandbox and refuses anything that is not
`policy`/version 1. `Tunneld.Attach` (`attest/tunneld/push.go:128`) is what puts a sandbox
behind that wrapper, so the check holds whichever one is beside this tunneld — the null one in
process, or a `Host` with another process behind it. Where the check runs is the point of it — an acknowledgement then means a
sandbox with *that* policy on every implementation of the contract, rather than meaning whatever
the sandbox beside a particular tunneld made of a document it could not read. Unknown fields are
ignored, which is the opposite of how this module loads its signed documents and deliberately
so: there an unknown field is a constraint the loader cannot see, and here the unknown fields
*are* the policy.

**The exercise maps onto the contract verb for verb.** It used to hold a `*tunneld.Channel`; it
now holds a `sandbox.Sandbox` and can see no tunnel at all.

| exercise, before | exercise, now |
| --- | --- |
| `establish`: `td.Peer(ctx, peer)`, timed | `box.Open(ctx, peer)`, timed, the stream given straight back |
| `exchange`: `channel.Exchange(ctx, request)` | `box.Open` → write → `CloseWrite` → read to end-of-file |
| the answering side: `Handler` on `tunneld.Config`, one framed exchange | `box.Accept` in `answer` (`nullsandbox.go:93`), one stream |

The figures keep their shape. An `Open` on the first pass is still the whole cost of admission —
no tunnel to that peer exists, so tunneld dials one and both sides judge the other's evidence —
and warm and concurrent exchanges are still one stream each on the tunnel that left behind. The
three `LATENCY` lines are unchanged field for field, which
`TestTheExercisePrintsTheSameThreeFiguresOverTheContract`
(`attest/cmd/tunneld/exercise_test.go`) asserts against the regular expressions a harness would
use. The framed `Handler` is still wired and still answers exchanges; what no longer reaches it
is the exercise.

One line was added to the console, at most once per distinct peer rather than once per stream:

```
SANDBOX stream from peer="<name>" vendor=amd-sev-snp measurement=<16 hex chars>… policy_digest=<16 hex chars>…
```

That is the whole of what a sandbox is told about who is at the other end, printed where the
only diagnostic surface a measured guest has can carry it (spec, user story 48).

## What proves it

| claim | where |
| --- | --- |
| a sandbox opens a stream to an attested peer, the other accepts it with the identity attached, and an exchange on the same tunnel still reaches the handler | `attest/tunneld/sandbox_test.go`, over the loopback harness with the fake platform |
| an ambiguous peer table names nobody, and the measurement is still right | same file |
| `Accept` is released when the tunneld closes, and closing twice is not a panic | same file |
| a manufactured `Channel` refuses rather than panicking | same file |
| tunneld refuses an unknown version before the sandbox sees it, and the null sandbox acks a version 1 blob | same file |
| a sandbox **in another process** opens, accepts with the identity, round-trips bytes both ways through the received descriptor, and answers two pushes | `attest/sandbox/socket_test.go`, which re-executes the test binary as the sandbox |
| the pump carries the end of the stream each way | same file |
| a sandbox in another process pulses the digest of what it acknowledged, and a sandbox that refused is not watched | same file, the liveness tests |
| a sandbox that is killed, that goes quiet, or that pulses another policy's digest is a policy no longer in force | same file, one test each |
| a widening push is refused component-wise and the refusal names which of `n`, `f` and `x` widened | `attest/sandbox/policy_test.go` |
| a tunnel whose sandbox stopped enforcing the pushed policy is closed, and one whose sandbox is in this process is not watched | `attest/tunneld/liveness_test.go` |
| the agent's sandbox and the exit's, two clients on one socket, both acknowledge and both pulse | `attest/cmd/agent-probe/liveness_test.go` |
| a push at a tunneld with no sandbox attached is refused rather than acknowledged | same file |
| a policy pushed **over the tunnel** reaches this contract's `Apply`, and what that returns decides the peer's tunnel | `attest/tunneld/push_test.go`, and `docs/policy-push.md` for the whole of it |
| a read deadline expires with `os.ErrDeadlineExceeded` on both implementations — the tunnel's raw stream, and the socketpair end a sandbox receives over the socket with tunneld's pump between it and the tunnel — the peer having sent nothing and the stream still open | `TestAReadDeadlineOnAStreamExpires` (`attest/tunneld/sandbox_test.go`), one subtest each |
| the exercise's three figures keep their shape | `attest/cmd/tunneld/exercise_test.go` |
| the measured binary still reaches no fixture, no fake and no `testing` | `attest/cmd/tunneld/importgraph_test.go`, `packaged_test.go`, unchanged |

`go test ./... -count=1` in `attest/` passes, `go vet ./...` is clean, and the same run under
`-race` passes for the three packages this touched.
`ripwire attest --quality-delta=32a18ba24..HEAD` reports `gating="0" stale="0"`, having gone
from 36 gating rows to 17 by two fixes in production code — `Channel.tunnelTo` and
`Channel.lost`, which took the preamble and the lost-tunnel postamble out of the channel's two
verbs — and by writing the new tests without cloning `internal/fixture`'s helper shape; the
remaining 17 are acked in `attest/.ripwire_quality_acks` with the reason, and are the idiom
collisions a second lifecycle beside tunneld's inevitably spells the same way across a package
boundary neither side may cross.

## What proves it on hardware

`docs/sandbox-contract-on-hardware.md` is this contract on two SEV-SNP guests: a policy
pushed over an attested tunnel and applied by the null sandbox at the far end, a second one
refused, and the egress ceiling refusing from inside each guest what the measurement says it
must. The recorded run is `docs/snp/evidence/ticket22/`.

## What is not built

- ~~**Nobody pushes a policy yet.**~~ Built, in ticket 22's other half: a delegator pushes on
  every tunnel it dials, once, and hands out no stream until the peer's sandbox has
  acknowledged it. The wire, the refusal reason and the ordering are `docs/policy-push.md`;
  what this contract contributes is `Apply` and the envelope, both unchanged.
- **Nothing enforces a policy.** The null sandbox records and acknowledges. `n`, `f` and `x` are
  unparsed by every line of code in this tree.
- **No reset signal.** See the pump, above.
- **A destination is not part of `Open`.** `Open` takes a peer name, and a peer is a sandbox
  rather than an exit: a name in the peer table maps to an address this tunneld dials and
  attests, and `api.anthropic.com:443` is neither a peer nor attestable. There is no verb, no
  argument and no field in `attest/sandbox` that carries a destination. An agent that needs the
  public internet from behind this contract needs an exit sandbox at a peer, and what it names to
  that exit is a protocol *above* the contract — E2's shim invented `CONNECT host:port` as the
  first line of the stream, and the contract neither defines that line nor sees it. Ticket 23
  did not change this.
- ~~**No liveness signal from sandbox to tunneld.**~~ Built, in ticket 26: the `alive` message,
  one a second, carrying the digest of the policy in force, and a tunnel closed when it stops.
  See *Liveness*, above. What that bullet measured — the ack at 1.856 ms, the workload dead at
  43 ms, the tunnel still up — is now bounded at 250 ms for a workload that exits and at 3.25 s
  for a sandbox that goes quiet without closing.
- **Liveness is a heartbeat and not a proof.** An `alive` message says what the sandbox says it
  is enforcing. It is trusted for arriving on a socket inside a measured guest, exactly as a
  pushed policy is trusted for arriving over an attested tunnel, and a sandbox that lied about
  its digest would be a sandbox lying about its own enforcement, which the measurement and not
  the contract is what stands behind.
- **The loss is found by polling, at a quarter of a pulse.** A closed socket and a mismatched
  digest are known the instant they arrive and are rounded up to the watch's 250 ms tick. Waking
  the watcher on each pulse would make both sub-millisecond; it is one loop against a fan-out
  from every attachment to every watch, and 250 ms is already an order of magnitude inside the
  miss path.
- **Ticket 23's record is `docs/agent-on-the-contract.md`.** What the two bullets above
  were measured by: a real agent on this contract, what Deno could enforce of a pushed
  policy and what it could not, the timings per hop over two delegation hops, and whether
  `(N, F, X)` as typed is enough for the policy track.
- **No runsc sandbox.** The socket exists and a forked test binary speaks it; the sandbox that
  will consume these descriptors as FD-backed endpoints is Milestone 4's.
