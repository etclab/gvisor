# RQ5's six components, as far as loopback can speak to them

The paper names six remote-cost components (`evaluation.tex:764-771`, quoted at
`paper-vs-design-27sec.md:212`): **guest execution overhead**, **attestation
acquisition**, **attestation verification**, **establishment of the attested
channel**, **installation and binding of `P`**, and **capability release**.

This file is what the *loopback* runs can put in that table and, for three of the
six, why they can put nothing. The hardware numbers — the ones that make four of
these six real — come from the two-guest TDX runs and are another agent's, and
nothing here is a substitute for them. **Two of the six must not be filled in
from this directory at all**, and saying so is the point of writing it down.

Sources: `20260918-160939/` (four `agent-probe` sandboxes, this directory) and
`../spikes/E4/20260918-161409/` (four Claude Code sandboxes). Nine pushes were
made between them: eight landed and one — the widening — was refused. The platform in both is
`attest/internal/snpfake` with a fixture verifier, in the test's own process,
over `127.0.0.1`.

## The table

| # | component, as the paper names it | what loopback measures | n | range | median |
|---|---|---|---:|---|---|
| 1 | guest execution overhead | **nothing.** See below. | — | — | — |
| 2 | attestation acquisition | **nothing.** See below. | — | — | — |
| 3 | attestation verification | **nothing.** See below. | — | — | — |
| 4 | establishment of the attested channel | a pusher's cold `Open` on the fake platform: dial, both sides' verdicts, the push and its ack, all together | 9 | 38–123 ms | 75 ms |
| 5a | installation and binding of `P` — the push round trip as the sandbox's side sees it | `Host.Apply`: the contract socket, the helper, urpc, the sentry and back | 9 | 2.014–65.721 ms | 38.7 ms |
| 5b | installation and binding of `P` — the whole of it inside the sentry | `Policy.Narrow`: parse, canonicalise, subset check, swap, record | 8 | 589.7 µs–2.696 ms | 1.109 ms |
| 5c | installation and binding of `P` — the part a running workload is exposed to | the table swap alone (`NarrowTunnel` plus the boot-side table) | 8 | 87.9–884.8 µs | 172.2 µs |
| 6a | capability release — first attach | `runsc` starting to the helper being on the contract socket | 7 | 130 ms–2.138 s | 165 ms |
| 6b | capability release — the first stream | `tunnel_open` (the exit accepting) to `first_connect` (the exit answering `OK`) | 7 | 11–14 ms | 13 ms |
| 6c | capability release — first byte back | `first_connect` to `first_byte` | 7 | 17–44 ms | 20 ms |

## Why three rows are empty, and must stay empty here

**1, guest execution overhead.** There is no measured guest. Both harnesses run
`runsc` on the workstation with `--platform=systrap`, outside any TEE, and the
tunnelds are goroutines in the test process. A number taken here would be a
number about this laptop-class host's scheduler, and quoting it as guest
execution overhead would be quoting the absence of the thing being measured.
Spike E2 has the one execution-overhead number this ticket produced that means
anything — the exec sink's decision costs about five microseconds and the
`PointExecve` it needs about four percent of a process start — and that is a
sentry cost, not a guest one.

**2 and 3, attestation acquisition and verification.** There is no attestation.
`fixture.SNPPlatform` builds evidence from `internal/snpfake` and
`fixture.VerifierTrusting` admits it; no `SEV-SNP` report is requested from any
hardware, no VCEK is fetched, no certificate chain is walked and no collateral
is consulted. The 38–123 ms in row 4 is a QUIC handshake plus a fixture's
arithmetic and **is not an attestation cost**. The hardware runs are where rows
2 and 3 come from and there is nothing here to interpolate from.

Row 4 is kept, with the same warning attached: what it measures is the *shape* of
establishment — a dial, two verdicts and a push, in that order, in one call — and
not its price. It is useful as the denominator the hardware number replaces, and
for nothing else.

## What the numbers are, run by run

The `agent-probe` runs (`20260918-160939/`):

| run | cold Open | handshakes | `Apply` at `a` | `Policy.Narrow` | table swap | attach | tunnel_open | first_connect | first_byte |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| off-policy | 75 ms | 3 | 38.723 ms | 2.696 ms | 511.9 µs | 130 ms | never | never | never |
| on-policy | 114 ms | 2 | 56.883 ms | 740.2 µs | 87.9 µs | 165 ms | 552 ms | 566 ms | 599 ms |
| narrowed, P0 | 51 ms | 1 | 3.901 ms | 894.4 µs | 106.3 µs | 2.138 s | 1.519 s | 1.530 s | 1.574 s |
| narrowed, P1 | 66 ms | 1 | 3.285 ms | 589.7 µs | 137.6 µs | — | — | — | — |
| narrowed, widening | 38 ms | 1 | 2.014 ms | refused | — | — | — | — | — |
| killed | 70 ms | 3 | 41.824 ms | 2.314 ms | 142.4 µs | 149 ms | 391 ms | 404 ms | 424 ms |

The Claude Code runs (`../spikes/E4/20260918-161409/`):

| run | cold Open | handshakes | `Apply` at `a` | `Policy.Narrow` | table swap | attach | tunnel_open | first_connect | first_byte |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| governed-1 | 99 ms | 3 | 52.443 ms | 2.052 ms | 884.8 µs | 163 ms | 2.640 s | 2.653 s | 2.670 s |
| governed-2 | 123 ms | 3 | 65.721 ms | 824.4 µs | 201.9 µs | 185 ms | 2.557 s | 2.570 s | 2.590 s |
| governed-3 | 78 ms | 4 | 35.231 ms | 1.323 ms | 530.8 µs | 201 ms | 2.397 s | 2.408 s | 2.428 s |
| unrestricted | — | — | — | — | — | — | 2.418 s | 2.429 s | 2.446 s |

## Three things the spread says

**`Apply` at `a` is bimodal and the mode is not noise.** The first push into a
sandbox costs 35–66 ms and every later push into the *same* sandbox costs
2.0–3.9 ms. The difference is the first dial of the sentry's control socket in
that sandbox's life: the helper is given the path and dials it per apply, never
at startup (`runsc/sandbox/sandbox.go`), so the first `Policy.Narrow` pays for a
connection nothing has made yet. Spike E1 measured the same shape over
twenty-four pushes — 2.349 ms minimum, 3.506 ms median, one 42.656 ms sample and
it was the first — and the adapter check saw it a third time. **A table of
push costs that quotes one number is quoting whichever of the two it happened
to sample.** The hardware runs will have exactly one push per guest and will
therefore only ever see the cold one.

**The sentry's own half is the small half.** `Policy.Narrow` is 0.59–2.70 ms and
the table swap inside it is 88–885 µs, against 38 ms at the boundary for a first
push. What costs is the crossing — the contract socket, the helper's callback
goroutine, a fresh `client.ConnectTo` on the control socket, urpc — and not the
enforcement. That is E1's finding restated on a different workload and it is the
one to carry into the record: the price of installing `P` is the price of the
process boundary it has to cross.

**Capability release is dominated by the workload, not by the arrangement.**
`tunnel_open` is 391 ms into a run for `agent-probe` and 2.4–2.6 s for Claude
Code, and the difference is entirely how long a 232 MB Node runtime takes to
decide to open a socket. What the arrangement costs once asked is rows 6b and
6c: 11–14 ms from the exit accepting a stream to the exit answering `OK` for the
`CONNECT` on it, and a further 17–44 ms to the destination's first byte — and
both of those are on loopback, so the second is a real TLS handshake to the
public internet and the first is not comparable to anything a WAN would do.
`attach` (row 6a) is the helper's own startup: 130–201 ms in six of the seven
runs that measured it and 2.138 s in the seventh, on the same machine, which is the variance a
one-second liveness pulse has to tolerate and does.

## What the hardware runs must add, and must not take from here

Rows 1, 2 and 3 in full. Row 4 replaced, not adjusted: a real `Open` is a real
report acquisition and a real verification with collateral, and the loopback
number shares nothing with it but the order of its steps. Rows 5 and 6 are worth
comparing against — the sentry-side halves (5b, 5c) should be within noise of
these, because the same code does the same work whether or not the guest is
measured, and if they are not, that difference *is* guest execution overhead and
is row 1's number arriving by the back door.
