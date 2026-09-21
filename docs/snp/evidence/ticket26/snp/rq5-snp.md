# RQ5 on SEV-SNP hardware: the six remote-cost components, as the paper names them

The paper's six (`evaluation.tex:764-771`, quoted at `paper-vs-design-27sec.md:212`)
are guest execution overhead, attestation acquisition, attestation verification,
establishment of the attested channel, installation and binding of `P`, and
capability release. This file is what two measured SEV-SNP guests said about each
of them, from the two boot pairs whose kill path worked: `run-4/` (73 of 73) and
`run-5/` (71 of 73, two console lines lost). Every number is read off a console
this directory contains, and the method for each says exactly which lines.

Nothing here is an average over a benchmark. Each component was observed two or
four times — two guests, two pairs — and the spread is given as the range. Two
components are bounded rather than measured and say so.

| # | component | SEV-SNP, this host | how it was read |
|---|---|---|---|
| 1 | guest execution overhead | **0.496 – 0.622 s** (4 observations) | runsc's own spawn timestamp, out of the debug log's filename, to the sandbox's first `tunnel dns:` — i.e. to the first syscall the workload made that left the sandbox |
| 2 | attestation acquisition | **0.50 – 0.51 s**, not separately timed | `init: uptime` before `running /usr/bin/tunneld` to `init: uptime` after `the sandbox socket is up`: the link, the report interface, the evidence, the chain, the listener and the socket together. tunneld prints no duration for the acquisition alone on this path; the TDX path does (`SELFCHECK acquired … in …`) |
| 3 | attestation verification | **1 verifier call per admission**, inside (4) | `LATENCY … verifier_calls=1`; the guest prints no separate verdict duration, so the figure that exists is (4), which contains it |
| 4 | establishment of the attested channel | **109.2 ms and 124.7 ms** (2 observations) | `tunneld: LATENCY pass=1 peer=guest-a kind=establish ms=… attempts=1 verifier_calls=1` — one `Open` on a peer no tunnel existed to, so it is the dial, both sides' evidence, both verdicts and the handshake |
| | the same thing seen from inside the sandbox | **61.8 – 159.7 ms** (4 observations) | the first `tunnel attach: … ok in …` on each guest: the sentry asking tunneld for a stream to a peer it had no tunnel to. Later attaches on the warm tunnel are **5.6 – 23.3 ms** (median of 30) |
| 5 | installation and binding of `P` | **965 µs – 1.314 ms**, of which the table swap is **67 – 173 µs** (2 observations) | `tunnel narrow: applied in …, of which the table swap was …` (`run-5/`, `policy.go:230`). This is the sentry's half: parse, subset-check, build and swap, with the workload running throughout |
| | the contract round trip that carries it | **not timestamped on hardware** | tunneld's `push policy …` and `SANDBOX applied …` lines carry no clock. The measured round trip is the workstation's: **25.2 ms** for the first push in a sandbox's life and **4.2 ms** for the second (`../adapter-check/notes.md`), and 24 pushes in spike E1 |
| 6 | capability release | **49.4 ms and 148.1 ms** (2 observations) | the sentry's `tunnel narrow: applied` timestamp to the first `tunnel attach: … ok` after it: from the policy being in force to the workload holding a socket to a permitted name |

## What each row means, and what it does not

**1. Guest execution overhead.** What is measured is a sandbox on the adapter
starting inside a measured guest and reaching the workload's first outward
syscall: 0.572 s and 0.496 s in `run-4`, 0.589 s and 0.622 s in `run-5`. The
comparison the brief asks for is ticket 24's bare workload on this same host and
the same runsc: E3 ran a bundle whose whole job was `uname -a` and an exit, with
none of the adapter's flags and **without** `--debug`, and init's clock put the
whole of it — launch to exit — at **0.85 s** (guest A) and **0.90 s** (guest B)
(`../../ticket24/spikes/E3/notes.md`). Ticket 25's adapter run, with `--debug` and
the tunnel flags, put launch-to-exit at **1.23 s** and **1.14 s**
(`../../ticket25/snp/run-2/notes.md`). So: the policy work of this ticket adds
nothing measurable to sandbox start — the 0.5–0.6 s here is the same start those
two recorded, measured to an earlier endpoint (first syscall rather than exit),
and the half second that `--debug` costs is inside all three.

**2 and 3 are honest gaps, not omissions.** A measured SEV-SNP guest prints no
duration for acquiring its own evidence and none for a verdict it reached; what
it prints is that it acquired 1,184 bytes over one write and bundled a 4,759-byte
chain, and that a peer was admitted. The bracket in the table is therefore an
upper bound on acquisition that also contains four other things. The TDX side of
this ticket has the number that is missing here, because `tunneld -selfcheck`
prints it (`../tdx/rq5-tdx.md`).

**4. Establishment is one number and it is the one the paper wants.** 109–125 ms
between two guests on one bench segment, with a relay copying every frame in the
middle, one verifier call each way, first attempt. The sandbox-side figure is
larger and noisier because it includes the sentry's hop over the socket and,
on the first attach, tunneld dialing; the warm-tunnel attaches (5.6–23.3 ms) are
what a second stream to an already-admitted peer costs.

**5. Installation is where this ticket's own cost lives, and it is a
millisecond.** `Policy.Narrow` on the boot controller parses the document,
sorts and deduplicates its atoms, checks `P1 ⊑ P0` component-wise, builds the new
table and swaps it: 965 µs on one guest and 1.314 ms on the other, of which the
swap itself — the only part during which a lookup could see one table or the
other — is 67 µs and 173 µs. The workload was running throughout both, and on
guest A an eight-mebibyte stream was in flight and completed
(`LONG COMPLETE bytes=8388608`). The *binding* half — the push travelling over
the tunnel, tunneld calling `Apply`, the sandbox acknowledging — has no clock on
the console; the workstation measured it at 25.2 ms for a sandbox's first push
(which includes the helper's first dial of the control socket) and 4.2 ms
afterwards.

**6. Capability release** is read as the interval between the policy being in
force and the workload getting a socket to a name that policy permits. The two
numbers differ by three times for a reason worth stating: on guest A the first
attach after the policy landed was a second fetch on a warm tunnel (49.4 ms),
while on guest B the first attach after it was the one that had to establish
(148.1 ms). Neither includes waiting for a peer to boot; both are single
observations per pair.

## The spread, and why it is not larger

Four boot pairs were recorded in all and two are used here; pairs 1 to 3 are in
this directory as well, and their timings agree with these to within the same few
tens of milliseconds for every component except the teardown, which pairs 1–3
could not measure at all (`run-4/notes.md`, "The five pairs"). What varies run to
run is the network-dependent half — establishment, the first attach — and it
varies by about 50 %. What does not vary is the sentry's own work: tunneld's
startup is 0.50 s in all eight guest-boots, and installing a policy is about a
millisecond in both observations.

## One number this ticket adds that the paper's six do not name

The teardown: from a workload being killed to the tunnel beside it being closed
with a refusal naming liveness. On hardware it is bounded by init's clock at
**≤ 2.4 s** (guest A) and **≤ 2.2 s** (guest B) in `run-4`, of which **0.68–0.77 s**
is init signalling five processes and the rest is console ordering — the watch
itself ticks every 250 ms. The workstation, where the kill is one `runsc kill`
and there is no serial port in the way, measured the same thing at **244 ms**
(`../adapter-check/notes.md`). The hardware number is an upper bound on a
teardown, not a measurement of one.
