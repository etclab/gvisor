# RQ5 on Intel TDX hardware: the six remote-cost components, as the paper names them

The paper's six (`evaluation.tex:764-771`, quoted at `paper-vs-design-27sec.md:212`)
measured on two Google Cloud `c3-standard-4` Confidential VMs in `us-central1-a`,
from the two boot pairs that ran the scenario through: `boot-2/` (69 of 74) and
`boot-3/` (71 of 74). Four guest-boots in all, so most rows have four
observations and the range is given rather than a mean. `../snp/rq5-snp.md` is
the same table on SEV-SNP, and the two are worth reading side by side: this
vendor is a current server part in a cloud VPC and that one is a bench host, and
the components that are compute divide by five while the component that is a
network divides by seven.

| # | component | Intel TDX, Google Cloud | how it was read | SEV-SNP, for comparison |
|---|---|---|---|---|
| 1 | guest execution overhead | **0.071 – 0.083 s** (4) | the sentry's own debug log being created (its filename's timestamp) to the sandbox's first `tunnel dns:` — the workload's first syscall that left the sandbox | 0.496 – 0.622 s |
| 2 | attestation acquisition | **40, 41, 41, 47 ms** (4) | `tunneld: SELFCHECK acquired 8000 bytes of intel-tdx evidence in 41ms, bound to a throwaway key and to policy digest 197d4aae…` — the guest times this itself | not printed on that path; 0.50 s bounds acquisition *and* four other things |
| 3 | attestation verification | **1 verifier call per admission**, inside (4) below; **4 workstation verdicts in 0.2 s** | `verifier_calls=1` on the `LATENCY` line; and `attest-tool verify -vendor intel-tdx` here, four quotes judged against two sets with the provisioned collateral, all ACCEPTED | the same, 1 call |
| 4 | establishment of the attested channel | **15.2 and 15.5 ms** (2) | `tunneld: LATENCY pass=1 peer=guest-a kind=establish ms=15.224 attempts=1 verifier_calls=1` — one `Open` on a peer no tunnel existed to: the dial, both sides' evidence, both verdicts, the handshake | 109.2 and 124.7 ms |
| | the same seen from inside the sandbox | **17.0 – 28.9 ms** first attach; **1.3 – 6.3 ms** warm (19) | the sentry's `tunnel attach: … ok in …` lines | 61.8 – 159.7 ms first; 5.6 – 23.3 ms warm |
| 5 | installation and binding of `P` | **169.5 – 200.3 µs**, of which the table swap is **11.4 – 20.1 µs** (4) | `tunnel narrow: applied in 169.519µs, of which the table swap was 11.407µs` — parse, sort, subset-check, build, swap, with the workload running throughout | 965 µs – 1.314 ms; swap 67 – 173 µs |
| | the contract round trip that carries it | **not timestamped on hardware** | tunneld's `push policy …` and `SANDBOX applied …` lines carry no clock on either vendor. The measured round trip is the workstation's: 25.2 ms for a sandbox's first push, 4.2 ms afterwards (`../adapter-check/notes.md`) | the same |
| 6 | capability release | **0.119, 0.286, 1.830, 2.016 s** (4) | the sentry's `tunnel narrow: applied` timestamp to the first `tunnel attach: … ok` after it | 49.4 ms and 148.1 ms |

## What each row means here, and what it does not

**1. Guest execution overhead is an order of magnitude smaller than on the
bench, and the endpoints are the same.** The method is identical on both
vendors — runsc's own log file appearing, to the first name the workload asked
the sentry to resolve — and the number is 0.071–0.083 s on a `c3-standard-4`
against 0.496–0.622 s on the SEV-SNP bench. Both include the same 108 MB runsc,
the same bundle and the same `--debug` flag set; what differs is the machine.
Two things this number is **not**: it is not a sandbox cold start measured from
`runsc run` being exec'd (the initrd's own clock brackets that at about 0.2 s,
`uptime 2.51s` at the launch and the sentry's log 0.07 s before the first
lookup), and it is not comparable to ticket 24's E3 figure, which was a whole
bare workload's launch-to-exit on SEV-SNP (0.85 and 0.90 s).

**2. This is the number SEV-SNP could not give.** `tunneld -selfcheck` prints
the acquisition it timed, so on this vendor attestation acquisition is a
measurement and not a bracket: 8,000 bytes of Intel TDX evidence in 40–47 ms,
four times, bound to a throwaway key and to the ceiling digest. On SEV-SNP the
guest prints no duration and the 0.50 s in that table also contains the link
coming up, the chain being bundled, the listener and the sandbox socket.

**3. Verification** is one verifier call per admission on the guest, and on this
workstation four `attest-tool verify` runs — each quote against its own set and
against the peer's — all ACCEPTED, with the Intel collateral provisioned on the
config device and the Intel root embedded in the library. The guest does not
print a verdict duration, so the figure that exists is (4), which contains it.

**4. Establishment is seven times faster than on the bench**, 15.2–15.5 ms
between two VMs in one zone against 109–125 ms between two QEMU guests with a
relay copying every frame. Same code, same handshake, one verifier call each
way, first attempt. The sandbox-side first attach is larger because it also
carries the sentry's hop over the socket and tunneld dialing; the warm attaches
(1.3–6.3 ms) are what a second stream to an already-admitted peer costs, and
they are what the narrowing control's fourteen probes measure.

**5. Installing a pushed policy costs a fifth of a millisecond on this
hardware**, and the swap of the table a workload is actually using costs
11–20 µs. Both guests, both pairs, with the workload running throughout and, on
guest A, with an eight-mebibyte stream in flight that carried two more mebibytes
after the swap. The binding half — the push crossing the tunnel, `Apply`, the
acknowledgement — is not timestamped on any console; the workstation measured it
at 25.2 ms for a sandbox's first push and 4.2 ms afterwards.

**6. Capability release varies by a factor of seventeen here, and the reason is
what it measures.** It is the interval from the policy being in force to the
workload next holding a socket to a name that policy permits, and the workload
decides when to ask: on two of the four guests the next fetch was the
narrowing control's next poll (three seconds apart in the script), so 1.8 and
2.0 s are the script's cadence and not a cost. The two numbers that are a cost
are 0.119 s and 0.286 s, and the mechanism underneath them is a warm attach of
1.3–6.3 ms. The SEV-SNP table has the same caveat with smaller numbers.

## One number this ticket adds that the paper's six do not name

The teardown: from a workload being killed to the tunnel beside it being closed
with a refusal naming liveness. On TDX it is bounded by the initrd's own clock at
**≤ 1.15 s** on all four guests — `kill-after: …s elapsed` to `kill-after:
nothing of the sandbox is left in this init's process table`, with
`SANDBOX liveness lost: the sandbox closed its socket` and the refusal between
them. That is about half the SEV-SNP bound (≤ 2.2–2.4 s) and for the same reason
as row 1: the same five processes are signalled, on a faster machine. The
watch's own granularity is 250 ms on both, and the workstation, where the kill is
one `runsc kill` and no serial port is in the way, measured 244 ms
(`../adapter-check/notes.md`).

## The spread, and what it is not

Two pairs is two samples, and a `c3-standard-4` in one zone is one machine type
in one place. Nothing here is a benchmark: each row is what the run printed, four
times at most, and the components that depend on another machine booting —
establishment, the first attach — are the ones that vary. The sentry's own work
does not: taking a policy was 169.5, 176.7, 195.2 and 200.3 µs across four
guests, and acquiring evidence was 40, 41, 41 and 47 ms.
