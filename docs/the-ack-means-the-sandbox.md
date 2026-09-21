# An ack means the sandbox has it: contract v4, role tracking, and liveness beyond the tunnel

Ticket 27. Master `cea8ae91d`. Four pieces closed. (1) **Contract v4: role tracking on the local socket.**
An attachment declares its role via an `attach` message (`{"id":0,"type":"attach","role":"enforcing"}` or
`"role":"network"`). Exactly one enforcing client is permitted per socket; a second enforcing client is refused
and closed with a diagnostic sentence, while non-enforcing clients (the exit proxy) remain free to open and accept
streams. (2) **`Host.Apply` waits and replays.** A policy push targets the enforcing attachment and nothing else;
if none is attached yet, `Host.Apply` waits inside the push deadline (`cfg.PushTimeout`, default 10 s) for the
enforcing attachment to arrive, delivers the policy, and acknowledges only when the enforcing sandbox has accepted
it. If an enforcing client attaches after a policy is in force, the policy is replayed to it immediately during
attach. Concurrent early pushes are serialised in order via an apply semaphore. (3) **The liveness watch outlives
the tunnel.** The heartbeat watch is owned per sandbox attachment rather than per tunnel. When a tunnel idles out
and closes, the watch continues running; if the sandbox exits or stops pulsing, tunneld marks the policy state as
not-live, clears the policy in force, drops the enforcing client, and logs `ReasonPolicyNotLive` stating plainly
that no tunnel was closed because none was open. The `hold + 60` workaround in `docs/snp/tunnel-on-two-guests.sh`
is removed. (4) **`x` semantics settled.** An absent `x` key is unconstrained exec (sink uninstalled); an empty `x`
list is a grant of nothing (all execs denied with `EACCES`).

Three spikes stand under it, recorded under `docs/snp/evidence/ticket27/spikes/`: **E1** (the attachment window
across 25 runs), **E2** (policy replay and idempotent narrow), and **E3** (liveness observation after tunnel
idle-out).

---

## 1. The two clients and contract v4

### What the two clients were
In ticket 25 and ticket 26, `tunneld` provided a single Unix domain socket (`/run/tunneld/sandbox.sock`) for the
sandbox. In a governed guest deployment, two distinct entities attached to this socket:
1. **The runsc tunnel helper (`cmd/tunnel_helper.go`):** The process outside the container that holds the
   socketpair to the sentry, delivers pushed policies to the sentry via `Policy.Narrow` over the sentry's control
   socket, and pulses `alive` messages to report that the policy is in force. This is the **enforcing** client.
2. **The exit proxy (`socketSandbox` / `ServeExit`):** The process that accepts streams from tunneld and dials
   external destinations (`api.anthropic.com:443`, `www.rfc-editor.org:443`). It neither enforces policy nor
   speaks to the sentry; it only opens and accepts streams. This is the **network** client.

In contract v3, `Host.Apply` iterated over a copy of `h.conns` (`attest/sandbox/host.go:128-145`) without knowing
which client was which. On SEV-SNP pair 3 (leftover 21 in `docs/policy-in-the-sentry.md`), the exit proxy attached
first; a push arrived before `runsc` started; the exit proxy acknowledged the push; and when the `runsc` helper
attached milliseconds later, `Host.Apply` had already returned success. The sentry never received the policy, while
`tunneld` believed the policy was in force. The workload ran thirty unconstrained execs.

### What one enforcing client means on the wire
Contract version 4 adds an explicit role declaration:
- Message format: `{"id":0,"type":"attach","role":"<role>"}`.
- Roles: `RoleEnforcing` (`"enforcing"`) and `RoleNetwork` (`"network"`).
- Like `alive`, `attach` carries `id: 0` and expects no reply; it is sent immediately upon connection before any
  requests or replies.
- `attest/sandbox/host.go` records `h.enforcing` separately from `h.conns`.
- If an attachment declares `role: enforcing` when `h.enforcing != nil`, `recordAttach` rejects it, logs a
  refusal, and closes the connection with:
  `"a second enforcing sandbox client was refused: socket already has an enforcing attachment"`.
- Non-enforcing attachments (`role: network`, or default unstated role for backwards compatibility with tests) are
  registered in `h.conns` for stream multiplexing, but `Host.Apply` never pushes to them.

---

## 2. Host.Apply: waiting for the enforcing attachment

### The decision and the numbers from E1
When a push arrives at `tunneld` before any enforcing client has attached, `Host.Apply` must either:
- (A) Wait up to the push deadline for the enforcing client to attach; or
- (B) Refuse immediately with `no sandbox is attached` and close the tunnel.

Spike E1 (`docs/snp/evidence/ticket27/spikes/E1/output.txt`, `notes.md`) measured the startup window across 25 loopback runs:
- The exit client attaches almost immediately: between 276 µs and 961 µs (median ~520 µs, mean ~500 µs; typical ~200–650 µs) after socket listen.
- The `runsc` helper attaches in **97.273 ms to 186.040 ms** from container start (`runsc run`), with **p50 = 135.495 ms**, **mean = 140.228 ms**, and **p90 = 167.541 ms**.
- In 100% of runs (25 of 25), the early push landing at 1.4–3.0 ms was answered by the non-enforcing exit client with `ack`, and **0 of 25** pushes were received or enforced by the helper.
- Even the historical outlier observed in ticket 26 leftover 19 was **2.138 s**.

Because `DefaultPushTimeout` is 10 s (`10,000 ms`), the attach window (under 187 ms observed, ~2.1 s worst case) fits comfortably inside the push deadline with an 80%+ safety margin. Refusing immediately would burn a tunnel handshake and force retries for a client that is reliably only ~100–186 ms away.

Therefore, the recommended decision (A) was implemented:
- In `Host.Apply`: if `h.enforcing == nil`, a waiter channel is enqueued in `h.enforcingWaiters`.
- When an enforcing attachment arrives, `recordAttach` pops the waiter and delivers the attachment.
- `Host.Apply` calls `a.apply(ctx, policy)` on the newly arrived attachment.
- Only when `a.apply` succeeds does `Host.Apply` set `h.inForce = policy` and return `nil`.
- If the context deadline expires before an enforcing client attaches, `Host.Apply` returns `sandbox.ErrNoSandbox`.
- Concurrent early pushes are serialised via `applySem chan struct{}`: the first caller waits for the attachment
  and delivers the initial policy; subsequent callers acquire the semaphore and apply directly to the attached
  enforcing client in strict order.

---

## 3. Late-attach delivery

When a policy has already been acknowledged and is in force (`h.inForce != nil`), what happens if a new enforcing
sandbox attaches?

In ticket 27, `recordAttach` checks if `h.inForce != nil`. If so, it replays the policy in force to the newly
attached enforcing client:
- It calls `a.apply(ctx, h.inForce)` before marking the attachment active.
- If the sentry accepts the policy, `recordAttach` records `h.enforcing = a` and releases any waiters.
- If the sentry refuses the policy, the attachment is closed.

### E2: a policy delivered twice
Spike E2 (`docs/snp/evidence/ticket27/spikes/E2/output.txt`, `notes.md`) evaluated the cost and semantics of delivering the same policy twice:
- Initial delivery to a fresh sentry (sentry B with no policy in force) took **3.182 ms** (`3.181803ms`), while delivery 1 to sentry A took **4.861 ms** (first delivery range **3.2–4.8 ms**).
- Across a 50-trial benchmark of replaying the policy in force to running sentry A:
  - **Min**: 906 µs
  - **p50**: **1.252 ms**
  - **Mean**: **1.867 ms**
  - **p90**: 2.838 ms
  - **Max**: 18.148 ms
- Single replay (delivery 2) to sentry A took **2.264 ms**.
- The subset check (`runsc/boot/policy.go:policySubset`) treats an identical document as a valid non-widening narrowing (`P ⊑ P`), returning `err=<nil>` and the identical SHA-256 digest (`e1a4ddd603e1edfba4479099c174dd815534b9174c4c74ea32a08f88ad7ce3e8`).
- Late-attach delivery is completely available at low marginal latency (~1.25 ms p50, ~1.87 ms mean).

---

## 4. Liveness outlives the tunnel

### The problem with per-tunnel liveness
In ticket 26, `watchLiveness` (`attest/tunneld/push.go`) polled `conn.Live()` once a second and returned silently
when `conn.Live()` became false (leftover 22). This meant that when a tunnel idled out after 60 s, liveness
monitoring stopped completely. If the sandbox died after the tunnel closed, `tunneld` never noticed, and a later
dial would find a dead sandbox. SEV-SNP pair 1 had to work around this by inflating the idle timeout to `hold + 60`
s (`tunnel-on-two-guests.sh:1690-1701`).

### The fix in ticket 27
1. Liveness monitoring is decoupled from the pushing tunnel connection and owned by the sandbox attachment: one
   watch per enforcing attachment on `Tunneld`.
2. `Tunneld` runs `watchLiveness` for the lifetime of the attachment.
3. On miss (3 missed pulses) or socket close:
   - If a governed tunnel is still open, it is closed with `ReasonPolicyNotLive`.
   - If no tunnel is open, `tunneld` logs:
     `"SANDBOX liveness lost: <why> (no tunnel was closed because none was open)"`.
   - The enforcing attachment is dropped (`DropEnforcing()`) and `inForce` is cleared. Any subsequent stream
     request or push is refused.

### E3: liveness after the tunnel is gone
Spike E3 (`docs/snp/evidence/ticket27/spikes/E3/output.txt`, `notes.md`) tested this behavior:
- Tunnel idle timeout was left at its default 60 s (`tunnel.DefaultIdleTimeout` = 1m0s); the test waited 62 s for the tunnel to idle out cleanly.
- After the tunnel was idle, the failure was triggered in two ways:
  - **Kill failure** (workload process killed with `SIGKILL`, closing socket): host watch observed loss after **250.404 ms** (`250.403818ms`, on the first 250 ms tick of `watchInterval`).
  - **Stop failure** (workload paused with `SIGSTOP`, socket open but pulses cease): host watch observed loss after **3.000 s** (`3.000303968s`, exactly `DefaultMisses * DefaultPulse` = 3 × 1 s).
- In the baseline (ticket 26), tunneld logged **0 new refusals** (silent) because `watchLiveness` had returned when the tunnel closed.
- In ticket 27, the watch outlives the tunnel: tunneld logs `ReasonPolicyNotLive` stating `"no tunnel was closed because none was open"`, drops the enforcing connection via `DropEnforcing()`, and clears `inForce`.
- The `hold + 60` workaround in `docs/snp/tunnel-on-two-guests.sh:1690-1701` was deleted, reverting to 60 s.

---

## 5. What the policy side must deliver: X semantics settled

This is a paragraph in this record and it is **sent nowhere**. Ticket 23 and ticket 26 left open whether an empty
exec list `x: []` meant unconstrained exec (the absent interpretation) or a grant of nothing (the zero-grant
interpretation). It is settled here:

> **Execution grant semantics.** An absent `x` key (`"x"` omitted from the policy document) denotes an unpoliced
> sandbox with respect to execution: no seccheck exec sink is installed, and `execve` proceeds unrestricted. An
> explicit empty list (`"x": []`) is a grant of nothing: the seccheck exec sink is installed with an empty allow
> set, and every subsequent `execve` fails with `EACCES`. Under the subset check (`P1 ⊑ P0`), an unpoliced sandbox
> (`x` absent) may be narrowed to any `x` list; a sandbox governed by an empty `x` cannot be widened by any later
> policy. Both `runsc/boot/policy.go` and `attest/sandbox/policy.go` distinguish `nil` (absent) from `[]string{}`
> (empty), consistent with `TestAnEmptyGrantIsAGrantAndNotAnAbsence`.

---

## 6. Verification and test results

### Unit tests
- **`attest/sandbox`**:
  - `TestAPushThatArrivesBeforeTheEnforcingSandboxHasAttachedIsNotAcknowledgedUntilTheEnforcingSandboxHasIt` (PASS)
  - `TestAnEnforcingSandboxThatAttachesAfterAPushReceivesThePolicyInForce` (PASS)
  - `TestASecondEnforcingClientOnOneSocketIsRefusedAndANonEnforcingClientIsNot` (PASS)
- **`attest/tunneld`**:
  - `TestASandboxThatStopsEnforcingAPushedPolicyClosesTheTunnel` (PASS)
  - `TestALivenessWatchSurvivesThePushingTunnelBeingClosedAndStillReportsTheLoss` (PASS: miss, mismatch, close)
- **`runsc/boot:boot_test`**:
  - `TestPolicyExecAtomsAbsentVsEmpty` (PASS)
  - `TestPolicySubsetWideningAnEmptyX` (PASS)
- **`pkg/sentry/policyx:policyx_test`**:
  - `TestSinkAbsentVsEmptyX` (PASS)
- **Full package tests**:
  - `attest/sandbox/deno`: all 11 tests PASS.
  - `attest/...`: all tests PASS (`go test ./...` in 108 s).
  - `make test TARGETS="//pkg/sentry/policyx:policyx_test //runsc/boot:boot_test"`: all PASS.

### Loopback harness & Early-push scenario
In `attest/cmd/agent-probe/governed_test.go`:
- Added fifth scenario `early-push` and its reporting method `tellEarly`.
- Under `early-push`, the pusher initiates the push immediately before the sandbox helper attaches to `a.sock`.
- `Host.Apply` suspends on `enforcingWaiters`, waits for the helper to attach, delivers the policy to the sentry,
  and acknowledges only when the sentry reports success.
- The workload runs governed under P0 and finishes cleanly.
- (Live model-backed Claude test skipped in automated harness when `ANTHROPIC_API_KEY` is not exported; plain probe
  and mock verifications complete without error).

### Quality gate
- `~/.local/bin/ripwire attest --quality-delta=cea8ae91d..HEAD`:
  `regressions="0" minor="0" acked="0" stale="9" preexisting-worse="0" new-symbol="0" gating="0"`.
  Gating delta is 0.

---

## Leftovers

The first five are ticket 26's (leftovers 16, 21, and 22 closed; 17, 18, 19, 20, 23, 24, 25 remain open as
recorded in `docs/policy-in-the-sentry.md`). The three below are ticket 27's own:

26. **Concurrent early pushes are serialised, but a widening between them fails.** `applySem chan struct{}`
    serialises `Host.Apply` calls so that early pushes wait in FIFO order and deliver to the enforcing attachment.
    However, each push is checked for `P_{i+1} ⊑ P_i` by the sentry. If pusher 1 pushes P1 and pusher 2 pushes P2
    concurrently where P2 widens P1, pusher 2 will be refused by the sentry after pusher 1 completes. This is the
    correct subset rule, but callers must be aware that concurrent pushes compose as a sequential narrowing.
27. **Sentry startup readiness race remains a retry.** If `runsc` starts and the helper attaches to the contract
    socket before the sentry's container loader has reached `started`, `Policy.Narrow` over urpc returns `a policy
    is honoured only by a started one`. `Host.Apply` returns this error to tunneld, which logs `SANDBOX refused` and
    retries. Closing this completely would require delaying the helper's `attach` until the sentry loader signals
    readiness.
28. **Local socket access is access to the peer table.** Any local process that can connect to
    `/run/tunneld/sandbox.sock` with `role: network` can open streams to any peer declared in `--tunnel-table`.
    There is no process-level authentication or credential passing (such as `SO_PEERCRED`) on the Unix domain
    socket. In a measured guest this is mitigated by single-tenant isolation, but on multi-tenant hosts it would
    require credential validation.
