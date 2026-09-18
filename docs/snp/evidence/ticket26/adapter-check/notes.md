# The adapter check — a sandbox that honours a pushed policy, end to end, on a workstation

Ticket 26's own check of the piece this ticket builds, in the shape ticket 25's
check (`../../ticket25/adapter-check/`) has. It is **not** the two-guest proof
and it is not the loopback proof: it is the sentry-side agent's own evidence
that everything the definition of done names is true of one sandbox at once,
with a throwaway stand-in where tunneld would be. Workstation only, 2026-09-18,
worktree `/home/pniroula/Projects/gvisor-t26`, branch
`ticket-26-the-sandbox-honors-a-pushed-policy`. No sudo, no hardware, **no API
key and nothing paid** — the run is `env -u ANTHROPIC_API_KEY` and no bundle
carries a credential of any kind.

    runsc sha256           6019cbf49bc87c5c1ca21382ec069376661bfb56ab74eb3840d61378fbab7819
    faketunneld sha256     274233ee72562ca94e21201a665de8488cee0a35cd13a5cdb8a0054367db8efe
    seccheck-receiver      d7be04465f899c4af6f5c94de2307cde5bd220679497db2455ea085189d509dd
    workload sha256        08e9fe9a00bb27e766181c30fac0efde2ed56754936a1c2ab0639d3cefeccace
    busybox                dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14

Reproduced by

    env -u ANTHROPIC_API_KEY ./run-adapter-check.sh <runsc> <workdir> \
        <faketunneld> <seccheck-receiver> ./check-workload.sh

and `output-01-adapter-check.txt` is the untrimmed transcript.

## What was asked

One sandbox, one busybox workload, three pushes, and the seven things this
ticket owes:

| # | the claim | what is in the transcript |
| --- | --- | --- |
| 1 | a pushed policy reaches the sentry and is applied to a running workload | `APPLY p0.json ACK elapsed=25.213417ms digest=86e8b283…7b3c` |
| 2 | a narrowing removes a name while the workload runs | `APPLY p1.json ACK` and `tunnel narrow: gone.peer-a:9001 at 100.64.1.0 is gone` |
| 3 | a widening is refused, naming the component | `APPLY p2.json REFUSED … it widens n by [net:gone.peer-a:9001]` |
| 4 | N: the removed name is NXDOMAIN, its old address ENETUNREACH, both recorded | `wget: bad address`, `Network is unreachable`, three `egress_refused` |
| 5 | X: an exec outside `x` is EACCES with an `exec_refused` event | `Permission denied` and `exec_refused path=/bin/probe … reason=not-in-x` |
| 6 | F: a `["ro","noexec"]` mount refuses an exec and nothing else | `rc=126` on the exec, `rc=0` on the read, `Read-only file system` on the write |
| 7 | contract v3: one `alive` a second carrying the digest; the workload's exit ends it | two watches that live, two that are lost as mismatches, one lost as a close |

The table is two names, `keep.peer-a:9000` and `gone.peer-a:9001`; sorted, so
`gone.peer-a` is `100.64.1.0` and `keep.peer-a` is `100.64.1.1`. The three
policies differ only in `n` — `f` is `[{"path":"/noexec","modes":["r"]}]` and
`x` is `[{"path":"/bin/busybox"}]` in all three — so nothing but `n` can explain
the difference between an acknowledgement and a refusal.

## 1–3. The three pushes

    P0  86e8b283aa251ba85e6e3be2c57a401d5590f3e6b021df2881a8e7b083a17b3c  ACK 25.213 ms
    P1  3f5ed6490ad9c638b2af78f3e8679b6e6455e2e25fb848831a8995e4bea9e292  ACK  4.207 ms
    P2  86e8b283aa251ba85e6e3be2c57a401d5590f3e6b021df2881a8e7b083a17b3c  REFUSED 3.247 ms

(P0's 25 ms is the first dial of the control socket in this sandbox's life; E1
measured the same shape over twenty-four pushes.)

P2 is byte-for-byte P0. It is accepted as a first push and refused as a third,
which is the subset rule doing its job: what P2 widens is not the boot table but
**the policy in force**, and the sentence says so —

    policy refused: it widens n by [net:gone.peer-a:9001]

carried back through the helper and the contract word for word. The sentry's own
account of the two that landed:

    tunnel narrow: sha256=86e8b283…7b3c n=2 of 2 names kept x=1 f=1
    tunnel narrow: applied in 2.131737ms, of which the table swap was 134.06µs
    tunnel narrow: gone.peer-a:9001 at 100.64.1.0 is gone
    tunnel narrow: sha256=3f5ed649…e292 n=1 of 2 names kept x=1 f=1
    tunnel narrow: applied in 811.429µs, of which the table swap was 200.679µs

## 4. N, in both places, with the reason recorded

    workload: NARROWED gone.peer-a:9001 stopped resolving on attempt 6: wget: bad address 'gone.peer-a:9001'
    workload: AFTER GET the dropped name's old address http://100.64.1.0:9001/ rc=1
              out='wget: can't connect to remote host (100.64.1.0): Network is unreachable'
    workload: AFTER GET http://keep.peer-a:9000/ rc=0 out='this is keep.peer-a:9000'

    egress_refused protocol=dns name=gone.peer-a reason=unknown-name time=…12.178…Z
    egress_refused protocol=dns name=gone.peer-a reason=unknown-name time=…12.178…Z
    egress_refused protocol=tcp address=100.64.1.0 port=9001 reason=not-in-table
                   time=…12.242…Z container_id=t26-check-… thread_id=20

Two DNS events because busybox asks A and AAAA; the TCP event carries the task's
context and the DNS ones do not, which is ticket 25's finding unchanged. The
surviving name still resolves to the address it always had and still opens a
stream.

## 5. X, on the identity the point already carried

    workload: EXEC /bin/probe out='/check-workload.sh: line 46: /bin/probe: Permission denied'
    workload: EXEC /bin/uname (a symlink to the busybox x names) out='Linux'

    exec refused: path="/bin/probe" sha256=c4b9b606…2f6e reason=not-in-x
    exec_refused path=/bin/probe sha256=c4b9b606…2f6e reason=not-in-x
                 time=…12.360…Z container_id=t26-check-… thread_id=25

`/bin/probe` is a copy of the very busybox `x` permits, with a comment appended:
a different file at a different path, so neither half of `x` matches it and the
execve fails `EACCES`. `/bin/uname` is a symlink to the permitted file and runs,
because the point reports the file an execve resolved to and not the name it was
given (spike E2 §3a).

## 6. F, which is mounts and only mounts

`/noexec` is a bind mount of a directory holding the same busybox, with
`["ro","noexec","rbind"]`:

    workload: EXEC /noexec/busybox on a ro,noexec mount out='… Permission denied' rc=126
    workload: READ /noexec/busybox rc=0 (noexec refuses the exec and not the read)
    workload: WRITE /noexec/written out='touch: /noexec/written: Read-only file system'

The file under it is the binary `x` permits **by path**, so what refused this
exec is `MountFlags.NoExec` in `pkg/sentry/vfs/vfs.go`, not the policy. That is
the whole of F in this sandbox. `f`'s atoms were parsed, subset-checked and
carried in the digest, and **enforced by nothing**: a policy naming
`/noexec` read-only would have been honoured by this run whatever it said,
because the mount was already read-only before a byte of policy arrived. No
mount in this tree can be asked for as `locked` from a bundle either — that is a
unit test (`runsc/boot:boot_test`, `TestFIsMountsOnly`) and a fact about
`ParseMountOptions`.

## 7. Contract v3, watched from the stand-in

`faketunneld` starts a `sandbox.Host.Watch` on every digest it successfully
pushes, and one on a digest nothing enforces. Four watches, four outcomes:

| watch | lived | ended as |
| --- | ---: | --- |
| P0's digest | 5.250 s | **mismatch** — `it pulsed 3f5ed649…, expected 86e8b283…`, 10 ms after P1 landed |
| P1's digest | 12.251 s | **closed** — `the sandbox closed its socket`, 0.232 s after the workload was killed |
| all-zero digest | 0.250 s | **mismatch** — `it pulsed 3f5ed649…, expected 0000…` |

P1's watch surviving 12.25 s is the heartbeat: at one pulse a second and three
misses allowed, a sandbox that had stopped pulsing would have been lost in about
three. The kill is `runsc kill … KILL`; the sentry goes, its end of the
socketpair goes, and the helper says so —

    Tunnel helper: the sentry channel ended: EOF
    Tunnel helper exiting: the sentry closed the channel
    Tunnel helper: the tunneld socket is gone, so the sandbox stops saying it is alive

— which is the attachment closing, which is the loss, 244 ms later.

### The defect this check found, and the fix it has

The **first** run of this check (before the fix) lost P1's watch after **250 ms**
with `it pulsed 86e8b283…, expected 3f5ed649…` — the digest of the policy that
had *just been replaced*. The cause is an ordering one: `Host.Apply` returns as
soon as the acknowledgement arrives, tunneld starts watching immediately, and
the last thing the host had heard from the sandbox was the previous policy's
digest. A ticker whose first tick is a second away leaves a one-second window in
which every watch is a mismatch — which, on a real tunneld, is every tunnel torn
down on every narrowing.

The fix is in the helper (`runsc/cmd/tunnel_helper.go`, `policyApplier.live`):
**the first `alive` for a new digest is sent synchronously, before `apply`
returns and so before the acknowledgement**, and the socket delivers them in
that order. The transcript above is the run after the fix, and the window is
gone.

## What this check does not say

Nothing about tunneld, about attestation, about two peers, about QUIC or about
an agent runtime: the stand-in has none of those. It uses one container, one
sandbox and no restore. It does not exercise a narrowing that removes a name a
stream is open on — that is spike E1, which measured it and found the stream
survives.

## Files here

| file | what |
| --- | --- |
| `run-adapter-check.sh` | the run, exactly as run |
| `check-workload.sh` | the workload, inside the sandbox |
| `faketunneld/` | the stand-in: `attest/sandbox`'s socket, `Host.Apply` and `Host.Watch` |
| `output-01-adapter-check.txt` | the untrimmed transcript |
| `../tools/seccheck-receiver/` | the receiver the event lines come from |
