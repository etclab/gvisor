# E1 — the window, and who is in it

Ticket 27's first experiment, re-run on the workstation against this branch's
tip. Everything here is reproduced by `./run.sh`, which prints the header below
into `output.txt` and then runs `e1_spike.go` against
`bazel-bin/runsc/runsc_/runsc`. **Every number in this file is copied from
`output.txt`**, and the percentiles are the ones the spike computes over its own
records; a script over the committed `output.txt` reproduces each of them from
the table rows.

## Setup

| thing | value |
|---|---|
| date | 2026-09-22T00:41:47Z |
| branch | `ticket-27-an-ack-means-the-sandbox-has-it` |
| commit | `648e056dabf5914857a1e7459b48169b4ef0643d`, this branch's tip when the run was made |
| runsc | `bazel-bin/runsc/runsc_/runsc`, sha256 `49740e434b42e1c1d65546258f2bcbd16134469cf8ea72190321a353daf9823c` |
| kernel | `Linux 6.11.0-rc3-snp-host-85ef1ac03941` |
| runs | 25 |
| push policy | version 1 envelope, `n = [test.example:80]`, `f = []`, `x = [/bin/busybox]` |
| workload | `/bin/busybox sleep 0.25` in a five-file rootfs |

Each run starts a `sandbox.Host` on a unix socket at $T_0$, attaches the exit's
client to it as a **network** client, starts `runsc run`, and enters
`Host.Apply` a millisecond or two later — before the runsc helper can have
attached. The deadline on the push is the ten seconds a pushing peer gives one
(`tunneld.DefaultPushTimeout`, `sandbox.DefaultApplyWait`), written into the
spike because it calls `Host.Apply` directly and no tunneld gives it one.

## What the experiment now measures, and what it no longer can

E1 was written to find out **which of two clients on one socket answered a push
that arrived before the enforcing helper attached**. On master the answer was the
exit, every time: `Host.Apply` pushed to whatever was attached at that instant,
and the exit was attached in well under a millisecond.

On this branch there is no such choice left to observe. A client declares a role
in its first message, the exit declares `network`, and a network attachment is
never offered a policy. So the two columns that recorded a choice are replaced by
the three facts that are left: whether the push was entered **before** the
enforcing attachment arrived, whether the exit was offered the document **at
all**, and how long the wait cost. The measurement the decision to wait rests on
— from `runsc` starting to the enforcing attachment arriving — is unchanged, and
is the one the percentiles below are for.

## The data

All times are from $T_0$, the host beginning to listen on the sandbox socket,
except "From runsc start". "Waited for it" is the push being entered before the
enforcing attachment; "Exit offered the policy" is the exit's apply callback
being called at all.

| Run | Exit attach | runsc start | Push entered | Enforcing attach | From runsc start | Apply returned | Apply took | Waited for it | Exit offered the policy | Answer |
|---|---|---|---|---|---|---|---|---|---|---|
| 01 | 1.549ms | 1.805ms | 3.291ms | 153.153ms | 151.348ms | 325.317ms | 322.026ms | true | false | acknowledged |
| 02 | 1.042ms | 1.372ms | 2.829ms | 153.156ms | 151.784ms | 296.343ms | 293.514ms | true | false | refused: not started yet |
| 03 | 849µs | 1.045ms | 2.311ms | 128.301ms | 127.256ms | 310.904ms | 308.593ms | true | false | acknowledged |
| 04 | 950µs | 1.278ms | 2.821ms | 158.387ms | 157.108ms | 323.586ms | 320.765ms | true | false | acknowledged |
| 05 | 719µs | 919µs | 2.387ms | 171.764ms | 170.845ms | 353.83ms | 351.444ms | true | false | acknowledged |
| 06 | 704µs | 902µs | 2.414ms | 156.584ms | 155.682ms | 354.726ms | 352.312ms | true | false | acknowledged |
| 07 | 1.043ms | 1.291ms | 2.598ms | 144.018ms | 142.727ms | 331.506ms | 328.908ms | true | false | acknowledged |
| 08 | 881µs | 1.225ms | 2.609ms | 165.197ms | 163.973ms | 344.153ms | 341.544ms | true | false | acknowledged |
| 09 | 931µs | 1.287ms | 3.013ms | 144.048ms | 142.761ms | 367.729ms | 364.716ms | true | false | acknowledged |
| 10 | 758µs | 1.045ms | 2.426ms | 129.662ms | 128.617ms | 261.047ms | 258.622ms | true | false | refused: not started yet |
| 11 | 904µs | 1.155ms | 2.713ms | 156.533ms | 155.378ms | 400.307ms | 397.594ms | true | false | acknowledged |
| 12 | 772µs | 949µs | 2.277ms | 120.97ms | 120.02ms | 348.293ms | 346.017ms | true | false | acknowledged |
| 13 | 577µs | 700µs | 2.343ms | 169.522ms | 168.822ms | 385.866ms | 383.524ms | true | false | acknowledged |
| 14 | 1.006ms | 1.262ms | 2.771ms | 177.496ms | 176.234ms | 393.213ms | 390.443ms | true | false | acknowledged |
| 15 | 903µs | 1.057ms | 2.596ms | 152.414ms | 151.357ms | 334.015ms | 331.419ms | true | false | acknowledged |
| 16 | 1.267ms | 1.573ms | 3.598ms | 148.039ms | 146.466ms | 329.149ms | 325.551ms | true | false | acknowledged |
| 17 | 835µs | 1.255ms | 3.272ms | 160.321ms | 159.066ms | 353.717ms | 350.445ms | true | false | acknowledged |
| 18 | 822µs | 1.137ms | 2.904ms | 138.015ms | 136.877ms | 388.3ms | 385.397ms | true | false | acknowledged |
| 19 | 585µs | 710µs | 1.645ms | 113.106ms | 112.396ms | 329.846ms | 328.201ms | true | false | acknowledged |
| 20 | 824µs | 1.045ms | 2.568ms | 151.703ms | 150.658ms | 340.836ms | 338.267ms | true | false | acknowledged |
| 21 | 830µs | 1.056ms | 2.671ms | 174.059ms | 173.003ms | 306.631ms | 303.96ms | true | false | refused: not started yet |
| 22 | 638µs | 912µs | 2.275ms | 169.224ms | 168.312ms | 337.926ms | 335.651ms | true | false | acknowledged |
| 23 | 802µs | 1.017ms | 2.459ms | 125.006ms | 123.989ms | 289.655ms | 287.195ms | true | false | acknowledged |
| 24 | 718µs | 868µs | 2.141ms | 137.388ms | 136.52ms | 373.615ms | 371.474ms | true | false | acknowledged |
| 25 | 761µs | 1.017ms | 2.496ms | 168.715ms | 167.698ms | 348.767ms | 346.272ms | true | false | acknowledged |

In the three refused runs the sentence is the sentry's own, carried back through
the helper and the contract word for word: `sandbox: policy refused: the sandbox
refused it: policy refused: the sandbox is created and a policy is honoured only
by a started one`.

## The statistics

Copied from `output.txt`. p50 is the middle element of the sorted 25 and p90 the
one nine tenths along, both by index and neither interpolated.

| | Exit attach (role network) | runsc start → the enforcing attachment | `Host.Apply` entered → returned |
|---|---:|---:|---:|
| Min | 577 µs | 112.396 ms | 258.622 ms |
| p50 | 830 µs | 151.357 ms | 338.267 ms |
| Mean | 867 µs | 149.556 ms | 338.554 ms |
| p90 | 1.043 ms | 170.845 ms | 385.397 ms |
| Max | 1.549 ms | 176.234 ms | 397.594 ms |

| push outcome | of 25 |
|---|---:|
| entered before the enforcing attachment | 25 |
| offered to the exit, a network client | 0 |
| acknowledged by the enforcing sandbox | 22 |

## Findings

1. **Every push in this experiment was the early push it is meant to be.** 25 of
   25 were entered before the enforcing attachment arrived, so nothing here rests
   on a race falling one way.

2. **The exit was never offered the document.** 0 of 25, where on master every
   such push was answered by it. That is the first piece of this ticket, measured
   rather than argued: the choice that produced ticket 26's finding 2 no longer
   exists, because a network attachment is not something a policy is pushed to.

3. **The enforcing attachment arrives in a bounded and small time.** From `runsc`
   starting: min 112.396 ms, p50 151.357 ms, mean 149.556 ms, max 176.234 ms over
   25 runs, and no run over 180 ms. Leftover 19's second-scale outlier — the one
   the ticket calls the whole question — is not reproduced in any of them, and
   the instruction to stop and report if the attach looked unbounded rather than
   merely slow is not triggered.

4. **Waiting for it is affordable.** `Host.Apply` entered to returned is p50
   338.267 ms and max 397.594 ms, well inside the ten seconds a pushing peer
   already allows. The wait is not most of that figure: most of it
   is the enforcing attach (p50 151.357 ms) plus the helper waiting for the
   sentry to listen on its control socket, and the whole of it fits inside the
   deadline the caller already gave with room over. `DefaultPushTimeout` did not
   need raising, which is the question E1 was asked.

5. **What is left of the window is the loader, not the attachment.** 22 of 25
   pushes were acknowledged by the enforcing sandbox; the other three were
   refused, and the refusal is the sentry's `the sandbox is created and a policy
   is honoured only by a started one`. So the helper had the document and could
   deliver it, and what said no was the loader not having started its workload
   yet (`runsc/boot/policy.go`). That refusal is answered by the pushing peer
   retrying — which is what the loopback proof's handshake counts record — and
   closing it would mean a verb that says "start the workload under this
   policy", which this design does not have.

6. **The exit still attaches in well under a millisecond** (p50 830 µs), so the
   ordering this experiment is about is not an artefact of a slow exit: the
   enforcing attachment is two orders of magnitude further out, and every push
   made in between now waits rather than being answered by the wrong client.

## What this does not say

Nothing about attestation: there is no tunneld here at all. The spike calls
`Host.Apply` directly, so no handshake, no peer and no verifier is in any figure
above. Nothing about a measured guest. Nothing about `x`, which the busybox
workload never execs.
