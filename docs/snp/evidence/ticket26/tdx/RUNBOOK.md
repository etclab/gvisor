# The TDX run of ticket 26, in one dispatch

Ticket 26's definition-of-done item: *the proof on two Google Cloud TDX guests —
`agent-probe` completing a task agent-to-agent over the tunnel under a pushed
policy; an off-policy control; a narrowing mid-run; and a liveness teardown after
the workload is killed.*

**What the hardware run actually proves, and what it does not.** The compiled-in
egress ceiling (`attest/ceiling/ceiling.nft`) permits **no TCP egress at all**
from a measured guest: the output chain rejects every TCP packet with a reset
before it reaches any accept, and the only thing granted is `udp/4433` on `eth0`
plus loopback. So nothing inside a measured guest can reach `api.anthropic.com`,
and the workload on hardware is the page fetch — ticket 25's shape — and not a
model call. **The model-backed `agent-probe` run is proven on loopback only**
(`docs/snp/evidence/ticket25/loopback/`, `docs/snp/evidence/ticket25/claude-smoke/`),
where the host's own network is underneath the adapter. Write that sentence into
this run's `notes.md`: the hardware answers "is the policy enforced by a measured
sentry, and can it be replaced under a live workload", and the loopback answers
"does a real agent complete a task through it". Neither run answers the other's
question, and a record that blurred them would be claiming a TDX guest reached
Anthropic.

The `agent-probe -network plain -task summarize` attempt inside the guest is
**deliberately skipped on hardware.** It would show one thing — a TCP reset at
the exit, from the ceiling — and that is already recorded as the egress proof at
step 7 of every boot, with the errno, thirty times over.

## 0. What this needs from the rest of the ticket

Identical to `../snp/RUNBOOK.md` §0, and read that table first. Two of its four
rows have landed and were checked against the tree rather than assumed: the
eleventh refusal reason is `attest/refusal.go:147`, *"the policy pushed to the
peer is no longer live"*, wired at `attest/tunneld/push.go:256`; and the exec
sink's point is `sentry/exec_refused` with `reason="not-in-x"`. The two that had
not landed when this was written are runsc itself — build it and check
`runsc flags` — and, the one that matters here:

> **`Host.Apply` logs nothing.** `SANDBOX applied format=… version=… bytes=…
> sha256=…` exists only in `attest/sandbox/null.go:115`, and the adapter path
> uses `Host`. Five assertions in the runner read the digest off that line, and
> without it the run has no console evidence that the sandbox took the policy at
> all — on a vendor where the console is the whole record. Ask the contract agent
> for the same four fields on the `Host` path before booting anything.

The TDX runner reads the refusal sentence out of one variable,
`LIVENESS_REASON`, for the same reason the SNP harness does.

One more, TDX-only: **the image must be built from this branch.** Ticket 19's and
ticket 24's TDX images carry no `agent-probe`, no `/srv/index.html` and no
`/etc/hosts`, so their exits have nothing to serve and nothing to resolve. The
runner checks the manifest for the first two and refuses to create an instance
otherwise.

## 1. Collateral, first, and on the same day

Intel's provisioned documents expire, and past that instant every TDX peer is
refused as `ChainNotRooted` however healthy it is (ADR-0007). The copy in
`docs/snp/evidence/tdx/collateral/` was fetched **2026-09-18T08:51:43Z** and is
valid until **2026-10-18T07:56:25Z**, the TCB info's `nextUpdate` and the
earliest of the four. The runner reads that date out of
`tcbinfo-00806f050000.body` and refuses to create anything past it.

The ticket asks for fresh collateral *the same day as any TDX run*. **If the
calendar day has changed since the last fetch, re-fetch before anything else.**
It is four requests, still `curl` and not `attest-tool provision fetch` — that
subcommand is the AMD chain tool, takes `-report REPORT.bin -out DIR`, parses an
SEV-SNP report and has no vendor flag, so it cannot be asked for a TCB info, a QE
identity or a CRL. That deviation is ticket 22's and is carried forward;
`docs/snp/evidence/ticket24/collateral-refresh.txt` is the worked record of the
last one and has the whole argument.

```
cd docs/snp/evidence/tdx/collateral
curl -sS -D tcbinfo-00806f050000.headers -o tcbinfo-00806f050000.body \
  'https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00806f050000'
curl -sS -D qeidentity.headers -o qeidentity.body \
  'https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity'
curl -sS -D pckcrl-platform.headers -o pckcrl-platform.body \
  'https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der'
curl -sS -D rootcrl.headers -o rootcrl.body \
  'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der'
```

Then append a dated section to that directory's `FETCH.txt` in the shape the
three before it have — the four URLs, the status, the byte counts, the
`Date:` headers and the four `sha256` lines — write
`docs/snp/evidence/ticket26/tdx/collateral-refresh.txt` in the shape of ticket
24's (the new window, whether any TCB moved, `go test ./... -count=1` in
`attest/`, and one `attest-tool verify -vendor intel-tdx` against the refreshed
directory), and update the expiry in ADR-0007's status line. If
`tcbEvaluationDataNumber` moved off 20, **stop**: a reference value's floor would
have to move and that is a decision, not a step.

## 2. Before you start

```
export PATH=/usr/local/go/bin:$PATH
export STACK=/home/pniroula/Projects/gvisor/.scratch/attested-secure-tunnel/host-stack
export SCRATCH=<a directory outside the repo>
cd /home/pniroula/Projects/gvisor-t26
```

| | |
|---|---|
| the adapter's runsc | `make runsc` → `bazel-bin/runsc/runsc_/runsc`, static, and `runsc flags` lists `-tunnel-socket` and `-tunnel-table`. On TDX this binary goes **into the initrd**, so it is 108 MB of RTMR2. |
| the pinned base image | `$STACK/…/base-disk.raw`, sha256 `d0b2b2c29a0bcc42c9dc414706b2b45af99fabf375150afaabcd59cd0785474f`; the build refuses any other |
| an author key | a fresh one for this ticket, or ticket 24's. **The same key must be given to the build and to the runner**: its public half goes into the initrd at `/etc/attested-tunnel/author.pub` and is therefore inside RTMR2, so signing a set with a different one produces a set the guest will not read. To make a new one: `mkdir -p $STACK/image-ticket26-tdx && openssl genpkey -algorithm ed25519 -out $STACK/image-ticket26-tdx/author.key` |
| `gcloud` | authenticated, project `nsf-2348130-428843`. Workspace reauth expires; run `gcloud compute instances list` once before you start, so that a login prompt does not arrive in the middle of a paid instance's life |
| the firewall | already open and not created here: `default-allow-internal` covers `10.128.0.0/9` and `attested-tunnel-udp-4433` opens the port |
| the pre-existing VMs | `eval-vm`, `listener`, `relay`, `trusted-vm`, `trusted-vm-smh`, `untrusted-vm`, `untrusted-vm-smh` are **never touched**. They were TERMINATED before this study started and are left that way |

## 3. The image

```
AUTHOR_KEY=$STACK/image-ticket26-tdx/author.key \
OUT=$STACK/image-ticket26-tdx/image \
BASE_IMAGE=$STACK/<the pinned base disk>.raw \
RUNSC=/home/pniroula/Projects/gvisor-t26/bazel-bin/runsc/runsc_/runsc \
IMAGE_LABEL=t26 \
  bash docs/snp/cloud/tdx/build-tdx-image.sh
```

`TUNNELD` and `AGENT_PROBE` are deliberately not set: the build runs
`go test ./cmd/tunneld` — ticket 14's import-graph and packaged-artifact guards —
before it builds anything, builds both statically, refuses a binary that embeds
the checkout path, and measures them afterwards. It predicts RTMR2 from the built
`disk.raw` with `predict-rtmr2.py --raw`, offline, with no machine consulted, and
emits the signed set and policy beside the image.

Three things to read out of `manifest.txt` before going further:

```
predicted_rtmr2:              the number the hardware must report
/usr/bin/agent-probe          present — ticket 19's image had none
/srv/index.html               present — likewise
provider constants pinned:    rtmr0 c2fc12a5…850a   (two disks)
                              rtmr0 8ee4fa36…b70a3f (three disks — ticket 26 authored this)
```

**Both RTMR0 values must be there.** A set with only the two-disk value refuses
every guest of this run on RTMR0 alone, which is exactly what happened to ticket
24 twice; `RTMR0-DECISION.md` beside this file is the decision and the argument.
The runner checks for the three-disk value in `reference-values.json` and refuses
to create an instance without it.

## 4. The workload disk

Built by the runner, or by hand first if you want to read the listing:

```
bash docs/snp/evidence/ticket26/snp/make-bundle.sh $SCRATCH/workload-src $SCRATCH/workload-tdx.raw -tdx
```

`-tdx` is the only difference from the SNP disk: one gibibyte instead of
sixty-four mebibytes, because Google's smallest pd-balanced disk is 10 GB and a
custom image's raw must be a whole gibibyte. **The bundle inside is byte for byte
the same**, which is what lets the two recorded runs be compared. Read the two
digests it prints — `/bin/busybox` and `/bin/probe` must differ, and the script
refuses to build a bundle in which they do not.

## 5. The run, printed before it is paid for

```
IMAGE_DIR=$STACK/image-ticket26-tdx/image \
KEY=$STACK/image-ticket26-tdx/author.key \
BUNDLE_SRC=$SCRATCH/workload-src \
OUT=docs/snp/evidence/ticket26/tdx/run \
  bash docs/snp/cloud/tdx/run-tdx-t26.sh policy -dry-run
```

**Read the dry run before the real one.** It prints every gcloud mutation, every
publish, both instance creates with their three `--create-disk` arguments, the
five derived numbers and the three policy digests, and it creates nothing. Check
in particular: the boot image name matches the predicted RTMR2's first twelve
characters; both instances carry `--labels purpose=attested-tunnel-t26`; each has
exactly three disks; the private IPs are `10.128.0.40` and `10.128.0.41`.

Then, with the same environment and without `-dry-run`:

```
IMAGE_DIR=… KEY=… BUNDLE_SRC=… OUT=… bash docs/snp/cloud/tdx/run-tdx-t26.sh policy
```

**Write the create row into `docs/snp/cloud/tdx/RESOURCES.md` the moment the
instances exist**, not afterwards: the ledger is a running note and a script that
edited it would be claiming an instance was gone before the delete returned. The
runner prints both rows at the end, filled in; the create timestamp is in the
transcript as soon as it happens.

`-keep` leaves both instances running for debugging. If you use it, delete them
by hand **the same hour they were created** and say so in the ledger.

Budget: the two guests live about eleven minutes (the hold is 360 s and guest B
is killed at 210 s), plus a few minutes for four image publishes. Ticket 24's
whole E4 was about eleven `c3-standard-4` TDX instance-minutes; this is one run
of roughly twenty-two.

## 6. What the run does, in order

1. preconditions — image files, author key, collateral **expiry**, the three-disk
   RTMR0 in the emitted set, `agent-probe` and `/srv/index.html` in the manifest,
   and the five numbers derived from the config devices' two knobs.
2. the workload disk from the bundle (or `WORKLOAD_RAW`).
3. the four signed documents: a probe pair to learn the two policy digests, then
   the real pair, each set naming the **other** guest's digest. Both sets admit
   the same measurement, because both guests boot the same image; what makes the
   two digests two numbers is that B's policy forwards to one extra measurement
   naming no image anybody has.
4. the two config devices — `env -u LABEL` around `mkconfigdev-tdx.sh`, because
   this script's `LABEL` is a Compute Engine resource label and that script's is
   an ext4 volume label, and leaving it through cost ticket 24 an instance.
5. four image publishes; each makes a bucket, uploads, creates the image and
   deletes the bucket.
6. both instances, created in parallel, three disks each.
7. both serial consoles, **incrementally**, by byte offset, stopping at
   `^initrd: EXIT status=` with a tail chase and one whole-buffer recovery read
   afterwards that is kept only if it is strictly longer.
8. both quotes off the consoles, judged here twice each — against the guest's own
   set (refused on the policy digest, which is what mutual pinning means) and
   against the peer's (admitted, which is the check that matters).
9. the pass table.
10. teardown: both instances, then only the images **this run created** — a boot
    image that already existed is one a previous run kept on purpose, and ten
    gibibytes is the one cost this project refuses to pay twice.

## 7. The pass criteria

Read `../snp/RUNBOOK.md` §7: the six groups are the same claims with `initrd:`
where the SNP console says `init:`, plus four that only TDX can make:

- `guest A's quote reports the three-disk RTMR0 this ticket authored`, and guest
  B's too — the first run of this project on a shape whose RTMR0 its own set
  names.
- `guest A's quote is admitted by the set guest B holds`, and the mirror. These
  are `attest-tool verify -vendor intel-tdx` on this workstation, exit 0.
- both self-checks **REFUSED on the policy digest**, with the measurement
  matching. Expected, and it is what "each pins the other" means.
- `initrd: workload device … mounted at /workload (ro,exec,nosuid,nodev; not
  measured)` — the one mount in the guest that permits exec, and the reason there
  is a third disk at all.

## 8. What to copy into the evidence

The runner writes into `OUT` already: `tunnel-run.txt` (the whole transcript),
`console-{a,b}.txt`, `quote-{a,b}.bin`, `quote-{a,b}.txt`,
`public-key-{a,b}.der`, `verify-evidence-{a,b}.txt`, `measurements.txt`,
`egress-{a,b}.txt`, `set-{a,b}.json(+.sig)`, `policy-{a,b}.json(+.sig)`,
`author.pub` and `config-src/` as delivered (minus the collateral, which is byte
for byte `docs/snp/evidence/tdx/collateral` and is listed file by file with its
sha256 on each console).

Add by hand:

- `manifest.txt` and `packaging.txt` from step 3;
- the bundle listing and the two digests from step 4;
- the dry-run transcript from step 5, beside the real one;
- `notes.md` in the shape of `docs/snp/evidence/ticket24/spikes/E4/notes.md`:
  the four things the run set out to show and what each console said, the
  timings off the initrd's own clock, the RTMR table, **the paragraph about the
  ceiling and the model call** from the top of this file, and a "what did not
  hold" section;
- the two `workload: OBSERVE exec` lines, whichever way they came out.

**Never trim an output.** Grep every file for the API key before `git add`, even
though this run cannot contain one.

## 9. The ledger

`docs/snp/cloud/tdx/RESOURCES.md` has a ticket 26 section header and no rows.
The discipline, which the ticket makes a constraint:

- one row per instance, image and bucket, **written on create**, with the
  creation timestamp;
- the `state` column completed **on delete**, in bold, with the deletion
  timestamp and the elapsed minutes;
- every instance deleted **the same hour it was created**;
- a closing "State after …" paragraph giving the total instance-minutes and the
  teardown confirmations as the commands printed them — `gcloud compute images
  list --no-standard-images`, `gcloud compute instances list --zones
  us-central1-a`, `gcloud compute disks list --filter="name~t26"`, and
  `--filter=labels.purpose=attested-tunnel-t26` for both instances and disks.
  Ticket 24's closing paragraph is the model.

The inventory command for this ticket:

```
gcloud compute instances list --filter="labels.purpose=attested-tunnel-t26"
```

The runner prints its rows already filled in; a person writes the ledger.

## 10. If something fails

Everything in `../snp/RUNBOOK.md` §8 applies, plus:

| symptom | where to look |
|---|---|
| both guests `SELFCHECK VERDICT REFUSED reason=launch measurement not in the reference value set` | read the RTMR0 line beside it. If it is `8ee4fa36…b70a3f`, the set was built without this branch's `build-tdx-image.sh`. Note that `reason=` does **not** name the register (ticket 19's and ticket 24's leftover 4), and a reader who takes it at face value will look at RTMR2, which was right. |
| the guest halts looking for `attested-config` | the ext4 volume label was overwritten — `LABEL` leaked into `mkconfigdev-tdx.sh`. The runner wraps that one call in `env -u LABEL`; check nothing else exports it. |
| `pivot_root failed, make sure that the root mount has a parent` | the bind-and-chroot dance in `init.tdx` was lost. It is three operations and each carries weight (ticket 24, E5). |
| the console ends before `initrd: EXIT status=` | Compute Engine serves an empty body for a stopped instance. The watcher chases the tail for 90 s and then does one whole-buffer read; if the tail is still missing, the guest's last lines are simply not retrievable and the record says so, as ticket 19's and ticket 24's do. |
| every TDX peer refused as `ChainNotRooted` | the collateral expired. §1. |
| a delete fails | say so in `RESOURCES.md`, in bold, and delete it by hand. An instance nobody wrote down is the one failure mode this ledger exists for. |
