# E4 — a config device without a policy

**Question.** Ticket 22 takes `policy.json` off the config device: the policy is
pushed over the tunnel after attestation, and the egress ceiling becomes a
compiled-in constant. Two things have to be established before that change is
written:

1. what today's code does with a config device that carries **no** `policy.json`
   — which function refuses, with what sentence, and where that leaves the rest
   of the startup sequence; and
2. what today's code does with a config device that still carries one, so that
   ticket 22 knows exactly where it must plant the opposite refusal — and what
   ticket 19's recorded artefacts replay as afterwards.

Nothing in the repository was changed by this spike. Everything it produced is
under this directory.

---

## What had to be worked around, and why

Two facts about the route, both recorded because they shape every capture below.

**No sudo, no disk image, no mount.** `tunneld` takes the config device as a
*directory*: `-config` (default `/config`) and `-author` (default
`/etc/attested-tunnel/author.pub`), `attest/cmd/tunneld/main.go:165-166`. The
config device is only an ext4 image because the guest's initrd mounts one;
`docs/snp/image/mkconfigdev.sh` is a packaging step over a source directory and
nothing in the loader knows about block devices. So every C1/C2 below is a plain
directory and no privileged command was needed anywhere in this spike.

**This host is an SEV-SNP *host*, not a guest, so the serving path stops before
it reads a document.** `run()` reaches `serve()`, `serve()` calls
`newVendorSeam` (`main.go:227`) before `tunneld.New` (`main.go:239`), and
`tsm.New` probes `/sys/kernel/config/tsm/report`, which does not exist here
(configfs *is* mounted; the tsm subsystem is not registered, because no guest
driver is loaded). So a plain `tunneld -config C1` on this machine refuses at
the vendor seam and never gets as far as the policy:

```
tunneld: report interface /sys/kernel/config/tsm/report: absent (open /sys/kernel/config/tsm/report: no such file or directory) — …
tunneld: refusing to start: tsm: no report interface at /sys/kernel/config/tsm/report: this is not a confidential guest, … : mkdir /sys/kernel/config/tsm/report/tunneld-1744925-0: no such file or directory
tunneld: EXIT status=1
```

(`logs/C1-serve.txt`, `logs/C2-serve.txt` — identical for both, because the
documents are never reached.) That is not a workaround failing; it is the
ordering fact ticket 22 should know: **on real hardware the policy load is late**
— behind the run configuration, the peer table, the author key, the link, the
report-interface probe and the reference value set.

The document loads were therefore reached two other ways, both of them real code
on the real config directories:

* **`tunneld -egress print`** — the binary's own second mode. It reads the same
  documents a serving tunneld reads and calls the *same* `attest.LoadPolicyFile`
  (`attest/cmd/tunneld/egress.go:709`), but needs no report interface, no root
  and no network. This is the production path the guest's init takes first:
  `docs/snp/cloud/tdx/init.tdx:254` runs `tunneld -config /config -egress
  install` and `:258` runs `-egress probe`, before `:274` starts the serving
  tunneld. Three invocations per boot, all three reading `/config/policy.json`.
* **`drv/`** — an 82-line driver in its own module outside the repository
  (`drv/main.go`, `drv/go.mod`; nothing was added under `attest/`) that hands
  `tunneld.New` a stub `attest.Acquirer`/`attest.Verifier` and the real config
  directory. It shows the order *inside* `tunneld.New` and reports which
  sentinel the refusal carries.

---

## What was built

Seven config directories, all under `cfg/` here (each also has a
`collateral/` copied from `$REPO/docs/snp/evidence/tdx/collateral` at run time —
Intel's 10 files, referenced by path rather than copied into this spike):

| dir | set | policy | author key used |
|---|---|---|---|
| **C1** | ticket 19 scenario-one `config-src/a` (v4) + sig | **absent** | ticket 19's recorded `author.pub` |
| **C2** | same | ticket 19's recorded `policy.json` + sig | same key — signature holds |
| C2b | same | a fresh policy of today's format, throwaway key | ticket 19's key — signature fails |
| C3 | same | `policy.json.sig` **only**, no document | ticket 19's |
| C4 | same | `policy.json` **only**, no signature | ticket 19's |
| F1 | fresh `emit-refvals` v4 set, throwaway key | fresh policy, same throwaway key | throwaway |
| F2 | fresh set, throwaway key | ticket 19's recorded policy + sig | throwaway — signature fails |

`peers.json` and `tunneld.json` are written by `rerun.sh`: one peer at
`127.0.0.1:4434`, `listen 127.0.0.1:4433`, no `link`, no `exercise`, `hold 5s`.

**On authoring.** The task allowed for the ticket 19 author *private* key being
off this branch. It is not needed. Verification takes a document, a detached
signature and a **public** key, and all three are recorded:
`docs/snp/evidence/ticket19/scenario-one/author.pub` plus
`config-src/a/{reference-values,policy}.json{,.sig}`. So C1–C4 are built out of
ticket 19's own signed documents and load under ticket 19's own author key,
which makes them a truthful replay of a ticket 19 config device rather than a
reconstruction. The recorded set is **version 4**, which is the version this
branch's loader reads, so nothing about it is stale yet.

The fresh-key route was exercised as well and works: `docs/snp/image/emit-refvals`
authors and signs both documents with an `openssl genpkey -algorithm ed25519`
key (`-tcb bootloader,tee,snp,microcode` is required for a set), and F1 loads
under the matching public key. The private half is deliberately **not** kept here
— ticket 21's harness keeps none either — so the authored documents themselves
are checked in (`cfg/fresh/`) and `rerun.sh` reuses them.

---

## C1 — the config device ticket 22 wants

`$ tunneld -config C1 -author author-t19.pub -egress print` (`logs/C1-egress-print.txt`):

```
tunneld: sandbox "e4-guest-a"
tunneld: author key 665053d10032f5b9… ($W/cfg/author-t19.pub, inside the launch measurement)
tunneld: peer table: guest-b = 127.0.0.1:4434
tunneld: refusing to touch the network: attest: policy refused: reading the policy at $W/cfg/C1/policy.json: open $W/cfg/C1/policy.json: no such file or directory
tunneld: EXIT status=1
EXIT_STATUS=1
```

`$ e4drv -config C1 -author author-t19.pub` (`logs/C1-tunneldNew.txt`):

```
e4drv: tunneld.New refused: tunneld: refusing to start: attest: policy refused: reading the policy at $W/cfg/C1/policy.json: open $W/cfg/C1/policy.json: no such file or directory
e4drv: errors.Is(err, attest.ErrSetRefused)    = false
e4drv: errors.Is(err, attest.ErrPolicyRefused) = true
EXIT_STATUS=1
```

So: **the reference value set loaded** (`ErrSetRefused` is false — the C1 device
is otherwise complete and correct), and the policy is the one and only thing
standing between a policy-free config device and a running tunneld.

The code path is exact:

* `attest/tunneld/tunneld.go:190` `attest.LoadReferenceValueSetFile` — succeeds.
* `attest/tunneld/tunneld.go:194` `attest.LoadPolicyFile(cfg.PolicyPath, …)` — refuses.
* → `attest/policyfile.go:379` `LoadPolicyFile` → `attest/refvalsfile.go:460`
  `readSignedDocumentPair`, and the sentence comes from **`attest/refvalsfile.go:463`**:
  `kind.refuse("reading the %s at %s: %v", kind.what, path, err)`, with
  `kind` = `policyDocumentKind` (`attest/policyfile.go:397`) and
  `refuse` = `refusePolicy` (`attest/policyfile.go:183`), which is what stamps
  `attest: policy refused:` and `attest.ErrPolicyRefused` onto it.
* The path itself is built at **`attest/cmd/tunneld/main.go:244`**,
  `PolicyPath: filepath.Join(o.configDir, policyName)`, from
  `policyName = "policy.json"` at `main.go:120`. The `-egress` modes build the
  same path independently at `attest/cmd/tunneld/egress.go:708`.

Note the deliberate design property this refusal has, spelled out in the doc
comments at `policyfile.go:372-378` and `refvalsfile.go:451-459`: a missing
document does **not** wrap `io/fs.ErrNotExist`, precisely so no caller can write
`if errors.Is(err, fs.ErrNotExist) { proceed without one }`. Ticket 22 cannot
get its behaviour by catching an absence; it has to stop calling the loader.

---

## C2 — a policy still on the device

`$ tunneld -config C2 -author author-t19.pub -egress print` (`logs/C2-egress-print.txt`):

```
tunneld: policy $W/cfg/C2/policy.json loaded under the author key; digest d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b
tunneld: policy egress: version 1, unattested egress permitted: false
tunneld: sandbox "e4-guest-a" listens on udp/4433; 1 peer(s) in the table
tunneld: EGRESS RULES as the signed policy and the peer table imply them:
table inet attested_tunnel { … }        (the full rule set is in the log)
tunneld: EXIT status=0
EXIT_STATUS=0
```

`$ e4drv -config C2 -author author-t19.pub` (`logs/C2-tunneldNew.txt`):

```
e4drv: tunneld.New refused: tunneld: refusing to start: ratls: acquiring evidence: E4 stub acquirer: this host has no report interface; reaching this line means both config-device documents loaded
e4drv: errors.Is(err, attest.ErrSetRefused)    = false
e4drv: errors.Is(err, attest.ErrPolicyRefused) = false
EXIT_STATUS=1
```

**Today a stale policy is accepted silently and used.** It is loaded, its digest
becomes this sandbox's identity (`tunneld.go:202-204`,
`ratls.NewIdentity(ctx, cfg.Acquirer, policy.Digest)`), its `forward_to` gates
every dial, and its `egress` section generates the netfilter rule set that is
installed in the guest's kernel. There is nothing to notice: the console line
says "loaded under the author key", which is true, and says nothing about the
document being from a previous ticket's world. That is the gap ticket 22 closes.

Signature behaviour, both directions (the task asked for both):

| dir | what changed | outcome |
|---|---|---|
| **C2** | ticket 19's policy + sig, under ticket 19's author key | **accepted**, digest `d47dce59…`, exit 0 |
| **C2b** | a *valid* policy of today's format signed by a different key | **refused**: `attest: policy refused: the signature is not this reference value author's signature over these bytes; either the document was modified in delivery, or it was signed by a different key, or it is a signature over some other document this author signed — a reference value set's signature is not a policy's, and each covers its own domain` |
| **F1** | fresh set *and* fresh policy, both under the throwaway key | **accepted**, digest `50623144…`, exit 0 |
| **F2** | fresh set, but ticket 19's policy beside it | **refused**, same sentence as C2b |
| **C3** | `policy.json.sig` alone, no document | **refused**: `attest: policy refused: reading the policy at …/policy.json: open …: no such file or directory` — *identical to C1's refusal*; the orphaned signature is never looked at |
| **C4** | `policy.json` alone, no `.sig` | **refused**: `attest: policy refused: reading the signature at …/policy.json.sig: open …: no such file or directory` |

The refusal sentence comes from `verifySignedDocument`
(`attest/refvalsfile.go:437`, the `ed25519.Verify` branch at `:445-447`) reading
`policyDocumentKind.notSigned` (`attest/policyfile.go:401-405`). Whose key signed
the set is irrelevant to whether the policy loads: the two documents are checked
independently, under two domain-separation prefixes, against the same author key.

---

## Finding 1 — the loader change

**What today does.** `policy.json` is a *required* document of the config device,
read at three places, all reached on every guest boot:

| site | call | reached by |
|---|---|---|
| `attest/tunneld/tunneld.go:194` | `attest.LoadPolicyFile(cfg.PolicyPath, cfg.AuthorPublicKey)` | the serving tunneld (`init.tdx:274`) |
| `attest/cmd/tunneld/egress.go:709` | `attest.LoadPolicyFile(policyPath, author)` | `-egress install` (`init.tdx:254`) |
| `attest/cmd/tunneld/egress.go:709` | (same line, second mode) | `-egress probe` (`init.tdx:258`) |

fed by `PolicyPath` (`attest/tunneld/tunneld.go:107-112`, set at
`attest/cmd/tunneld/main.go:244`) and `policyName` (`main.go:120`,
`egress.go:708`).

**What ticket 22 must do.**

1. *Remove the requirement.* `tunneld.Config.PolicyPath` and the
   `LoadPolicyFile` call at `tunneld.go:194` go away, and with them `main.go:244`.
   The policy arrives over the tunnel after attestation instead. Everything
   downstream of the load in `New` needs a policy value from somewhere else:
   `ratls.NewIdentity(…, policy.Digest)` at `:202-204`, `forwardTo(policy)` at
   `:220`, `t.policy` at `:224`, and `PolicyDigest()`/`ForwardTo()` at
   `:259`/`:270`. That is the shape question E2 is answering; E4 only establishes
   that the *load* is the single blocking call, because C1 proves everything
   before it succeeds on a policy-free device.
2. *Plant the opposite refusal.* Removing the load alone would make a device that
   still carries `policy.json` load **silently** — the C2 capture shows how much
   behaviour that document currently drives, so silence is the worst outcome.

**Where the refusal belongs: `run()` in `attest/cmd/tunneld/main.go`, by `stat`,
between line 191 (`readAuthorKey`) and line 208 (the `-egress` mode split).**
The reasoning, all of it from the captures and the code above:

* **`stat`, not the loader.** After change (1) nothing calls `LoadPolicyFile` on
  a config-device path at all, so there is no loader left to refuse in. The
  refusal has to be a presence check on a file nobody reads. (`LoadPolicyFile`
  itself should survive for the pushed policy — the same document kind, the same
  domain-separated signature — but it will be handed bytes from the tunnel, not
  a config-device path.)
* **`main.go`, not `attest/tunneld`.** The config device's *layout* is this
  command's business and is documented only here: `main.go`'s package comment
  lists every path and `main.go:106-121` holds the constants.
  `attest/tunneld.New` never knows a directory, only explicit paths, so a check
  there would be checking something it was not told.
* **Before the mode split.** One check at `main.go:~207` covers all three of the
  guest's per-boot invocations. Put it inside `serve()` and `-egress install`
  still runs against a stale device; put it inside `runEgressMode` and the
  serving tunneld does.
* **Stat both names.** C3 is the case that decides this. Today a device carrying
  only `policy.json.sig` produces a refusal that names the *document* as missing
  — the orphan signature is invisible. After ticket 22, a check that stats only
  `policy.json` would let a half-updated device through carrying a stale
  `policy.json.sig`, which is exactly what a partial config-device update leaves
  behind. Refuse on either name, and name the one that was found.
* **The message.** It must name ticket 22, because the operator holding that
  device built it from a script that is still correct for the old world
  (`docs/snp/image/mkconfigdev.sh:12-14,30`,
  `docs/snp/cloud/tdx/mkconfigdev-tdx.sh:11-13,54`, and the emitters
  `docs/snp/cloud/tdx/emit-tdx-documents.sh`, `build-tdx-image.sh`,
  `docs/snp/image/build-image.sh`, `package-tunneld.sh`). Something of the shape:
  `refusing to start: the config device carries policy.json (removed in ticket
  22): the policy is pushed over the tunnel after attestation and the egress
  ceiling is compiled in; re-build the config device without it`.

Two smaller notes for whoever writes the change:

* `runEgressMode` (`egress.go:707-716`) does not merely *read* the policy, it
  derives the rule set from `policy.Egress`. With the ceiling compiled in,
  `buildEgressRuleSet` (`egress.go:151`) needs the constant instead of
  `attest.Policy`, and the two console lines at `egress.go:714-715`
  ("policy … loaded under the author key; digest …" / "policy egress: version …")
  are the exact lines in `logs/C2-egress-print.txt` that must stop being printed.
* `main.go:239-250`'s log block prints `td.PolicyDigest()` and
  `td.ForwardTo()` at startup (`logStartupSummary`, `main.go:356`). Those
  numbers currently come off the config device; after the change they come off
  the pushed policy and so move later in the transcript, which every recorded
  console in `docs/snp/evidence/ticket19/*/console-*.txt` will differ by.

---

## Finding 2 — what ticket 19's recorded artefacts replay as

Two different kinds of ticket 19 artefact, with two different answers.

### (a) The recorded **config sets** become older-format records

`docs/snp/evidence/ticket19/{scenario-one,scenario-two,scenario-three}/config-src/{a,b}/`
and `docs/snp/evidence/ticket19/smoke/config-src/` each hold a complete config
device *source*: `reference-values.json(+.sig)`, `policy.json(+.sig)`,
`peers.json`, `tunneld.json`, `network.conf`. This spike's **C2 is one of them**,
and it loads today (exit 0, digest `d47dce59…`). After ticket 22 the same
directory becomes exactly the C2 case the new check refuses: a device that
carries a policy. That is the intended outcome — they are records of what ticket
19 ran, not inputs anything re-runs. Nothing in the tree feeds a `config-src`
directory back into `tunneld`; the scripts that *build* such a directory
(`mkconfigdev.sh`, `mkconfigdev-tdx.sh`, `run-tdx-scenario.sh:396`,
`smoke-tdx-guest.sh:125-128`) all build a fresh one, and each of those scripts is
a site ticket 22 has to update. Their `README.txt` should gain the sentence that
these are pre-ticket-22 devices.

### (b) The recorded **verdict invocations** are untouched

The replay harness is `docs/snp/evidence/ticket21/harness/replay-verdicts.sh`
over `verdict-invocations*.txt`. The key fact, checked rather than assumed:
**`attest-tool verify` has no flag that takes a policy *file*.** Its complete
flag set is `attest/cmd/attest-tool/verify.go:77-90`: `-bundle -evidence -chain
-key -refvals -author -vendor-root -product-line -without-chain -now -vendor
-tdx-collateral-dir -tdx-root -policy-digest`. The only policy input is
`-policy-digest HEX` (`verify.go:90`), parsed by
`attest.ParsePolicyDigest` via `attest/cmd/attest-tool/acquire.go:202-211`
(`attest/policyfile.go:123`). `verify` never opens a policy document; it compares
a digest against `ReferenceValue.PolicyDigest` from the allow-list.

Counted over the lists:

| list | rows | carry `-policy-digest` | carry a policy **file** |
|---|---|---|---|
| `verdict-invocations.txt` | 111 | 52 | **0** |
| `verdict-invocations-v2.txt` (live) | 64 | 51 | **0** |
| `verdict-invocations-retired.txt` | 47 | 1 | **0** |

and the 51 live digest-bearing rows break down as:

* **41** pass `d47dce59f26635e9b4cd0c375cc73f32a39ef85d55223143cad438a075aee92b`
   — which is precisely
   `emit-refvals -digest-of docs/snp/evidence/ticket19/scenario-one/config-src/a/policy.json`
   (and the smoke guest's), the same number C2's startup line printed above;
* **7** pass `444a4aa826ae40b5cc4332df842f0cea17e02a51f6d8f30f2385daf051561f28`
   — guest-b's recorded policy digest;
* **2** are digest-*parser* negatives — `snp-t05-badhex` (`-policy-digest zz`)
   and `snp-t05-shortdigest` (`abcd`), both of which exit 1 before any
   verification happens — and **1**, `snp-t05-v2-zerodigest`, passes 32 zero
   bytes, which parses and then loses on the allow-list (exit 3);
* the other **13** rows pass none.

Both real digests also appear verbatim as `policy_digest` fields inside ticket
19's recorded reference value sets, which is the allow-list field the ticket
keeps.

**So: every one of the 111 recorded invocations replays unchanged after ticket
22, and none would be affected by `-policy FILE` going away, because no such
flag exists and no row passes one.** The three parser negatives are in fact the
regression test for the half the ticket promises to keep: the two parser rows
exercise `attest.ParsePolicyDigest` directly and must keep printing
`verify-evidence: -policy-digest is not hexadecimal: encoding/hex: invalid byte:
U+007A 'z'` and `verify-evidence: -policy-digest is 2 bytes; a policy digest is
32`, and the zero-digest row must keep reaching the allow-list comparison.

A today-baseline was taken so that the post-change run has something to diff
against — the 64 live invocations, replayed against this branch's `attest-tool`
(`logs/replay-v2.txt`, `replay/INDEX.txt`, `replay/COMMANDS.txt`):

```
invocations: 64
exit status histogram:
  exit 0: 8      accepted
  exit 1: 15     not a verdict: 4 usage dumps, 4 missing/bad input files, 2 digest-parse
                 negatives, 1 bad vendor, 4 tdx flag/collateral negatives
  exit 2: 37     refused
  exit 3: 4      reference value set refused
```

The one thing on this list that ticket 22 *could* disturb is `-refvals`, not
`-policy-digest`: 4 rows read the throwaway sets in `harness/authored/`, and 2
rows (`tdx-smoke-configsrc-set`, in both lists) read
`docs/snp/evidence/ticket19/smoke/config-src/reference-values.json` — a reference
value set out of a ticket 19 config-src. Ticket 22 removes the *policy* from
those directories' meaning, not the set, so those rows are fine; they are listed
here only so that nobody removes a `config-src` directory wholesale.

---

## Rerun

Everything here is reproduced by one script, which was itself run end to end
after being written (identical digests, identical refusals, identical replay
histogram):

```
export PATH="/usr/local/go/bin:$PATH"
bash docs/snp/evidence/ticket22/spikes/E4/rerun.sh /tmp/e4        # or no argument for a mktemp -d
```

It honours `REPO` (default `/home/pniroula/Projects/gvisor-t22`) and `GO`
(default `/usr/local/go/bin/go`), builds `tunneld`, `attest-tool`, `emit-refvals`
and the stub-seam driver, lays out all seven config directories, writes every
transcript into `$W/logs/`, and replays the 64 live verdict invocations.

The individual commands, if you want one of them by hand (`$W` is the workdir):

```
# build
cd $REPO/attest && go build -o $W/bin/tunneld ./cmd/tunneld
cd $REPO/docs/snp/image/emit-refvals && GOFLAGS=-mod=mod go build -o $W/bin/emit-refvals .

# C1: the policy-free device, through the mode that needs no report interface
$W/bin/tunneld -config $W/cfg/C1 -author $W/cfg/author-t19.pub -egress print

# C1: the serving path (stops at the vendor seam on any non-guest host)
$W/bin/tunneld -config $W/cfg/C1 -author $W/cfg/author-t19.pub \
               -tdx-collateral-dir $W/cfg/C1/collateral

# C1/C2: the order inside tunneld.New, with the vendor seam stubbed
$W/bin/e4drv -config $W/cfg/C1 -author $W/cfg/author-t19.pub

# ticket 19's recorded verdicts
REPLAY_REPO=$REPO \
REPLAY_LIST=$REPO/docs/snp/evidence/ticket21/harness/verdict-invocations-v2.txt \
REPLAY_AUTHORED=$REPO/docs/snp/evidence/ticket21/harness/authored \
  bash $REPO/docs/snp/evidence/ticket21/harness/replay-verdicts.sh \
       $W/replay-v2 $W/bin/attest-tool verify
```

## Caveats

* Absolute paths in `logs/` and `replay/` were rewritten to `$W/` and `$REPO/`
  after capture; nothing else in them was touched.
* `docs/snp/evidence/tdx/collateral/` showed as modified in this worktree while
  these captures were taken (7 files, concurrent ticket 22 work) and matches the
  committed bytes again now; `MANIFEST.sha256` records its hashes either way, and
  they are the committed ones. The collateral is never reached by any capture
  here — `tsm.New` fails before `verify.NewTDX`, and `-egress print` builds no
  verifier — so it could not have affected a result.
* `-tdx-collateral-dir` is an ordinary flag defaulting to empty
  (`main.go:169`); collateral is **not** part of the config-device documents the
  loader reads, and a tunneld started without it simply admits no Intel TDX peer
  (`main.go:336-343`). It was still copied into each `C*/collateral` so that each
  directory is a complete config device in `mkconfigdev-tdx.sh`'s layout, which
  is what `init.tdx:274` passes.
* The replay histogram is a baseline from *this* branch, not a comparison with
  ticket 21's recorded diff.
