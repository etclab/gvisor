# Shrink

**Nothing here changes what the code does.** Ticket 21 removed what twenty tickets left behind
that the design no longer stands on, so that what remains is the mechanism for one sentence: *a
sandbox may dial only a sandbox whose hardware-signed boot measurement and policy digest are on
its own signed list.* Every deletion was made against the ticket's three-part rule — no live
script under `docs/snp/` invokes it, no test imports it, no non-test package imports it — and the
rule is cited, per file, in the commit that removed it. What proves the behaviour did not move:
`go test -count=1 ./...` in `attest/` passes uncached; the three guard tests pass on their own and
now name `internal/snpfake`, `internal/tdxfake` and `internal/fixture`; of the 111 recorded verdict
invocations, 64 survive the removal of `-binding-version` and 60 of those replay byte-identically
from line 2 on, the other four being the usage dumps that lose exactly the deleted flag's own two
help lines and the closing sentence of `-policy-digest`'s; the 47 retired invocations each print
`flag provided but not defined: -binding-version` and exit 1; thirteen ticket 19 verdict blocks
replay character-for-character, including their refusal sentences; and
`ripwire attest --quality-delta=92658f502..HEAD` reports `gating="0" stale="0"`. The measurements
are under `docs/snp/evidence/ticket21/{before,after}/`, and the verdict harness that produced them
is under `docs/snp/evidence/ticket21/harness/` so a later ticket can re-run the same diff.

## The numbers

| | before, `205fd2154` | after, `e35a3cdc4` |
|---|---|---|
| Go packages under `attest/` | 13 | 12 |
| exported top-level symbols in package `attest` | 63 | 58 |
| exported methods in package `attest` | 18 | 18 |
| non-test Go lines, all of `attest/` | 11,969 | 12,210 |
| non-test Go lines, minus `attest/tsm/` | 11,302 | 11,543 |
| non-test Go lines, root package only | 2,947 | 2,992 |
| test Go lines, all of `attest/` | 10,345 | 10,162 |
| test Go lines, minus `attest/tsm/` | 9,307 | 9,142 |
| test Go lines, root package only | 4,662 | 4,569 |
| Go files, non-test / test | 33 / 24 | 35 / 25 |
| test function names | 476 | 476 |
| the two fakes, non-test lines | 1,396 | 1,363 |
| fake functions the coverage profile lists | 41 | 39 |
| `attest/.ripwire_quality_acks`, ack lines | 122 | 80 |
| the verdict tool's `verify.go` | 592 | 516 |

The one number that went the wrong way is non-test lines, and it went the wrong way on purpose.
The builders nine test files had each written for themselves are now 233 non-test lines in
`internal/fixture`, a package rather than a `_test.go` file because four test packages need them.
Test lines fell by 183, non-test rose by 241, and the module's Go total is 58 lines larger than it
was. What actually went is not in this column: three command packages, one flag, six exported
names, two fake exports, a C placeholder, a cross-check tool, a stock-guest harness with a
nine-megabyte binary, three probe scripts, and 42 ack-ledger lines. No target number was set for
any count and no deletion was justified by one.

`attest/tsm/tsm.go` is byte-for-byte unchanged at 667 lines; only its two test files moved onto
the fixture package.

| `ripwire attest --clones --limit=400` | before the fixture package | at HEAD |
|---|---|---|
| rows | 158 | 113 |
| `groups` | 12 | 5 |
| `clone_groups` | 42 | 41 |
| `dup_loc` | 1,605 | 1,442 |
| `dup_pct` | 12.7 | 11.5 |

| `ripwire attest --quality-delta=92658f502..HEAD` | before | after |
|---|---|---|
| regressions | 158 | 179 |
| preexisting-worse (gating) | 0 | 0 |
| new-symbol (never gate) | 158 | 179 |
| acked | 122 | 80 |
| stale | 0 | 0 |
| renames read | 0 | 6 |
| foreign-acks | — | 1 |

Both ends of that table are green, and the middle of it was not. Re-running the range after the
eight item commits landed put 44 rows into `preexisting-worse` and 74 ledger lines into `stale`,
because a clone ack keys on a hash of its member set and is never re-filed across a rename: items
1, 4 and 5 renamed or dissolved every group ticket 20 had accepted. The ledger was rebuilt in
`e35a3cdc4` — nine churn acks deleted (churn cannot be measured in the range form at all, and this
project does not ack churn rows), 74 stale lines deleted, and 45 rows re-acked narrowest scope
first so that no entry absorbed another's rows. 26 went under `*_test.go` with ticket 20's
table-driven-scenario reason, every member resolved to a definition in a test file first; 13 under
`internal/fixture`, each a fixture builder against the per-package helper it replaced; and five as
exact pairs with reasons of their own (`Detail | ReasonOf`, `Detail | refusal`,
`defaultConfig | newAcquirer`, `loadPolicy | loadReferenceValueSet`). The one `foreign-acks` row is
ticket 20's `productFms | tdxHex`, still filed under `by=snpfake/snpfake.go`; the package moved and
the row did not, and it is left as it is.

| Delta Maintainability Model | dmm | size | complexity | interfacing |
|---|---|---|---|---|
| the phase, `92658f502..205fd2154`, before | 0.516 | 0.215 | 0.448 | 0.885 |
| the phase, `92658f502..HEAD`, after | 0.520 | 0.218 | 0.446 | 0.896 |
| this ticket's own range, `205fd2154..HEAD` | 0.667 | 0.936 | 0.427 | 0.636 |

Reported as they came out. The phase-wide row barely moves, and that is the model saying what it
measures: volume. The phase added 5,000 lines and this ticket moved about 1,000, of which roughly
half is one file changing address.

This ticket's own 0.936 on size is a deletion ticket's honest score: 103 units of the changed
volume left a function that was over the 15-line low bar or landed in one under it, and 7 did not.
Complexity at 0.427 is worse than even, and the reason is the fixture package: 47 good against 63
bad, where the bad are the builders arriving as new functions in a new file and the good are the
nine copies each of them replaced. Interfacing at 0.636 is `sortedKeys` gaining a type parameter,
the fixture builders taking `*testing.T` plus what they build, and `verifierFor` and
`printBinding` losing a parameter each when the version-1 branch went. The pooled score across the
ticket, 0.667 over `good="220" bad="110"`, is exactly two good units per bad one.

## What went

**The residue under `docs/snp/`** (`3fa9751b1`). Eight paths, each with the three-part rule
checked and written into the commit message: `image/tunneld-placeholder.c`,
`image/crosscheck-report.c`, `image/crosscheck-compare.sh`, `tunnel-in-stock-guest.sh`, the whole
`unattested-peer/` directory (`go.mod`, `go.sum`, `main.go`, `.gitignore`, and the untracked
nine-megabyte binary beside them), `canary-experiment.sh`, `canary-scan.py`, and
`host-read-guest-ram.py`. `build-image.sh` was the placeholder's only caller and now requires
`TUNNELD` — `: "${TUNNELD:?...}"` — so every build names the binary whose measurement it computes;
its two callers, `package-tunneld.sh` and `sensitivity-on-hardware.sh`, already passed it. The
relay, `l2relay.py` and `relay-selftest.sh`, stays: the SNP two-guest script still needs it and
that script is the cheap local proof. `verify-on-hardware.sh` stays as the SNP evidence-path
harness.

**Three commands became one** (`dc1f99689`). `cmd/verify-evidence`, `cmd/acquire-evidence` and
`cmd/provision-chain` moved whole into `cmd/attest-tool` as `verify.go`, `acquire.go` and
`provision.go`, with `main.go` holding the dispatch and the usage. `cmd/tunneld` stays the measured
binary and was not folded in. What the package now shares is what it had copies of: one
`readAuthorKey`, and one policy-digest parser — acquire's `parsePolicyDigest`, which also became
the v2 branch of verify's `bindingFor`, whose two error texts it already spelled identically. What
was deliberately **not** renamed is the evidence-facing vocabulary: each subcommand keeps its own
`flag.NewFlagSet` name, so the usage still reads `Usage of verify-evidence:`, and its own error
prefix, so a failure still reads `verify-evidence:`, `acquire-evidence:` or `provision-chain:`. The
recorded transcripts hold those strings and `run-tdx-scenario.sh` greps for
`verify-evidence exit status:`; a tool that renamed them would make its own evidence unreplayable.
Only the usage text a person types is new. Re-pointed: `verify-on-hardware.sh`,
`tunnel-on-two-guests.sh`, `sensitivity-on-hardware.sh`, `smoke-tdx-guest.sh`,
`run-tdx-scenario.sh`, `probe-tdx-mutate.sh`, `probe-tdx-initrd.sh`, `mkconfigdev.sh`'s comment and
`SCENARIOS.md`'s runbook. Verdict output on all 111 recorded invocations was byte-identical at this
commit.

**The version-1 binding replay path** (`ec299ac2e`). The `-binding-version` flag, the
`bindingVersion` helper, `verifyPreV2`, and the v1 arm of `bindingFor`, which now returns the v2
binding unconditionally. `verifierFor` hands back the verification alone, and `printBinding` and
`printAccepted` lose the options they read nothing but a binding version out of; `verify.go` goes
from 585 lines to 516. `attest.BindingContextV1` **stays**, and this is where the three-part rule
failed: `Binding.CallerSuppliedBytes` branches on it, and five test files replaying recorded ticket
05 and 08 evidence import it. `docs/policy-binding.md` loses the `-binding-version 1` invocation
and the paragraph explaining it, and says instead what is now true: a bundle recorded before ticket
18 verifies with the binary of its era, named by the commit in its manifest.

**The fakes** (`1a033ebf4`). Coverage over both packages, run from the whole suite, found three
functions no test reaches. Two are `Vendor`, which `attest.Acquirer` requires of both platforms, so
they stay at 0%. The third, `tdxfake.Platform.FMSPC`, goes: the platform still reads the FMSPC out
of the recorded PCK certificate and still files the TCB info under it, but nothing ever asked the
platform for it. Four package-level constants had no caller outside their own package and are now
unexported: `DefaultProductLine`, `DefaultTCB`, `DefaultNow`, `DefaultEvaluationDataNumber`. Both
packages moved under `attest/internal/`. `snpfake.Policy` is gone: `Config.Policy` takes an
`attest.GuestPolicy`, so the fake launches a platform in the same vocabulary a reference value
permits one in, and the `snpPolicy` body duplicated between the fake and `verify/snp.go` is one
function, exported as `verify.SNPPolicyBits` — packed bits, not a `go-sev-guest` type, because "no
go-sev-guest type in this package's exported surface" is an invariant of `verify` (ADR-0003) and
the word crossing the boundary keeps it. 1,396 lines of fake before, 1,363 after.

One correction to the ticket's wording on this item. It asked for the move "so the compiler
enforces what the import-graph and packaged-binary tests currently enforce by scanning". `internal/`
does not do that: it blocks importers outside the module, which is `pkg/` and `runsc/`, and inside
`gvisor.dev/gvisor/attest` any package may still import the fakes. The guard tests are still the
enforcement and they stay — now strengthened, because both import-graph lists and the packaged
binary's byte scan name `internal/fixture` beside the two fakes.

**Six root exports became unexported** (`3838e192f`). `PolicyFormat`, `PolicyVersion`,
`ReferenceValueSetFormat`, `ReferenceValueSetVersion`, `LoadPolicy` and `LoadReferenceValueSet`.
The tests reach `loadPolicy`, `loadReferenceValueSet` and `policyVersion` through a new
`export_test.go`, keeping every name and assertion they had, and staying in package `attest_test`
so what they drive is still the surface a caller could reach — with the one difference that a
caller cannot reach these. `LoadPolicyFile` and `LoadReferenceValueSetFile` stay exported: they are
how a guest and the two authoring tools under `docs/snp` read a signed document off disk. One
literal changed outside the root package: `closedPolicy` in `cmd/tunneld/egress_test.go` dropped
`Version: attest.PolicyVersion`, after checking that nothing in the egress rendering reads a
policy's version field.

**One fixture package for the tests** (`99544238a`). `internal/fixture` holds `SNPPlatform`,
`SNPPlatformAtTCB`, `VerifierTrusting`, `TDXVerifier`, `Verification`, `AcquireZero`, `MustAccept`,
`Detail`, `Author` with `NewAuthor`/`Sign`/`SignPolicy`, `WriteFile`, `WriteSigned`, and the fixed
instants `ChainCreatedAt`, `WhenChainsAreValid` and `ChipID`. Each replaces between two and four
per-package copies; `MustAccept` is written once over both an `attest.Verifier` judging against a
set and an `attest.Verification` judging against a binding, which is what let four helpers under
four names become one. Left local on purpose: the recorded-run loaders `loadLiveGuest`,
`loadBootedGuest`, `baselineReferenceValues`, `tdxReadQuote` and `tdxNewFake`, and the pre-v2
stand-in they feed, because a test whose subject is a recording does not start from a builder; and
`loads`, `loadsPolicy`, `refusesToLoad` and `refusesToLoadPolicy`, because they call the in-memory
loaders that only `export_test.go` names and no other package can see. One rename was forced: the
root tests' `fixture` struct is now `guest`, because a type and an imported package cannot share a
name. Test count and test names do not change — 476 `=== RUN` lines before and after, and the
sorted name lists differ nowhere. No assertion changed.

**Two small clone families** (`cb35b7a49`). `sortedPeerKeys` was `sortedKeys` over another map
value type; the value type is a parameter now and its three callers pass the maps they always did —
the signature changed, the order did not, and `PEER SEEN` still prints ascending by key. The
`-policy-digest` parser in three commands and the loader's `policy_digest` field decode through one
`attest.ParsePolicyDigest`, over an unexported `decodePolicyDigest` that returns the digest and its
width and says nothing about either; the loader keeps its own two refusal sentences, the flag
parser keeps its own, so no output byte moved and the 64 recorded verify invocations replay
identically.

**Every decision record gained a Status line** (`51f8670ce`). No ADR text otherwise changed:

```
docs/adr/0001-standalone-attest-module.md          Status: accepted.
docs/adr/0002-versioned-report-data-binding.md     Status: accepted; amended by ticket 18, corrected by ticket 19.
docs/adr/0003-go-sev-guest-for-verification.md     Status: accepted; amended by ticket 17.
docs/adr/0004-signed-reference-values.md           Status: accepted.
docs/adr/0005-provisioned-certificate-chain.md     Status: accepted.
docs/adr/0006-detached-signature-reference-value-sets.md  Status: accepted; amended by ticket 17.
docs/adr/0007-provisioned-intel-collateral.md      Status: accepted.
```

## What stayed, and why

**`MarshalReferenceValueSet`, `SignReferenceValueSet`, `MarshalPolicy` and `SignPolicy`.** The
ticket's premise for this item was stale. It says the live authoring tools "carry their own
marshal-and-sign in separate modules" and that the four exports are called only by tests. They are
not: `docs/snp/cloud/tdx/emit-tdx-refvals/main.go:192` and `:196` call
`attest.MarshalReferenceValueSet` and `attest.SignReferenceValueSet`, and
`docs/snp/image/emit-refvals/main.go` calls all four, at `:160`, `:164`, `:272` and `:276`. A later
ticket had already done what this item asked for. The four stay exported and live.

**`TDPolicy`, `Unconstrained` and `UnconstrainedValue`.** Reviewed for the same treatment and
kept: `TDPolicy` is read by `verify/tdx.go:296` and printed by the verdict tool, and
`ReferenceValueSet.Unconstrained` is called by `tunneld.go:225` and re-exposed as
`Tunneld.Unconstrained`, which is the API a caller asks what its set admits unconditionally.

**`ErrRefused`, `ReasonNone` and the rest of the refusal taxonomy.** These are the seam contract.
A test in another package asserting `errors.Is(err, attest.ErrRefused)` is the only way to state
"this was a refusal and not a bug", and the reason constants are what a cross-package test names
instead of a string.

**`attest.BindingContextV1`.** See above: `Binding.CallerSuppliedBytes` branches on it and the
ticket 05 and 08 replay tests import it. The three-part rule failed on its second and third clause.

**`readAuthorKey` in `cmd/tunneld`.** Still a clone of the one in `cmd/attest-tool/verify.go` —
113 tokens, the largest non-test clone group left. `cmd/tunneld` is the measured binary; sharing
this would mean a package both import, which is a new exported surface for a key file reader, and
the ticket removes rather than redesigns.

**Two console strings that name commands that no longer exist.**
`cmd/tunneld/selfcheck.go:132` tells an operator to feed the base64 evidence to
`attest/cmd/verify-evidence`, and `:144` calls the key file `verify-evidence -key`.
`attest/tsm/tsm.go:116` says the chain files are "written by `cmd/provision-chain`". Both are
correct about what to do and wrong about what it is called. They were left alone for the same
reason the flag-set names were kept: `cmd/tunneld` is the measured binary and `attest/tsm` is
frozen, and changing a string inside either means a new measurement or a change to a package this
ticket promised not to touch. A later ticket that rebuilds the image can change the tunneld string
in the same commit that re-measures it.

**`tdxfake.Config.TeeTCBSvn` and `.CollateralNextUpdate`.** No test sets either, and no code
outside the fake mentions them. They are read where they are declared — `tdxfake.go:283` and
`collateral.go:67`, `:180` — and they are the two knobs a TCB-recovery or expiry test would reach
for first. The item's rule was written for functions coverage does not reach, not for struct
fields a test has not needed yet.

**Ledger rows still filed under `by=snpfake/...`.** `productFms | tdxHex` carries the scope ticket
20 wrote it under, and `internal/snpfake/snpfake.go` is not covered by it, so the report counts it
as `foreign-acks="1"`. Rewriting the row would change nothing about what is suppressed and would
lose the record of who accepted it.

**`docs/snp/evidence/ticket19/step-zero/.gitignore`** still names `acquire-evidence`, the binary
that run uploaded. Recorded evidence is never touched, and that file is part of the recording.

**`docs/snp-measured-image.md:233`** still shows a `build-image.sh` invocation without `TUNNELD`,
which would now refuse. It is a record of what was run in ticket 06, not a runbook line; the line
at `:199` beside it says the placeholder went in ticket 21 and that `build-image.sh` now requires
`TUNNELD`.

## Named and left alone

The ticket names three functions and says a shrink ticket does not refactor untested code. All
three are untouched by ticket 21 — `git diff 205fd2154..HEAD` is empty for all three files — and
their complexity was measured again at HEAD by bisecting `ripwire attest --graph-query='cx(all,N)'`:

| function | ticket's number | measured now |
|---|---|---|
| `(*Cache).Get`, `tunnel/tunnel.go:606` | 19 | 12 |
| `readInstalledRuleSet`, `cmd/tunneld/egress.go:387` | 22 | 13 |
| `(*TDX).Verify`, `verify/tdx.go:148` | 24 | 19 |

The inventory's 12, 13 and 19 are what the tool reports today; the ticket's 19, 22 and 24 are not.
Only the TDX `Verify` is over ripwire's ccx bar of 15, and it is the one of the three whose package
has tests that drive it. The reason for leaving them stands either way: `tunnel` and `tunneld` have
no test files of their own by design, and refactoring a function with no test around it is not a
removal.

The `tunnel` and `tunneld` split stays. It is what lets the import guard prove the shipped binary
is fake-free: the guard runs on `cmd/tunneld`, whose dependency graph contains package `tunneld`'s,
and package `tunnel` knows nothing about attestation at all.

## What the tool reported that was not true

- **A moved body reads as a new symbol.** 179 of the 179 remaining regressions are
  `origin="new-symbol"`, and a large share of them are bodies that moved address in this ticket and
  changed in no other way. The report discloses this rather than hiding it: `renames="6"` is how
  many rename pairs git's own record supplied, and the header states that "a move git recorded no
  rename for still reads as new-symbol" and that the two clone kinds "key on a member-SET hash and
  are NOT re-filed, so a clone ack still dies on a rename". That is the whole mechanism behind the
  74 stale ledger lines.
- **`--edit-check` cannot see a type parameter.** `sortedKeys` changed from
  `func(map[string]string) []string` to `func[V any](map[string]V) []string`, and
  `--edit-check='cmd/tunneld/main.go:sortedKeys'` reports `status="unchanged" callers="3"
  incompatible="0"`. The verb compares parameter count and publicness, and a type parameter changes
  neither. It is right about the thing it checks and silent about the thing that moved; the three
  call sites were read by hand.
- **The ticket's inventory says one root export has no callers at all.** Whatever it named, it is
  not `BindingContext.Recognised`: `--callers=Recognised` reports one, `Verify` at
  `verification.go:104`, and the call is at `verification.go:115`.
- **Churn is not measurable in the range form**, and nine acks were written as if it were. A
  range materialises two committed trees out of the repo, so `short-horizon-churn` reports
  `churn="unavailable"`, which the header is explicit is "not evidence that nothing churned". The
  nine were deleted in `e35a3cdc4`.

## Files that records still cite by name

Each of these is gone from the working tree at HEAD and recoverable with
`git show 205fd2154:<path>`. Recorded evidence under `docs/snp/evidence/` is never touched, so
several of these names also live on inside transcripts, which is history and stays.

| path at `205fd2154` | what it is now | records that cite it |
|---|---|---|
| `docs/snp/image/tunneld-placeholder.c` | deleted | `snp-measured-image.md` |
| `docs/snp/image/crosscheck-report.c` | deleted | `measurement-sensitivity.md`, `snp-measurement-prediction.md` |
| `docs/snp/image/crosscheck-compare.sh` | deleted | `snp-measurement-prediction.md` |
| `docs/snp/tunnel-in-stock-guest.sh` | deleted | `two-guests-on-hardware.md` |
| `docs/snp/unattested-peer/` | deleted | `two-guests-on-hardware.md` |
| `docs/snp/canary-experiment.sh` | deleted | `snp-host-stack.md` |
| `docs/snp/canary-scan.py` | deleted | `snp-host-stack.md` |
| `docs/snp/host-read-guest-ram.py` | deleted | `snp-host-stack.md` |
| `attest/cmd/verify-evidence/main.go` | `attest/cmd/attest-tool/verify.go` | `measurement-sensitivity.md`, `policy-binding.md`, `quality-pass-tdx.md`, `tdx-as-a-second-vendor.md`, `tdx-verifier.md`, `two-guests-on-hardware.md`, `two-guests-on-tdx.md`, `verification-on-hardware.md` |
| `attest/cmd/acquire-evidence/main.go` | `attest/cmd/attest-tool/acquire.go` | `evidence-acquisition.md`, `measurement-sensitivity.md`, `quality-pass-tdx.md`, `tdx-as-a-second-vendor.md`, `two-guests-on-tdx.md`, `verification-on-hardware.md` |
| `attest/cmd/provision-chain/main.go` | `attest/cmd/attest-tool/provision.go` | `provisioning-certificate-chain.md`, `snp-measured-image.md` |
| `attest/snpfake/snpfake.go` | `attest/internal/snpfake/snpfake.go` | `evidence-acquisition.md`, `policy-binding.md`, `quality-pass-tdx.md`, `tdx-verifier.md`, `two-guests-on-hardware.md` |
| `attest/tdxfake/` | `attest/internal/tdxfake/` | `tdx-verifier.md` |

The eight deleted `docs/snp/` paths and the three commands each already carry their one-line
pointer in the records above, added by `3fa9751b1` and `dc1f99689`. The two fake packages do not:
`1a033ebf4` moved them without touching the five records that spell the old import path. This table
is that pointer.

---

Nothing under `pkg/` or `runsc/` changed. Nothing was pushed. Branch
`tdx-attested-tunnel`: eight item commits from `3fa9751b1` to `99544238a`, the ack-ledger rebuild
in `e35a3cdc4`, and this record on top of it. `e35a3cdc4` is the last commit that changes anything
a build reads, and every measurement in this file was taken there.
