# A quality pass over the TDX phase

**Nothing here changes what the code does.** Ticket 20 measured the four TDX-phase tickets as one
branch, `92658f502..7c399c8ae`, and found that each had passed its own bar while the phase as a
whole had grown large functions rather than adding small ones. This record says what was shared,
what was split, what was accepted with a reason, and what the tool reported that was not true.
Every edited symbol was checked against `git HEAD` with `--edit-check` and reads `unchanged`;
`verify-evidence` was run on 82 recorded invocations before and after and its output is
byte-identical; `go test ./...` in `attest/` passes uncached. The measurements are under
`docs/snp/evidence/ticket20/{before,after}/`.

*`attest/cmd/verify-evidence` and `attest/cmd/acquire-evidence` became `attest-tool verify` and `attest-tool acquire` in ticket 21; their last versions are `git show 205fd2154:attest/cmd/verify-evidence/main.go` and `git show 205fd2154:attest/cmd/acquire-evidence/main.go`.*

## The numbers

| `ripwire attest --quality-delta=92658f502..HEAD` | before | after |
|---|---|---|
| regressions | 292 | 158 |
| preexisting-worse (gating) | 133 | 0 |
| new-symbol (never gate) | 159 | 158 |
| acked | 0 | 122 |

| Delta Maintainability Model | dmm | size | complexity | interfacing |
|---|---|---|---|---|
| the phase, `92658f502..HEAD`, before | 0.504 | 0.200 | 0.410 | 0.901 |
| the phase, `92658f502..HEAD`, after | 0.516 | 0.215 | 0.448 | 0.885 |
| this ticket's own commits, `7c399c8ae..HEAD` | 0.817 | 1.000 | 1.000 | 0.000 |

The ticket's own score is reported as it came out. Size and complexity are 1.000 because every
line this pass moved left a function that was over the bar or landed in one under it.
Interfacing is 0.000 because the helpers lifted out of `run`, `verdict` and the loaders take
three to five parameters each, and the model calls anything above two high-risk; no function's
parameter count was reduced, so there was nothing on the good side of that ratio. Splitting a
190-line `run` into steps that each receive the flags, the logger and the context is the trade
this pass made knowingly.

The phase-wide score barely moved, and that is expected: the model scores volume moved, and the
phase's 5,000 added lines dwarf the 600 this pass touched. The per-function view is where the
change shows.

| function | complexity before → after | lines before → after |
|---|---|---|
| `verdict`, `cmd/verify-evidence/main.go` | 51 → 8 | 230 → 48 |
| `run`, `cmd/tunneld/main.go` | 31 → 7 | 193 → 53 |
| `run`, `cmd/acquire-evidence/main.go` | 23 → 12 | 110 → 58 |
| `Verify`, `verify/snp.go` | 17 → 8 | 86 → 60 |
| `parseReferenceValueSetDocument`, `refvalsfile.go` | — | 77 → 56 |

## What was shared

**One signed-document loader** (`686461448`). `SignPolicy`, `LoadPolicy` and `LoadPolicyFile`
had copied `SignReferenceValueSet`, `LoadReferenceValueSet` and `LoadReferenceValueSetFile`
nearly token for token. The shared shape now lives beside the existing `signedBytesUnder` and
`parseSignature` in `refvalsfile.go`: a `signedDocumentKind` naming the four things that may
differ between the two documents (the domain-prefix function, the package's refusal
constructor, the noun for error messages and the not-signed sentence), and three unexported
functions over it, `signDocument`, `verifySignedDocument` and `readSignedDocumentPair`. Each
document keeps its own kind in its own file (`setDocumentKind`, `policyDocumentKind`), its own
format and version checks, and its own parser. Error strings are reproduced byte for byte.
`ripwire --exemplar` named `provision.Load` as the house pattern, read the files, refuse per
file, hand the bytes to a parse, and the extraction keeps that shape. `provision.Load` itself was
not rewired: it is another package, it reads two separately named files with no signature, and
its refusals carry ADR-0005's sentence; its clone row went away because the copy lived in
`LoadPolicyFile`, which no longer carries it.

**One error-to-refusal mapping for both verifiers** (`cfc898331`). The two `checkAuthentic`
bodies were not one function: each builds its own vendor library's options struct and calls
that library's entry point. What they did share, turning any library error into
`ReasonChainNotRooted` without inspecting it, is now `refuseUnrooted` in `verify/shared.go`.

**One place for a superseded set version** (`d74af81be`). `parseReferenceValueSetDocument` had
grown three parallel refusals for versions 1, 2 and 3 in the middle of its own checks. They are
one `switch` in `refuseSupersededSetVersion`, same reasons, same order.

## What was split

**The verdict printer** (`518ce6d3b`). `verdict` had absorbed both vendors' claims blocks and
the binding section inline. Each vendor's claims now print from `printTDXClaims` and
`printSNPClaims`; the binding context and policy digest from `printBinding`; trust roots,
reference values, the refusal and the acceptance each from a function of their own; and reading
the invocation and wiring the verifiers from `present`, `readTrust` and `verifierFor`, in the
original order so the first thing wrong with an invocation is still the thing reported.
`verdict` keeps the four preamble lines, the set load, the version dispatch and the exit
statuses. Byte identity was checked on 82 invocations across the ticket 04, 05, 08, 18 and 19
bundles, the `tdx/` recordings and every flag-error path, before and after, with `diff -r`
empty. One observation from that run, not a change: the ticket 05 and ticket 08 reference-value
sets are format version 1 and the loader reads version 4, so those recordings replay as
`SET REFUSED` today; the accepted transcripts beside them are from the binary of their day.

**tunneld's `run`** (`e07858efa`). The flags parse into an `options`; `run` reads the three
documents both modes need and dispatches on `-egress`; `serve` owns the rest through
`bringUpLink`, `resolveLimits`, `newVendorSeam` (where the opt-in TDX collateral branch now
lives), `refusalLogger`, `logStartupSummary` and `exerciseAndHold`. **acquire-evidence's `run`**
(`72890f9fd`) keeps the flags, the key and binding, and the acquisition; `newAcquirer`,
`printBundle`, `writeBundle` and `dumpBundle` hold the rest. Every flag name, default and help
text, every log line and every error string is the same set before and after, checked by
diffing the sorted string literals of each file. Lifting the key-and-binding construction out of
acquire-evidence was tried and undone: the helper it produced was a 93-token clone of a helper
in `tsm/tsm_test.go`, which is not importable, and the only fix would have been a new exported
constructor on package `attest`, a contract change.

**The SNP verifier's last step** (`3ca77d507`). The ticket said `Verify` in `verify/snp.go`
grew when the policy-digest plumbing landed. It did not: the only addition was the multi-vendor
skip inside the reference-value loop, and neither verifier checks the binding, which ADR-0002
places in `attest.Verification` above both. The loop and its fallback refusal moved to
`satisfyingValue`, a pure move that keeps the check order vendor, presence, parse,
authenticity, claims, coherence, reference values. It was not merged with the TDX verifier's
loop, which counts its values, tracks a first mismatch and treats an empty vendor tag the
opposite way.

## What was accepted, and why

The ledger is `attest/.ripwire_quality_acks`, 122 lines, committed in `5bfbbb706`. Every line
carries the scope it was written under and a reason. No line was written with a bare
`--quality-ack`.

- **108 rows scoped to `*_test.go`**, selected with `--ack-only=gating` inside that scope so
  nothing outside a test file could be written under the entry. They are table-driven scenarios
  written long-hand per refusal reason: each test names the one input that earns one refusal and
  repeats the setup around it so a failing test reads on its own. Before acking, every member
  name of every row was resolved to its definition; the five names that also exist in production
  code (`accept`, `report`, `verifierFor`, `tcbParts`, `writeFile`) were checked against the
  clone groups, and the two rows that really do pair a test helper with a non-test function were
  taken out of this entry and given their own, below.
- **`closedPolicy | tcbParts`** and **`writeFile | writeFile`**: one-line struct constructors of
  unrelated types, and two `os.WriteFile` wrappers with different modes and different contracts,
  one in the TDX fake and one in a test of another package. Scoped to the files they live in.
- **`checkAuthentic | checkAuthentic`**, 71 tokens before, 49 after: what remains is
  `sevverify.Options` and `SnpAttestationContext` against `tdxverify.Options` and `TdxQuote`.
  Sharing it means wrapping two third-party libraries behind one interface.
- **`anyOf | contains`**, two clone groups: `anyOf` searches `[][]byte` with `bytes.Equal`,
  `contains` searches `[]string` with `==`; `[]byte` is not `comparable`, and `contains` is
  defined in the test files of two other packages, one of them the frozen `attest/tsm`.
- **`LoadPolicy | LoadReferenceValueSet`** and **`LoadPolicyFile | LoadReferenceValueSetFile`**,
  95 and 79 tokens before, 34 and 37 after: the residue is `if err != nil` around one call to the
  shared helper and one to the document's own parser. Passing the unexported parsers as values
  was built and measured; it made both bodies one line and turned both parsers into gating
  dead-code rows, because the graph no longer saw a call edge.
- **`refuse | refuseCollateral | refusePolicy | refuseSet`**: four two-line sentinel
  constructors in three packages. Folding the two in package `attest` leaves one-liners cloning
  each other across packages; deleting them makes every call site spell its sentinel.
- **`MarshalReferenceValueSet`**, 33 to 62 lines: version 4 added a vendor tag and a second
  vendor, and the switch's two arms share only `vendor` and `policy_digest`; splitting them
  would hide which fields each vendor's document carries. Honest growth.
- **`productFms | tdxHex`**: a product-line parse in the SNP fake and a hex decode in a test,
  sharing the shape one call, one check, one return. Scoped to `snpfake/snpfake.go`.

## What the tool reported that was not true

- **`permits` at `refvals.go:338` is not dead.** It is called at `verification.go:167` and
  `:176` from `(*Verification).permits`. Two definitions share the name and the graph, which
  resolves calls by name, bound the sites to the wrong one; `--callers` on either reads zero
  while `graph_ambiguous="225"` says why.
- **`Get` at `verify/tdxcollateral.go:451` is not dead.** `provisionedGetter` is returned as
  `tdxtrust.HTTPSGetter` and handed to go-tdx-guest at `verify/tdx.go:410`, which calls `Get`
  through the interface from outside this repository.
- **The TDX verifier's `Verify` and the TDX fake's `New`, `Vendor`, `Acquire`, `FMSPC` and
  `VendorRootPEM`** are reached through `attest.Verifier` and `attest.Acquirer`. Not touched.
- **Every `Test*` function listed as dead** is run by the Go test runner, which the graph does
  not see.
- **The `Verify` growth in `verify/snp.go` was attributed to policy-digest plumbing** by the
  ticket; the diff shows the multi-vendor skip. The lift applied either way.

## Left for later, on purpose

`Forwards` in `policyfile.go` and `anyOf` in `verify/tdx.go` are the same function with the
arguments swapped; both are new this phase, the row never gated, and they sit in different
packages, so the shared byte-slice search belongs wherever Milestone 4's allow-list work puts
its own. `parsePolicyDigest` in acquire-evidence and `policyDigest` in verify-evidence decode
the same hex the same way in two commands with no shared package between them; the same is
true of the TDX collateral construction in `newVendorSeam` and in verify-evidence's
`verifierFor`. Both are new-symbol rows and both wait for a home that is not another package
boundary crossed for a one-liner.

Nothing under `attest/tsm/`, `pkg/` or `runsc/` changed. Nothing was pushed.
