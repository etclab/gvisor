# attest

The attested-tunnel module: evidence, verification, the reference value loader, the RA-TLS
carry, the transport, and tunneld.

## Building and testing

`go` is not on this machine's `PATH` and gvisor's own toolchain comes from bazel.

```sh
export PATH=/usr/local/go/bin:$PATH
go build ./...
go test ./...
```

`/usr/local/go` is go1.22.3, but this module's `go.mod` asks for go1.26.3 and Go's toolchain
switching fetches and uses exactly that, from
`~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.linux-amd64`. That is the module cache, not
the bazel cache, so a `bazel clean` does not remove it — which is the failure mode the
alternative (the go1.26.3 inside
`~/.cache/bazel/.../rules_go++go_sdk+main___download_0/bin/go`) has. Nothing needed installing:
the version is pinned by the `go` directive in `go.mod` rather than by which binary is invoked,
so a reader who runs the commands above gets the same compiler whatever `go` resolves to.

Almost every test runs against fake hardware with test signing; the exceptions replay reports
that real silicon produced, captured under `docs/snp/evidence`. Either way no confidential VM
and no network is required: the tunneld tests talk over loopback on ephemeral ports, and the
suite passes inside an empty network namespace with only loopback up:

```sh
unshare -rn sh -c 'ip link set lo up && env PATH=/usr/local/go/bin:$PATH HOME=$HOME go test ./...'
```

Ports are always ephemeral (`127.0.0.1:0`). Other suites run concurrently on this machine and a
fixed port collides in ways that look like flaky tests.

## Module shape

This is a standalone module with its own `go.mod`, outside gvisor's bazel graph and outside its
`pkg/<name>` convention, per ADR-0001. Its module path — `gvisor.dev/gvisor/attest` — is the one
it would have as an ordinary subpackage of this repository, so integrating it at Milestone 4 is
deleting `go.mod` with no import rewriting. There are deliberately no BUILD files and nothing is
registered in `MODULE.bazel`; that cost is paid once, against proven code, rather than on every
iteration of unproven code.

## Layout

| Package   | What it is |
|-----------|------------|
| `attest`  | The public surface: the vendor seam, the reference value vocabulary, the signed reference value set format and the signed policy format with their loaders, the binding of ADR-0002, the refusal taxonomy, and `Verification.Verify`. |
| `verify`  | The SEV-SNP verifier. Wraps `go-sev-guest` (ADR-0003) and keeps that library's API shape from reaching anywhere else. |
| `tsm`     | Ticket 04: evidence acquisition from real hardware, through the kernel's vendor-neutral report interface at `/sys/kernel/config/tsm/report`. Writes the caller-supplied bytes, reads the evidence back, and bundles the chain the config device holds — never the platform's, which is empty here, and never the network's (ADR-0005). Procedure: `docs/evidence-acquisition.md`. |
| `cmd/acquire-evidence` | The command over `tsm`, run inside a guest: generate a key, acquire evidence bound to it, bundle the chain, print what the platform said. |
| `snpfake` | A fake SEV-SNP platform built on `go-sev-guest`'s test signing. Implements the acquisition half of the seam for everything that must run without a confidential VM. Test support, but not a `_test` package, because tunneld's tests inject it through `tunneld.Config`. |
| `provision` | Ticket 15: fetches the certificate chain for a platform's chip and TCB from AMD's key distribution service once, validates it through `verify`, and writes it beside the reference value set (ADR-0005); the consumer half loads it and refuses a missing or stale chain rather than fetching. Procedure: `docs/provisioning-certificate-chain.md`. |
| `cmd/provision-chain` | The operator command over `provision`: `fetch` and `check`. |
| `cmd/verify-evidence` | Ticket 05: the command that takes a verdict on a bundle from outside the guest that produced it — load the signed set, wire it to the verifier, exit 0 on acceptance and 2 on refusal. Procedure: `docs/verification-on-hardware.md`. |
| `ratls`   | The certificate as a serialization envelope: a versioned payload (version 2) under a private arc carrying the evidence, the chain, the binding context and the peer's policy digest, and the handshake callback that runs `Verification.Verify` on the peer's. Nothing else in the certificate is read. |
| `tunnel`  | The transport: QUIC with TLS 1.3, early data refused on both ends, one exchange per stream, the establishment round trip, and the cache that holds at most one tunnel per peer under an idle timeout and a maximum age (`Limits`). Knows nothing about attestation. |
| `tunneld` | The composition root and the public API: `New` with a `Config`, `Peer(name)` yielding a `Channel`, `Channel.Exchange`. It loads the set and the policy, presents the policy's digest as its identity, and enforces `forward_to` on the peers it dials. One `tunnel.Cache` per tunneld, built from its one identity, under `Config.Limits`; a `Channel` is a handle on a peer rather than a holder of a connection. |

`verify`, `snpfake`, `ratls` and `tunnel` have no test files of their own, and that is the design
rather than a gap. There are two seams, one per layer. Below tunneld the seam is this module's
public surface: every `attest` test drives `Verification.Verify` or the set loader and asserts on
external behaviour — accepted, or refused with a given reason — and none reaches inside `verify`.
Above it the seam is tunneld's API: every `tunneld` test starts tunnelds with the fake platform
injected through `Config` and asserts that a channel exists or does not, and that an exchange
completes or does not. Certificate carry, transport and peer resolution are tested only through
that API, and verification is not re-tested there. The package has one second instrument: a
peer built by hand from `ratls` and `tunnel`, admitting on exactly a tunneld's terms, used where
a tunneld cannot stand in — a peer that misbehaves after the handshake (`hostile_test.go`), and
a peer that writes down the key it was shown (`identity_test.go`), since a tunneld's key is by
design observable nowhere but at the peer it is presented to.

`tsm` is the one exception, and it is the exception for a reason worth stating. What sits below it
is not a vendor but the kernel, so nothing above it can drive it without a confidential VM — the
substitution has to happen where this package talks to the kernel. That boundary stays unexported
and the fake for it is declared in `export_test.go`, so the tests themselves are still in
`tsm_test` and still drive `Acquire` and nothing else. What they stand in for is the ABI, not the
hardware: attributes generated on read, a generation counter that advances on every write, an
`inblob` the width of the field, an empty `auxblob`. The evidence they feed it is real —
`snpfake`'s, or the reports `docs/snp/evidence` captured from live guests.

## Acquiring evidence

`tsm` is the acquirer that runs on real hardware. The interface it drives is the kernel's and is
the same on every vendor — make a request directory under `/sys/kernel/config/tsm/report`, write
the caller-supplied bytes to `inblob`, read the evidence from `outblob`, remove the directory —
so what is AMD-specific is only the bytes that come back, and it stays behind `attest.Acquirer`.
The procedure and the captured run are `docs/evidence-acquisition.md`.

Three things about it are decided rather than incidental:

- **The caller-supplied bytes are written in one write and are not computed here.** They are
  whatever `Binding.CallerSuppliedBytes` produced, so producer and consumer agree on ADR-0002 by
  construction; and the write is one `write(2)`, never retried, because a partial `inblob` is a
  different request rather than half of this one.
- **An empty certificate table is recorded, not refused.** `auxblob` is empty on this host and no
  operator action fills it (`docs/snp-host-stack.md`). Every acquisition reads it and records its
  size in an `Observation` an operator can read, because the alternative — treating it as a
  failure — fails on every host this design runs on.
- **The chain comes from the config device, and a bad one fails closed.** `provision.LoadFor` is
  the boundary: missing, mismatched or stale is a refusal naming ADR-0005, and there is no
  fallback fetch. `tsm`'s import allowlist test is the structural guard that no fetch can be
  written here without somebody saying so out loud.

## tunneld

A tunneld is one sandbox's identity for the life of the process. It generates its key at startup
and never persists it, takes the sandbox identifier as a parameter (synthetic until the sentry
integration passes a real one), loads its reference value set through
`attest.LoadReferenceValueSetFile` against the author public key it was started with, and refuses
to start on `attest.ErrSetRefused` — there is no path that runs without a set.

Four things about a tunnel's establishment and its life are decided rather than incidental:

- **A tunnel exists only once both sides have accepted the other's evidence, and a refusal aborts
  the handshake.** `ratls.PeerVerifier` returns an error from `VerifyPeerCertificate`, which is
  a TLS alert, not a connection whose exchanges are refused afterwards. TLS 1.3 lets a client
  finish its handshake before the server has judged the client's certificate, so the QUIC dial
  alone can return a connection the peer is about to close. `tunnel.Dial` therefore completes one
  empty application round trip before returning (spec, Transport): the listener answers a stream
  only on a connection it admitted, so a returned connection is one both sides admitted.
- **Early data is off twice.** The listener's `Allow0RTT` is false and the dial path is
  `quic.DialAddr`, never `DialAddrEarly`; the server also disables session tickets. A replayed
  privileged exchange has no 0-RTT slot to ride in on.
- **A tunnel's life belongs to the timeouts and not to its callers.** Tunnels are cached per peer
  per sandbox, dialed the first time somebody asks for that peer, and dialed again whenever the
  one that was there has gone — so no caller ever dials, and no tunnel exists because the peer
  table mentions a peer. One closes after 60 seconds carrying nothing or 15 minutes carrying
  anything, and both ends enforce the age, because a bound only the dialer honoured would depend
  on the peer choosing to give a tunnel up. `Channel.Close` gives up the handle, not the tunnel.
  A request that reached the wire is never sent again: re-dialing is transparent, re-sending
  would be replay. `tunnel.DefaultMaxAge` records why 15 minutes, what would change it, and what
  it does not bound — it is how long a verdict about a peer is relied on, not how fresh that
  peer's evidence is, because evidence is acquired once at startup and held for the life of the
  process.
- **Identity is per tunneld, and so is everything built from it.** One `ratls.Identity`, one
  `tunnel.Cache` made from it, and a `Channel` that resolves through its own tunneld and no
  other — so two tunnelds on one VM present distinct keys and distinct evidence over one chain,
  and neither can reach the tunnel under the other's channel by name, by address, by cache, or
  by the other going away (`identity_test.go`). What that does not make is a peer that can tell
  them apart: both run the measured image, and membership is "runs the measured image".

The payload's extension identifier sits under the private enterprise number IANA reserves for
documentation (32473, RFC 5612). It is nobody's, so no verifier can be led to guess another
party's format, and it is visibly a placeholder: if an enterprise number is assigned for this
work, `ratls.PayloadOID` is the one constant that changes. (Go's `encoding/asn1` represents arcs
as `int`, which rules out the UUID-based `2.25` arc.)

`snpfake` must never reach a production binary: it imports `go-sev-guest`'s test helpers, which
import `testing` and register flags at init, and ticket 14 puts a binary inside the launch
measurement. The binary that goes in is `cmd/tunneld`, not package `tunneld`, and that is where
the guard lives: `cmd/tunneld/importgraph_test.go` lists the non-test dependency graph of
`gvisor.dev/gvisor/attest/cmd/tunneld` and fails if `snpfake`, `go-sev-guest/testing` or
`testing` appears, and checks package `tunneld`'s graph beside it so a failure names which of the
two grew the dependency. The command's graph contains the package's, so one guard on the command
is stronger than the guard that was in the package until ticket 14 moved it. The fake is injected
only through `Config`, from test code.

Two things about it are worth knowing before trusting it. It guards the *artifact* as well as the
graph — `cmd/tunneld/packaged_test.go` builds the binary the way the packaging step does and reads
what came out, refusing one that carries either package path or that asks for a dynamic loader,
because the measured image ships none and such a binary fails at exec inside the guest with the
measurement already fixed. And it has to run *before* the measurement is computed, which is a
property of the packaging step rather than of any test file:
`docs/snp/image/package-tunneld.sh` runs the tests, then builds, then calls `build-image.sh`.

The reference value loader is driven through the same seam: a set is loaded and then wired into a
`Verification` and shown to admit or refuse a fake platform, because what a set is for is deciding
who gets in. The spec's module list names a separate `refvals` package for the format; it lives in
`attest` instead, following the same collapse ticket 02 made when the reference value vocabulary
became `attest/refvals.go` rather than a package. A separate package would have to import `attest`
for `ReferenceValueSet`, so `attest` could not expose the loader, and the loader would then be a
second public surface for tests to drive.

## Verification on real hardware

Milestone 1 (ticket 05) is the first point at which a report from a physical AMD processor is
checked against AMD's own root, outside the guest that produced it, against a set signed for
that guest. It needed no new verification code — `attest/cmd/verify-evidence` loads a set,
wires it to `verify`, and asks `Verification.Verify` for a verdict — and it is established by
a recorded harness, `docs/snp/verify-on-hardware.sh`, because a live guest cannot be replayed.

Three things about the run are decided rather than incidental:

- **The reference value was predicted before the guest was asked anything.** A measurement
  read off a booted platform makes a check that cannot fail
  (`docs/snp-measurement-prediction.md`), so the harness predicts the stock guest's **M** from
  the firmware image and the launch parameters, authors and signs the set, and only then
  acquires evidence.
- **The verdicts were taken with the vendor unreachable, and then again with it reachable.**
  The first shows verification needs no network; the second shows the refusals are decisions
  rather than failed fetches. `verify`'s `offlineGetter` and `tsm`'s import allowlist test are
  the structural guards for both.
- **A stale chain does not surface as this design's documents say it does.** AMD derives the
  VCEK per TCB, so a stale chain carries a different key and the report's signature fails
  first: the verdict is `ReasonChainNotRooted`, not `ReasonMalformedEvidence`. See
  `docs/verification-on-hardware.md`, *What this run corrected*.

`hardwareevidence_test.go` replays the captured artifacts offline on every `go test`, as a
regression guard on that conclusion rather than as a substitute for it.

## The signed reference value set

A set is two files: a JSON document and a detached signature beside it, named by appending
`.sig`. The document is delivered from outside the launch measurement and only the reference
value author's public key lives inside it (ADR-0004), so updating values needs no new
measurement.

```json
{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 4,
  "reference_values": [
    {
      "vendor": "amd-sev-snp",
      "launch_measurement": "1111…",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true},
      "policy_digest": "ee22…"
    },
    {
      "vendor": "intel-tdx",
      "observed_mrtd": ["c1ee…"],
      "observed_rtmr0": ["c0b8…"],
      "observed_rtmr1": ["02c7…", "3a44…"],
      "predicted_rtmr2": "ecc9…",
      "td_attributes_policy": {"allow_debug": false},
      "minimum_tcb": {"status": "UpToDate", "tcb_evaluation_data_number": 20}
    }
  ]
}
```

Six things about it are decided rather than incidental:

- **A value names the image it admits and the policy that image must be running under** (format
  version 3 for `policy_digest`, version 4 for the set being only that). `policy_digest` is the
  digest of the peer's own signed policy, which the peer folded into its evidence under ADR-0002's
  binding version 2; a verifier checks it before recomputing the binding. Absent means
  unconstrained — this value admits the named image under any policy — which is the one place this
  format reads an absent field the weaker way, and a tunneld prints one line per such entry at
  every start.

  Version 3 documents also carried a top-level `egress` section, on the theory that the set was the
  sandbox's own policy as well as its guest list. It is not, and cannot be: a set whose digest is
  its sandbox's policy would have to contain the digest of a peer's set that already contains
  it, so no two peers could pin each other (`docs/policy-binding.md`). Version 4 is version 3 with
  the section removed, and a document that still carries one is refused with a sentence saying to
  move it into `policy.json` and sign both again. Version 2 documents carried no `policy_digest`
  at all and are refused likewise.

- **Every value names its vendor, and one file holds both** (format version 2, ADR-0006's
  addendum). The rest of a value's fields are that vendor's, and a field belonging to the other
  one is refused rather than ignored. Version 1 documents carried no vendor and are refused
  outright rather than read as SEV-SNP: that would be the loader deciding what an author did not
  write down. Re-emit and re-sign them. The Intel names say which kind of value each register is
  — three *observed* on the provider's hardware because nobody can predict them, one *predicted*
  from the image before it booted, which is the only one that can fail a check
  (`docs/tdx-rtmr2-prediction.md`).

- **The signature is detached and covers the document's exact bytes** (ADR-0006). The alternative — an
  envelope whose payload is an opaque blob parsed only after its signature verifies — gives the
  same unambiguous signed region and was rejected because the file exists to be read and reviewed
  by a human, and a base64 payload cannot be. There is no canonical form, nothing is ever
  re-serialised and then checked, and the API has no path from a parsed set back to a signature
  check.
- **The set is always a list**, even holding one value, because that is what makes an image
  rollout without downtime expressible rather than special.
- **A TCB floor is four separately named component versions**, all four required. This file is the
  trust root and nobody reviews a packed integer for whether it means "microcode 72".
- **Unknown fields are refused, and so are repeated ones.** An unknown field is a constraint the
  loader cannot see; a field named twice is a constraint the reviewer cannot see, since a person
  reads the first occurrence and a JSON parser takes the last. Both end with a value weaker than
  its author intended. Because Go's parser matches names case-insensitively (and folds U+212A and
  U+017F), `"Microcode"` would be a repeat of `"microcode"` to the parser and a different field to
  a reviewer; field names are therefore restricted to lowercase ASCII and underscore, and any other
  name is refused before it can alias one.

A launch measurement's width is deliberately checked nowhere: it belongs to the hardware vendor,
and one of them baked in here would sit above the seam that makes a second vendor tractable. A
measurement of the wrong width matches nothing, which fails closed.

## The signed policy

The second document a tunneld loads, beside the set and under the same author key. It is what a
sandbox *is*, where the set is whom it admits, and its digest is the number a peer names in
`policy_digest`.

```json
{
  "format": "gvisor.dev/gvisor/attest/policy",
  "version": 1,
  "egress": {"version": 1, "unattested": false},
  "forward_to": ["a234…"]
}
```

- **It names measurements and never digests**, which is the whole reason it is a separate file.
  A policy that named policies would put its own digest inside the document that fixes it, and two
  peers could not both pin each other — the finding ticket 18's live run produced and ticket 19
  acted on (`docs/policy-binding.md`).
- **`egress` says what leaves the sandbox.** Today it says unattested egress is refused, and both
  its `version` and its `unattested` field are required, because a policy a verifier vouches for
  is one its author wrote down. A document claiming `"unattested": true` is refused on load:
  nothing here enforces permitting it, and a digest that vouched for it would vouch for a promise
  no code keeps. The section versions separately from the document around it.
- **`forward_to` is the images this sandbox will dial**, enforced by the dialing side after a
  peer's evidence has verified and its policy has been admitted. Empty means it dials nobody;
  absent does not load, because an author who said nothing has not said "nobody".
- **The signature is the set's scheme under its own domain prefix**, so a signature over one
  document can never be presented as a signature over the other, and the digest of the same bytes
  differs between the two. `attest.PolicyDigestOf` computes it over the signed region, so
  `sha256sum policy.json` is a different number and the wrong one.
