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

Every test runs against fake hardware with test signing. No confidential VM and no network is
required: the tunneld tests talk over loopback on ephemeral ports, and the suite passes inside
an empty network namespace with only loopback up:

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
| `attest`  | The public surface: the vendor seam, the reference value vocabulary, the signed reference value set format and its loader, the binding of ADR-0002, the refusal taxonomy, and `Verification.Verify`. |
| `verify`  | The SEV-SNP verifier. Wraps `go-sev-guest` (ADR-0003) and keeps that library's API shape from reaching anywhere else. |
| `snpfake` | A fake SEV-SNP platform built on `go-sev-guest`'s test signing. Implements the acquisition half of the seam; the real acquirer is ticket 04. Test support, but not a `_test` package, because tunneld's tests inject it through `tunneld.Config`. |
| `ratls`   | The certificate as a serialization envelope: a versioned payload under a private arc carrying the evidence, the chain and the binding context, and the handshake callback that runs `Verification.Verify` on the peer's. Nothing else in the certificate is read. |
| `tunnel`  | The transport: QUIC with TLS 1.3, early data refused on both ends, one exchange per stream, and the establishment round trip. Knows nothing about attestation. |
| `tunneld` | The composition root and the public API: `New` with a `Config`, `Peer(name)` yielding a `Channel`, `Channel.Exchange`. |

`verify`, `snpfake`, `ratls` and `tunnel` have no test files of their own, and that is the design
rather than a gap. There are two seams, one per layer. Below tunneld the seam is this module's
public surface: every `attest` test drives `Verification.Verify` or the set loader and asserts on
external behaviour — accepted, or refused with a given reason — and none reaches inside `verify`.
Above it the seam is tunneld's API: every `tunneld` test starts tunnelds with the fake platform
injected through `Config` and asserts that a channel exists or does not, and that an exchange
completes or does not. Certificate carry, transport and peer resolution are tested only through
that API, and verification is not re-tested there.

## tunneld

A tunneld is one sandbox's identity for the life of the process. It generates its key at startup
and never persists it, takes the sandbox identifier as a parameter (synthetic until the sentry
integration passes a real one), loads its reference value set through
`attest.LoadReferenceValueSetFile` against the author public key it was started with, and refuses
to start on `attest.ErrSetRefused` — there is no path that runs without a set.

Two things about establishment are decided rather than incidental:

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

The payload's extension identifier sits under the private enterprise number IANA reserves for
documentation (32473, RFC 5612). It is nobody's, so no verifier can be led to guess another
party's format, and it is visibly a placeholder: if an enterprise number is assigned for this
work, `ratls.PayloadOID` is the one constant that changes. (Go's `encoding/asn1` represents arcs
as `int`, which rules out the UUID-based `2.25` arc.)

`snpfake` must never reach a production binary: it imports `go-sev-guest`'s test helpers, which
import `testing` and register flags at init, and ticket 14 puts the binary inside the launch
measurement. `tunneld/importgraph_test.go` lists the non-test dependency graph of package
`tunneld` and fails if `snpfake`, `go-sev-guest/testing` or `testing` appears; the fake is
injected only through `Config`, from test code.

The reference value loader is driven through the same seam: a set is loaded and then wired into a
`Verification` and shown to admit or refuse a fake platform, because what a set is for is deciding
who gets in. The spec's module list names a separate `refvals` package for the format; it lives in
`attest` instead, following the same collapse ticket 02 made when the reference value vocabulary
became `attest/refvals.go` rather than a package. A separate package would have to import `attest`
for `ReferenceValueSet`, so `attest` could not expose the loader, and the loader would then be a
second public surface for tests to drive.

## The signed reference value set

A set is two files: a JSON document and a detached signature beside it, named by appending
`.sig`. The document is delivered from outside the launch measurement and only the reference
value author's public key lives inside it (ADR-0004), so updating values needs no new
measurement.

```json
{
  "format": "gvisor.dev/gvisor/attest/reference-value-set",
  "version": 1,
  "reference_values": [
    {
      "launch_measurement": "1111…",
      "minimum_tcb": {"bootloader": 9, "tee": 0, "snp": 23, "microcode": 72},
      "guest_policy": {"allow_smt": true}
    }
  ]
}
```

Four things about it are decided rather than incidental:

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
