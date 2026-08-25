# attest

The attested-tunnel module: evidence, verification, and — as later tickets land — the
reference value loader, the RA-TLS carry, the transport, and tunneld.

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
required, and the suite passes inside an empty network namespace:

```sh
unshare -rn env PATH=/usr/local/go/bin:$PATH HOME=$HOME go test ./...
```

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
| `attest`  | The public surface: the vendor seam, the reference value vocabulary, the binding of ADR-0002, the refusal taxonomy, and `Verification.Verify`. |
| `verify`  | The SEV-SNP verifier. Wraps `go-sev-guest` (ADR-0003) and keeps that library's API shape from reaching anywhere else. |
| `snpfake` | A fake SEV-SNP platform built on `go-sev-guest`'s test signing. Implements the acquisition half of the seam; the real acquirer is ticket 04. Test support, but not a `_test` package, because tunneld's tests will inject it through a constructor. |

`verify` and `snpfake` have no test files of their own, and that is the design rather than a
gap. The agreed seam for this effort is tunneld's public API; tunneld does not exist yet, so the
seam here is this module's public surface. Every test drives `Verification.Verify` and asserts on
external behaviour — accepted, or refused with a given reason — and none reaches inside `verify`
or asserts on how a verdict was reached. Those packages stay free to change, which is the point
of ADR-0003 having drawn the seam deliberately.
