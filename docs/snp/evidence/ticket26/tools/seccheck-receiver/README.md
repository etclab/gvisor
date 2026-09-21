# `seccheck-receiver` — ticket 26's copy, which also decodes `sentry/exec_refused`

Ticket 25's receiver (`../../../ticket25/tools/seccheck-receiver/`) with two
points added. It is the same program in every other respect: `argv[1]` is the
`AF_UNIX` `SOCK_SEQPACKET` socket a trace session's **remote sink** is pointed
at, it does the version handshake, and every message becomes one line on stdout.
No bazel, no module, no dependency but the standard library.

## Build

```
/usr/local/go/bin/go build -o seccheck-receiver ./docs/snp/evidence/ticket26/tools/seccheck-receiver
```

It decodes two things by hand, which is why it needs nothing generated: the
remote sink's eight-byte header (`pkg/sentry/seccheck/sinks/remote/wire`,
little-endian `HeaderSize uint16`, `MessageType uint16`, `DroppedCount uint32`)
and enough of protobuf's wire format to walk a message of varints and
length-delimited fields.

## What ticket 26 added

| message type | point | fields read |
| ---: | --- | --- |
| 3 | `sentry/execve` | `binary_path` (2), `binary_sha256` (8) |
| 39 | `sentry/egress_refused` | ticket 25's six |
| **40** | **`sentry/exec_refused`** | `path` (2), `sha256` (3), `reason` (4) |

`sentry/exec_refused` is the new point: an `execve` the policy in force did not
name, refused with `EACCES`. `sentry/execve` is not new, but it is decoded here
because **the exec sink turns it on wherever it is installed** — X is decided on
the identity that point carries — so a trace of one run is the list of every
`(path, sha256)` the sandbox executed. That is how spike E2's reach table was
produced, and it is worth knowing that it happens whether or not the trace
session asked for the point: `seccheck.State.SentToSinks` calls every registered
sink for every enabled point, so a session that names only `egress_refused` will
still receive one `execve` per exec once a policy carrying an `x` lands.

## `pod-init.json`

The file beside this README is ticket 25's, enabling one point. Ticket 26's
harnesses write their own; the two shapes they use are

```json
{"trace_session":{"name":"Default",
  "points":[{"name":"sentry/egress_refused","context_fields":["time","container_id","thread_id"]},
            {"name":"sentry/exec_refused","context_fields":["time","container_id","thread_id"]}],
  "sinks":[{"name":"remote","config":{"endpoint":"<socket>","retries":3},"ignore_setup_error":true}]}}
```

and, for a run that wants the identities without a policy being pushed at all,

```json
{"name":"sentry/execve","optional_fields":["binary_sha256"],
 "context_fields":["time","container_id","thread_id"]}
```

`optional_fields` is what asks for the digest; without it `binary_sha256` is
empty and the hash cache is never set up (`seccheck.State.SetupExecveHashCache`
returns early when no session asked for a hash).

## What a line looks like

```
listening on /dev/shm/t26-check-1688627/check.events
connected: the sentry speaks wire version 1
execve path=/bin/busybox sha256=dbac288c…6ac14 time=2026-09-18T19:22:15.031614246Z container_id=t26-check-… thread_id=2
egress_refused protocol=dns name=gone.peer-a reason=unknown-name time=2026-09-18T19:22:20.621908277Z
egress_refused protocol=tcp address=100.64.1.0 port=9001 reason=not-in-table time=… container_id=… thread_id=20
exec_refused path=/bin/probe sha256=c4b9b606…2f6e reason=not-in-x time=… container_id=… thread_id=25
disconnected
```

`reason` on an `exec_refused` has one value today, `not-in-x`: the resolved path
is not one of `x`'s paths and the SHA-256 of the contents is not one of `x`'s
digests. A refusal by the **mount** — a `noexec` bind mount — is *not* here: it
is `EACCES` from `pkg/sentry/vfs`, it happens before any point fires, and
nothing records it. That asymmetry is F's, and the record says so.

An `execve` line whose `sha256` is empty means the point was enabled without
`binary_sha256`, or the binary could not be hashed; an `x` written by digest
would refuse such an exec, and one written by path would not care.
