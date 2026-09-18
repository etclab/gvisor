# `seccheck-receiver` — the receiver the `sentry/egress_refused` evidence is read from

The sentry records a refusal to let bytes leave the sandbox as a trace point,
`sentry/egress_refused`. A trace session with a **remote sink** sends those
points to a process outside the sandbox over an `AF_UNIX` `SOCK_SEQPACKET`
socket. This is that process: it listens, does the version handshake, and
prints one line per point.

It is `examples/seccheck/server.cc` in Go, with one point's fields spelled out,
and it keeps that server's contract: **`argv[1]` is the socket path**, and every
message becomes a line on stdout.

## Build

No bazel, no module, no dependency but the standard library:

```
/usr/local/go/bin/go build -o seccheck-receiver ./docs/snp/evidence/ticket25/tools/seccheck-receiver
```

(Or `cd` into this directory and `go build -o seccheck-receiver .` — the
package has no `go.mod` of its own and builds under the repository's.)

It decodes two things by hand, which is why it needs nothing generated: the
remote sink's eight-byte header (`pkg/sentry/seccheck/sinks/remote/wire`,
little-endian `HeaderSize uint16`, `MessageType uint16`, `DroppedCount
uint32`), and enough of protobuf's wire format to walk a message of varints and
length-delimited fields. The field numbers it reads are `EgressRefused`'s in
`pkg/sentry/seccheck/points/sentry.proto` and `ContextData`'s in
`points/common.proto`. Regenerating the protos is therefore not needed; adding
a field to `EgressRefused` means adding one line here.

## Run

```
./seccheck-receiver /run/user/$(id -u)/t25-events.sock
```

Then point a sandbox's trace session at the same path with
`runsc ... --pod-init-config=pod-init.json run ...`.

## `pod-init.json`

The session beside this README enables exactly the one point and sends it to a
remote sink, with `ignore_setup_error` so that a sandbox started without a
receiver still boots:

```json
{"trace_session":{"name":"Default",
  "points":[{"name":"sentry/egress_refused",
             "context_fields":["time","container_id","thread_id"]}],
  "sinks":[{"name":"remote",
            "config":{"endpoint":"<socket>","retries":3},
            "ignore_setup_error":true}]}}
```

`endpoint` must be the path the receiver was started on. The three context
fields are the ones the loopback harness asks for, and they are what the
printed line carries beyond the point's own fields.

## What a line looks like

```
listening on /run/user/1000/t25-events.sock
connected: the sentry speaks wire version 1
egress_refused protocol=dns reason=unknown-name name=example.com time=2026-09-18T12:00:00.123456789Z container_id=t25-adapter-1234 thread_id=12
egress_refused protocol=tcp address=8.8.8.8 port=53 reason=not-in-table time=... container_id=... thread_id=...
egress_refused protocol=udp address=8.8.8.8 port=53 reason=not-a-tcp-stream time=... container_id=... thread_id=...
```

`reason` is which rule refused it: `not-in-table` (an address that is neither
loopback nor one the sentry allocated for a name), `wrong-port` (a name's
address on a port the table does not permit), `not-a-tcp-stream` (a datagram or
a non-`AF_INET` socket aimed at a name's address), `unavailable` (the helper or
tunneld could not produce the stream), `unknown-name` and `unknown-type` (the
resolver was asked for a name the table does not carry, or for a record type
other than A and AAAA).

A refusal by the **far exit** is deliberately absent: that is the other end's
allow list, it is recorded there, and the sandbox is told `ECONNREFUSED`
rather than `ENETUNREACH`.
