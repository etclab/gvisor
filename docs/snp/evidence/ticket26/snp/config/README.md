# The twelve files that are the whole difference between the two guests

Ticket 26's run boots two guests from one image, with one workload disk attached
to both. Everything either of them runs is inside one launch measurement; these
twelve files are on the two config devices, which are outside it, and they are
the only thing that differs.

```
a/tunnel-table.json         guest A's sandbox may reach web.peer-b, port 80, through peer guest-b
a/exit-allow                guest A's exit will dial web.peer-a:80 for a peer, and nothing else
a/push-policy.json          what guest A PUSHES AT guest B, so it governs guest B's sandbox
a/push-policy-narrow.json   the narrower one A would push second — shipped, not used in this run
a/kill-after                150 — seconds before init kills A's sandbox
a/narrow-after              0  — no second pusher on A
b/tunnel-table.json         guest B's sandbox may reach web.peer-a, port 80, through peer guest-a
b/exit-allow                guest B's exit will dial web.peer-b:80 for a peer, and nothing else
b/push-policy.json          what guest B PUSHES AT guest A, so it governs guest A's sandbox
b/push-policy-narrow.json   the narrower one B pushes second, from a second tunneld
b/kill-after                210 — seconds before init kills B's sandbox
b/narrow-after              40 — seconds before B starts that second tunneld
```

The harness writes two more files onto each device out of the same inputs:
`tunneld.json`, the run configuration, and — on the guest that has a
`narrow-after` — `tunneld-narrow.json`, the second run configuration the second
tunneld is started with. Neither is kept here, because both name addresses the
harness chooses.

## `a/push-policy.json` governs **B**, not A

This is the one thing in this directory that reads backwards on a first pass and
it is worth being blunt about. `-push-policy` is the document a tunneld hands to
**every peer it dials**, over a tunnel that peer was already admitted on
(`attest/cmd/tunneld/main.go`, `docs/policy-push.md`). `/sbin/init` passes
`/config/push-policy.json` to the local tunneld as that flag. So:

```
A's config device --> A's tunneld --push--> B's tunneld --Apply--> B's SANDBOX
```

and therefore `a/push-policy.json` names `web.peer-a`, which is the name **B's**
sandbox fetches, and `b/push-policy.json` names `web.peer-b`, which is the name
**A's** sandbox fetches. Each file names the page its *recipient* reads, which is
the same page that guest's tunnel table already permits.

## The bytes, exactly

```
a/push-policy.json          {"format":"policy","version":1,"n":[{"host":"web.peer-a","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}
b/push-policy.json          {"format":"policy","version":1,"n":[{"host":"web.peer-b","ports":[80]}],"f":[],"x":[{"path":"/bin/busybox"}]}
a/push-policy-narrow.json   {"format":"policy","version":1,"n":[],"f":[],"x":[{"path":"/bin/busybox"}]}
b/push-policy-narrow.json   {"format":"policy","version":1,"n":[],"f":[],"x":[{"path":"/bin/busybox"}]}
```

Each file is that one line and a newline, and tunneld pushes the file's bytes
unchanged, so the sha256 a console prints is `sha256sum` of the file:

```
b23887d06a044f0752371ed8899c752ce0023a2aeaec56424e0cc3b747381268  a/push-policy.json         110 bytes
681331c69aedad34d51e9e1f325889ff81863885d1067055bf005ca9e33b785d  b/push-policy.json         110 bytes
92fb0e17644f61d44d0fa7c8ed10d2c5af5b9ccf75911a4d106463ba2967248e  a/push-policy-narrow.json   76 bytes
92fb0e17644f61d44d0fa7c8ed10d2c5af5b9ccf75911a4d106463ba2967248e  b/push-policy-narrow.json   76 bytes
```

The two narrow documents are byte-identical and therefore share a digest, which
is correct and is not a mistake: neither carries a name, so there is nothing in
them to differ. Only one of them is pushed in this run.

This is the provisional shape ticket 22 left and ticket 26 does not redefine:
`{format, version, n, f, x}`, `n` entries as `{host, ports}`, `x` entries as
`{path}` or `{sha256}`, `f` entries as `{path, modes}`. `cidr` is deliberately
absent — a `cidr` entry is refused as unenforceable by name, the same way Deno
refuses it.

## Why each is a subset of what it narrows

`P1 ⊑ P0` is checked component-wise over sorted, deduplicated atoms, and the
first push is additionally checked against the boot table:

```
A's boot table  ->  n atoms { net:web.peer-b:80 }
b/push-policy.json          { net:web.peer-b:80 }        equal, so the first push names nothing the table lacks
b/push-policy-narrow.json   { }                          a strict subset, so the second push narrows
x, both                     { run:/bin/busybox }         unchanged: x is fixed by the first push and may only shrink
f, both                     { }                          nothing, and nothing is a subset of nothing
```

`f` is empty on purpose. `F` is approximated by mounts and only by mounts in this
ticket: the bundle's root is read-only, the config device is `ro,noexec`, and the
workload device is `ro,exec` — and the record says plainly that a path×{r,w,x}
allow-set is not what this enforces. An `f` list here would be a claim the sentry
does not make.

## Why only guest B narrows, and what would happen if both did

The liveness rule tunneld enforces is sandbox-agnostic: after a successful Apply
on a tunnel with digest `D`, the tunneld that applied it watches its sandbox and
tears that tunnel down if the sandbox stops pulsing `D`, pulses something else,
or closes its socket. It does not parse `n`, `f` or `x`, so it cannot tell a
*narrowing* from a *different policy* — it compares digests.

So when B's second tunneld pushes the narrower document at A, A's sandbox starts
pulsing the narrower digest, and **A's tunneld loses liveness for the tunnel B's
first tunneld opened** and closes it, naming the mismatch. That is correct
behaviour and this run asserts on it; what it means for the arrangement is that
the narrowing must land on the guest whose own long stream is *outbound*:

```
A's sandbox --> A's tunneld --[tunnel A dialed]--> B's tunneld --> B's exit --> B's httpd
                                                  ^ B applied A's policy here and watches B's sandbox
```

A's long fetch rides the tunnel **A** dialed, which B watches against **B's**
sandbox's digest — and B's sandbox is never narrowed, so nothing about that
tunnel changes. Narrowing A therefore leaves A's stream alone, which is exactly
the property under test. Narrowing **B** instead would have torn down the tunnel
carrying A's fetch, and the run would have proved the opposite of what it set out
to.

`a/push-policy-narrow.json` and `a/narrow-after` are shipped anyway, set to a
value that starts nothing, so that the two sides stay mirror images and either
can be the narrowed one by changing one number.

## The timing knobs are not measured, and they move only *when*

`kill-after` and `narrow-after` are read by `/sbin/init` (SEV-SNP) and `/init`
(TDX) out of `/config`, checked against the shape a number has before they reach
a command line, and printed on the console next to what they did. Nothing about
them is in a launch measurement, and a host that changed one would change how
long a recording lasts and nothing else: the ceiling is compiled in, the runsc
flag set is in the measured init, and the policy the sandbox ends up under is
decided by the peer that pushed it and by the sentry that judged the subset.

`0` means "not set". A file that is not a number is ignored with a warning.

## The rest is ticket 25's, for ticket 25's reasons

**The peer names are the ones in `peers.json`**, because `default_exit` and a
name's `peer` are tunneld peer labels; a label that is not in `peers.json` is a
stream that never opens.

**`exit-allow` is a file and not a field in `tunneld.json`** because the run
configuration refuses unknown fields (`attest/cmd/tunneld/runconfig.go`,
`dec.DisallowUnknownFields()`), so a new field would mean changing the measured
binary. It would also be the wrong place: the list belongs to the exit, which is
another process, and `-allow` is its flag. An absent file is an empty list, which
refuses everything.

**Why each guest's table names the *other* guest's page.** The names in a table
are what that guest's sandbox may reach; the names in an exit-allow are what that
guest's exit will dial *for somebody else*. So A's table names `web.peer-b` and
B's exit-allow names `web.peer-b:80` — the same destination from the two ends of
one hop — and the mirror pair is the hop the other way.

`web.peer-a` and `web.peer-b` both resolve to `127.0.0.1` in **both** guests
(`/etc/hosts`, in the image and measured). That costs nothing: a guest is only
ever asked for a name by its own exit, and its own exit only dials what its
exit-allow permits.
