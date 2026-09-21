# The four files that are the whole difference between the two guests

Ticket 25's SNP run boots two guests from one image. Everything either of them
runs is inside one launch measurement; these four files are on the two config
devices, which are outside it, and they are the only thing that differs.

```
a/tunnel-table.json   guest A's sandbox may reach web.peer-b, on port 80, through peer guest-b
a/exit-allow          guest A's exit will dial web.peer-a:80 for a peer, and nothing else
b/tunnel-table.json   guest B's sandbox may reach web.peer-a, on port 80, through peer guest-a
b/exit-allow          guest B's exit will dial web.peer-b:80 for a peer, and nothing else
```

**The peer names are the ones in `peers.json`**, because `default_exit` and a
name's `peer` are tunneld peer labels: the sandbox's `Open` asks tunneld for that
peer by name and tunneld looks it up in the table the harness wrote
(`{"peers": {"guest-b": "10.14.0.3:4433"}}`). A label that is not in `peers.json`
is a stream that never opens.

**`exit-allow` is a file and not a field in `tunneld.json`** because the run
configuration refuses unknown fields (`attest/cmd/tunneld/runconfig.go:289-302`,
`dec.DisallowUnknownFields()`), so a new field would mean changing the measured
binary. It would also be the wrong place: the list belongs to the exit, which is
another process, and `-allow` is its flag. `/sbin/init` reads the file and passes
its contents through. An absent file is an empty list, which refuses everything —
the honest default for the one place a destination is checked
(`attest/cmd/agent-probe/exit.go:31-42`).

**Why each guest's table names the *other* guest's page.** The names in a table
are what that guest's sandbox may reach; the names in an exit-allow are what that
guest's exit will dial *for somebody else*. So A's table names `web.peer-b` and
B's exit-allow names `web.peer-b:80` — the same destination, from the two ends of
one hop — and the mirror pair is the hop the other way.

`web.peer-a` and `web.peer-b` both resolve to `127.0.0.1` in **both** guests
(`/etc/hosts`, in the image and measured). That costs nothing: a guest is only
ever asked for a name by its own exit, and its own exit only dials what its
exit-allow permits.
