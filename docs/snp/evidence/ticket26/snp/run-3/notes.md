# Pair 3: `=== 68 passed, 5 failed ===`, and the two findings that paid for it

Image `5dad2470…c5fb`: `/sbin/init`'s `kill_later` now reads the whole process
table before it signals and prints what it found. The full account of the five
pairs is `../run-4/notes.md`.

**Finding 1 — the kill could not see the sandbox.** The table it printed:

```
init: kill-after: round 1, the sandbox in this table is unshare(183) runsc(184)
init: kill-after: round 1 killed 2 processes
```

Two processes. The sentry, the gofer and the tunnel helper are re-execs of
`/proc/self/exe` with `Args[0]` set afterwards, so each one's `comm` is `exe`
(`runsc/container/container.go:1486`) and only `cmdline` carries
`runsc-sandbox`, `runsc-gofer`, `runsc-tunnel-helper`. Fixed in pair 4 by
matching argv[0]; nothing under `runsc/` was touched.

**Finding 2 — a push reaches only the sandboxes attached at that instant, and
this is a defect in the contract, recorded and not fixed.** Guest B's console:

```
B:554  tunneld: PEER key=10b39a37adb372d8… (guest A dialing)
B:556  tunneld: REFUSED … the policy pushed to the peer was not applied: … sandbox: …
B:558  tunneld: SANDBOX attached on /run/tunneld/sandbox.sock
B:577  SANDBOX applied format=policy version=1 bytes=110 sha256=b23887d0…81268
B:606…694  workload: exec /bin/probe attempt 1…30: it ran … no policy carrying an x is in force
B:694  workload: EXEC NOT REFUSED after 30 attempts over about 60s
B:700  workload: LONG-B bytes=0 expected=8388608
```

`attest/sandbox/host.go`'s `Apply` copies `h.conns` under the lock and pushes to
what is there; a sandbox that attaches afterwards never receives the policy. On
this boot guest A dialed before guest B's runsc helper had attached, and the
result is a console that says a policy is in force beside a sandbox enforcing
none of it. Two of the five failures are that; the other three are the teardown
the kill still could not produce.
