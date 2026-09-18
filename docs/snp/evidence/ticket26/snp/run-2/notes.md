# Pair 2: `=== 72 passed, 1 failed ===`

Same image as pair 1 (`f8b60b78…ef31`): what changed is outside the measurement —
the tunnel idle timeout, 60 s → 420 s (`hold + 60`, printed before the boot), and
the workload's exec control asking once before anything else. The full account is
`../run-4/notes.md`.

Both changes did what they were for. The transition is on both consoles —
`exec /bin/probe attempt 0: it ran (rc=127); no policy carrying an x is in force
in this sandbox yet`, then `EXEC REFUSED /bin/probe on attempt 1` — and guest B
carried the teardown the ticket is about:

```
B:776  tunneld: SANDBOX liveness lost: the sandbox closed its socket
B:777  tunneld: REFUSED verification refused: the policy pushed to the peer is no longer live: …
```

**The one that failed:** guest A never reported the socket closing. Its console
says why, a hundred and fifty seconds earlier: `init: kill-after: killed 1
processes`, printed at the very end of the run rather than at the kill. The scan
matched `comm`, killed the foreground runsc and left the sentry, the gofer and
the tunnel helper alive — their `comm` is `exe` — so the socket whose closing is
the teardown did not close. Pair 3 printed the table that proved it and pair 4
fixed it.
