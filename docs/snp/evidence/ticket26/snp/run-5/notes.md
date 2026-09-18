# Pair 5: `=== 71 passed, 2 failed ===`, and the sentry's own cost of taking a policy

Image `1bc0c930…a1f2`: `/sbin/init` now picks the sentry's `tunnel narrow:` lines
out of the debug log onto the console, which is the only way this run can say
what installing a policy costs inside a measured guest. The full account of the
five pairs is `../run-4/notes.md`.

```
A  I0918 20:28:52.910913  tunnel.go:312   tunnel narrow: 1 of 1 names kept
A  I0918 20:28:52.911344  policy.go:225   tunnel narrow: sha256=681331c6…b785d n=1 of 1 names kept x=1 f=0
A  I0918 20:28:52.911367  policy.go:230   tunnel narrow: applied in 1.314092ms, of which the table swap was 172.759µs
B  I0918 20:28:53.071642  policy.go:230   tunnel narrow: applied in 965.309µs, of which the table swap was 66.609µs
```

One to one and a third milliseconds to take a pushed policy, of which 67–173 µs
is the swap of the table the workload is using — with the workload running
throughout, which is the property the ticket exists for. `../rq5-snp.md` uses
these two numbers.

Guest A also carries the teardown in full (`SANDBOX liveness lost: the sandbox
closed its socket`, and the refusal naming liveness) 0.9–2.4 s after its kill.

**The two that failed:** guest B's console carries neither of those two lines.
They would have been printed in the middle of init's dump of the sentry's debug
log — the same region where pair 4's two lines landed interleaved with three
other writers and survived only just (`../run-4/policy/console-b.txt` line 722).
Ticket 25's run 1 recorded the same serial-console loss and drew the same lesson.
Nothing else on either console differs from pair 4, and pair 4 is the record.
