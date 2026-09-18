#!/bin/sh
# Spike E2's busybox workload: the execs whose identities the run records, and
# the benchmark whose numbers it compares.
#
# Every command is spelled /bin/busybox <applet> or an absolute path, because
# what the sentry hashes and compares is the file an execve named and this
# script's whole subject is which path that turns out to be.
BB=/bin/busybox
say() { $BB echo "workload: $*"; }
N="${N:-200}"

say "=== E2: the exec sink's cost and reach ==="

# 1. the execs whose (path, sha256) the receiver records. Three of them go
#    through a symlink to busybox, which is the open question: does the sentry
#    report the path the workload typed or the file it resolved to?
say "--- execs through /bin/busybox itself"
$BB uname -a
$BB echo hello
$BB cat /etc/hosts

say "--- execs through symlinks to the same file"
/bin/uname -a
/bin/echo hello
/bin/cat /etc/hosts

say "--- an exec of a script, whose interpreter is what is opened first"
/bin/sh -c 'echo from a child shell'
/e2-script.sh

say "--- an exec of a different file at a different path"
out=$(/bin/probe --help 2>&1 | $BB head -1); rc=$?
say "probe rc=$rc out='$out'"

# 2. the benchmark. It is a static Go program, so its own identity is a fourth
#    distinct one, and what it execs is busybox.
say "--- execbench, three rounds of $N fork+execve+wait of /bin/busybox true"
# Three rounds rather than one, because the interval measured is dominated by
# the platform's process creation and a single round's median moves by more
# between runs of the same configuration than the sink costs.
/bin/execbench "$N" /bin/busybox true
/bin/execbench "$N" /bin/busybox true
/bin/execbench "$N" /bin/busybox true

say "=== done ==="
