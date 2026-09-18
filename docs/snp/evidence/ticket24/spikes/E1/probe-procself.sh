#!/busybox sh
# Ticket 24 E1, the diagnostic for variant b. runsc re-execs itself through
# /proc/self/exe to start the gofer and the sandbox
# (runsc/specutils/specutils.go:97, used at runsc/container/container.go:1471,
# reported at :1686-1688 and wrapped at :383), so this probe asks the three
# things that path needs of the procfs it is handed: does /proc/self resolve,
# can /proc/self/exe be read, and can it be executed.
BB=/busybox
echo "---- the procfs at /proc"
$BB grep -E " proc | /proc" /proc/mounts
echo "---- my pid in MY pid namespace: $$"
echo "---- readlink /proc/self  (my pid as THAT procfs numbers it)"
$BB readlink /proc/self || echo "READLINK_FAILED=$?"
echo "---- is /proc/\$\$ there?  (\$\$ = $$)"
$BB ls -d /proc/$$ 2>&1 || echo "LS_FAILED=$?"
echo "---- ls -l /proc/self/exe"
$BB ls -l /proc/self/exe 2>&1 || echo "LS_EXE_FAILED=$?"
echo "---- readlink /proc/self/exe"
$BB readlink /proc/self/exe 2>&1 || echo "READLINK_EXE_FAILED=$?"
echo "---- read it: cat /proc/self/exe | wc -c"
$BB cat /proc/self/exe 2>&1 | $BB wc -c
echo "---- execute it: /proc/self/exe true"
/proc/self/exe true 2>&1; echo "EXEC_EXIT=$?"
echo "---- execute it with an argument that prints: /proc/self/exe echo hello-from-proc-self-exe"
/proc/self/exe echo hello-from-proc-self-exe 2>&1; echo "EXEC_EXIT=$?"
echo "---- execute the same file by its real path: /busybox echo hello-from-real-path"
/busybox echo hello-from-real-path 2>&1; echo "EXEC_EXIT=$?"
echo "---- and the path runsc would take for the gofer: /runsc --version"
/runsc --version 2>&1; echo "EXEC_EXIT=$?"
