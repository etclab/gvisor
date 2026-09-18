#!/bin/sh
# The workload of ticket 26's adapter check: one sandbox, one policy pushed
# twice, and the six things the definition of done says must be true from
# inside.
#
# It decides nothing and asserts nothing about timing: it says what it sees, in
# order, and stands still at the end so that what ends it is a kill from
# outside — which is how the contract's liveness is made to end for a reason
# other than the script running out of work.
BB=/bin/busybox
say() { $BB echo "workload: $*"; }
KEEP="${KEEP:-keep.peer-a:9000}"
GONE="${GONE:-gone.peer-a:9001}"
GONEADDR="${GONEADDR:-100.64.1.0}"
GONEPORT="${GONE#*:}"

say "=== ticket 26 adapter check ==="

# 1. before the narrowing: both names are in the table and both answer.
out=$($BB wget -q -O - "http://$KEEP/" 2>&1); say "BEFORE GET http://$KEEP/ rc=$? out='$out'"
out=$($BB wget -q -O - "http://$GONE/" 2>&1); say "BEFORE GET http://$GONE/ rc=$? out='$out'"
say "READY"

# 2. the narrowing, watched from in here: the name the second push drops stops
#    resolving, and nothing else changes.
i=1
while :; do
	out=$($BB wget -q -O - "http://$GONE/" 2>&1)
	case "$out" in
	*"bad address"*)
		say "NARROWED $GONE stopped resolving on attempt $i: $out"
		break
		;;
	esac
	if [ "$i" -ge 90 ]; then
		say "NOT NARROWED: $GONE still resolved on attempt $i"
		break
	fi
	i=$((i + 1))
	$BB sleep 1
done
out=$($BB wget -q -O - "http://$GONEADDR:$GONEPORT/" 2>&1); say "AFTER GET the dropped name's old address http://$GONEADDR:$GONEPORT/ rc=$? out='$out'"
out=$($BB wget -q -O - "http://$KEEP/" 2>&1); say "AFTER GET http://$KEEP/ rc=$? out='$out'"

# 3. X: a file that is neither a path nor a digest the policy names.
out=$(/bin/probe --help 2>&1 | $BB head -1); say "EXEC /bin/probe out='$out'"
# and one that is: every applet of the busybox the policy names by path.
out=$(/bin/uname -s 2>&1); say "EXEC /bin/uname (a symlink to the busybox x names) out='$out'"

# 4. F, such as it is: a bind mount carrying ["ro","noexec"]. The file under it
#    is the very busybox the policy permits by path, so what refuses this exec
#    is the mount and not the policy — which is the whole of what F is in this
#    sandbox, and the record says so.
out=$(/noexec/busybox true 2>&1); say "EXEC /noexec/busybox on a ro,noexec mount out='$out' rc=$?"
out=$($BB cat /noexec/busybox > /dev/null 2>&1; $BB echo $?); say "READ /noexec/busybox rc=$out (noexec refuses the exec and not the read)"
out=$($BB touch /noexec/written 2>&1); say "WRITE /noexec/written out='$out'"

say "=== controls done; standing still so that a kill is what ends this workload ==="
$BB sleep 300
say "=== nothing killed this workload; it ran out of sleep ==="
