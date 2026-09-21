#!/bin/sh
# Spike E1's workload: hold one stream open through a narrowing and say what
# happened, from inside the sandbox.
#
# Everything here is /bin/busybox. The sandbox has --network=none, one
# loopback-only stack and the adapter; /etc/resolv.conf says 127.0.0.53, and the
# only thing that can turn a name into an address is the responder in the sentry.
#
# The harness pushes policies from outside while this runs, and this script does
# not know when: it polls the name it expects to lose, so the transition is what
# it records rather than a guess at a time.
BB=/bin/busybox
say() { $BB echo "workload: $*"; }
stamp() { $BB date -u +%H:%M:%S; }

BULK="${BULK:-bulk.peer-a:9000}"
DROP="${DROP:-drop.peer-a:9001}"
EXPECT="${EXPECT:-16777216}"
DROPADDR="${DROPADDR:-100.64.1.1}"
BULKHOST="${BULK%:*}"
DROPHOST="${DROP%:*}"
DROPPORT="${DROP#*:}"
# WHICH says which name this run narrows away: "other" is the name the stream is
# not on, "self" is the name the stream IS on.
WHICH="${WHICH:-other}"

look() { $BB nslookup "$1" 2>&1 | $BB tr '\n' ' '; }

say "=== E1: narrowing under traffic (WHICH=$WHICH) ==="
say "start $(stamp)"
say "BEFORE resolve $BULKHOST: $(look "$BULKHOST")"
say "BEFORE resolve $DROPHOST: $(look "$DROPHOST")"
out=$($BB wget -q -O - "http://$DROP/" 2>&1); say "BEFORE GET http://$DROP/ rc=$? out='$out'"
out=$($BB wget -q -O - "http://$BULK/" 2>&1); say "BEFORE GET http://$BULK/ rc=$? out='$out'"

# The long stream. The body is a fixed size the far exit was told to serve, and
# the count at the end is the whole answer to "did the open stream survive".
(
	c=$($BB wget -q -O - "http://$BULK/big" 2>/dev/null | $BB wc -c)
	if [ "$c" = "$EXPECT" ]; then
		say "LONG COMPLETE bytes=$c expected=$EXPECT at $(stamp)"
	else
		say "LONG SHORT bytes=$c expected=$EXPECT at $(stamp)"
	fi
) &
LONGPID=$!
say "LONG STARTED pid=$LONGPID at $(stamp)"
$BB sleep 1

# The name this run expects to lose, asked for until it is lost. A name the
# policy in force does not carry never becomes an address, so what wget reports
# is a resolution failure and not an errno on a socket.
if [ "$WHICH" = self ]; then
	WATCH="$BULK"
else
	WATCH="$DROP"
fi
i=1
while :; do
	out=$($BB wget -q -O - "http://$WATCH/" 2>&1)
	case "$out" in
	*"bad address"*)
		say "NARROWED $WATCH stopped resolving on attempt $i at $(stamp): $out"
		break
		;;
	esac
	if [ "$i" -ge 90 ]; then
		say "NOT NARROWED: $WATCH still resolved on attempt $i at $(stamp)"
		break
	fi
	i=$((i + 1))
	$BB sleep 1
done

# The removed name's OLD synthetic address, dialled directly. The name is gone
# from the resolver and the address is gone from the table, so this is the other
# half of N: ENETUNREACH and a not-in-table event.
if [ "$WHICH" = self ]; then
	OLD="$DROPADDR"
	OLDPORT="${BULK#*:}"
else
	OLD="$DROPADDR"
	OLDPORT="$DROPPORT"
fi
out=$($BB wget -q -O - "http://$OLD:$OLDPORT/" 2>&1); say "AFTER GET the removed name's old address http://$OLD:$OLDPORT/ rc=$? out='$out'"
say "AFTER resolve $BULKHOST: $(look "$BULKHOST")"
say "AFTER resolve $DROPHOST: $(look "$DROPHOST")"
out=$($BB wget -q -O - "http://$BULK/" 2>&1); say "AFTER GET http://$BULK/ rc=$? out='$out'"
out=$($BB wget -q -O - "http://$DROP/" 2>&1); say "AFTER GET http://$DROP/ rc=$? out='$out'"

say "waiting for the long stream (pid $LONGPID) at $(stamp)"
wait "$LONGPID"
say "=== done $(stamp) ==="
