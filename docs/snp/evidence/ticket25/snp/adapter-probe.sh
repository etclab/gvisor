#!/bin/sh
# The workload of ticket 25's SNP run, inside the sandbox and nowhere else.
#
# Three fetches and a uname, and the same three on both guests: this script is on
# one disk, that disk is attached to both guests read-only, and nothing in it
# knows which guest it is running on. What decides the outcome is the tunnel
# table on each guest's config device, which the measured sentry enforces — so
# on guest A the first fetch is the one that works and on guest B the second is,
# and neither guest can reach the third.
#
# Everything this prints goes to the sandbox's stdout, which runsc puts on the
# guest's serial console, which the harness captures. There is no network in
# here to put it on: --network=none, one loopback-only stack, and the adapter.
say() { echo "workload: $*"; }

# fetch retries, and what it will not retry is the whole point of it.
#
# Both guests are booted at once and this sandbox starts about a tenth of a
# second after its own tunneld. The peer it wants may still be acquiring its
# evidence, or may have a listener and no exit attached to it yet, and a fetch
# that gave up on the first attempt would record that race as a refusal. So a
# failure is tried again, for about twenty seconds.
#
# A name that did not resolve is *not* tried again. That is not a race: the
# sentry answers NXDOMAIN for a name this guest's tunnel table does not carry,
# and it will answer NXDOMAIN for the next twenty seconds too. Telling the two
# apart is what keeps a control fast and honest — the control's line is the
# first attempt's, and it says out loud that it is not being retried.
fetch() { # NAME
  n=1
  while :; do
    say "--- GET http://$1/ (attempt $n)"
    out=$(wget -q -O - "http://$1/" 2>&1)
    rc=$?
    [ -n "$out" ] && echo "$out"
    if [ "$rc" = 0 ]; then
      say "wget exit 0 for $1"
      return 0
    fi
    case "$out" in
      *"bad address"*)
        say "wget exit $rc for $1: the name did not resolve, so it is not in this guest's tunnel table; not retrying"
        return 1 ;;
    esac
    if [ "$n" -ge 10 ]; then
      say "wget exit $rc for $1 after $n attempts"
      return 1
    fi
    n=$((n+1))
    sleep 2
  done
}

say "=== ticket 25: a sandbox on the adapter ==="
say "this process has no interface of its own; its only way out is the adapter"
# 1. guest A's permitted name: A's table maps it to peer guest-b, whose exit
#    dials web.peer-b:80 on its own loopback. On guest B it is not in the table
#    and the sentry's resolver answers NXDOMAIN.
fetch web.peer-b
# 2. the mirror image: guest B's permitted name, and a name guest A cannot
#    resolve.
fetch web.peer-a
# 3. the control, in nobody's table on either guest. NXDOMAIN, and the sentry
#    records the refusal; wget reports it as a bad address, because a name that
#    does not resolve never becomes an address to dial.
fetch not-in-the-table.example
# 4. and the line that says this ran in a sandbox at all: the sentry's own
#    compile-time kernel string, against a guest running 6.16.0-snp-guest, with
#    the bundle's hostname as the nodename (ticket 24's argument, unchanged).
uname -a
say "=== done ==="
