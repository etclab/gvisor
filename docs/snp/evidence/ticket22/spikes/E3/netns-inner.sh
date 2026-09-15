#!/bin/sh
# The inside of the namespace: the ceiling first, then one guest's network
# stood up the way docs/snp/cloud/tdx/init.tdx stands up a real one, then the
# proof.
#
# It is run by run-e3.sh under `unshare -rn`, which is a user namespace and a
# network namespace and no sudo at all: inside a user namespace we are root
# enough for netlink and for nf_tables, and the network namespace means the
# workstation's own rules and interfaces are not here to confuse the result.
#
# Everything below mirrors init.tdx, with one substitution, one deletion and
# one reordering:
#
#   substitution  the VPC link is a dummy interface named eth0 rather than a
#                 gve one. It has the same name, the same /32 addressing and
#                 the same off-link gateway route as ticket 19's guests
#                 (docs/snp/evidence/ticket19/scenario-one/config-src/a/network.conf).
#                 A dummy device accepts a packet and discards it, which is
#                 exactly what is wanted: a packet the ceiling permits leaves
#                 the socket and goes nowhere, and a packet the ceiling refuses
#                 never reaches the device at all. The difference between those
#                 two is the whole experiment.
#
#   deletion      no config device contributes to the rule set. A minimum one
#                 exists only because tunneld's egress probe is behind a
#                 signature check and E3 wants the real probe rather than a
#                 copy of it.
#
#   reordering    the ceiling goes in FIRST, against a namespace that has no
#                 eth0 and whose lo is still down. init.tdx installs its rule
#                 set at step 5, after the network; it had to, because the rule
#                 set named peer addresses that were on the config device. A
#                 constant has no such dependency, so the window in which the
#                 guest is up and unconstrained has length zero.
#
# Environment, from run-e3.sh:
#   BIN      directory holding tunneld, ceilinginstall and control
#   CEILING  path to ceiling.nft
#   CFG      a minimum config device, only so that tunneld reaches its probe
#   OUT      directory to write captures into
set -e

IFACE=eth0
ADDR=10.128.0.40
PREFIX=32
GW=10.128.0.1
MTU=1460
PORT=4433
PEER=10.128.0.41   # an address no machine here has; it is a destination, not a peer

say() { echo "e3: $*"; }

# ---- 0. the ceiling, before there is anything to filter ------------------
{
	say "================ PHASE 0: the ceiling before the link ================"
	say "the namespace as it stands, before anything is installed:"
	ip -o link show | sed 's/^/e3: link: /'
	nft list ruleset | sed 's/^/e3: ruleset: /' || true
	say "(an empty ruleset above means the kernel is holding nothing yet)"

	say "installing $CEILING — a constant file; no config device has been looked for yet"
	nft -f "$CEILING"
	say "installed, with no eth0 in this namespace and lo still down:"
	nft list ruleset

	# The sub-experiment that forced `iifname`. `iif` resolves the name to an
	# interface index at rule-load time and fails outright when the interface
	# is absent; `iifname` compares the name when a packet arrives and does
	# not. A ceiling that must be installed before the link can only be
	# written the second way.
	say "why iifname and not iif: the same rule in the index-matching spelling,"
	say "against this same namespace with no eth0 in it:"
	variant=$CFG/../e3-iif-variant.nft
	cat > "$variant" <<-EOF
	table inet probe_iif_spelling {
		chain output {
			type filter hook output priority 0; policy drop;
			oif "$IFACE" accept
		}
	}
	EOF
	set +e
	nft -f "$variant" > "$variant.out" 2>&1
	irc=$?
	set -e
	sed 's/^/e3: nft: /' "$variant.out"
	say "nft -f with the oif spelling exited $irc (non-zero: Interface does not exist)"
	say "the ruleset is unchanged; the ceiling installed above is still the only table:"
	nft list tables
} 2>&1 | tee "$OUT/phase-0-before-the-link.txt"

# ---- the network, as init.tdx brings it up -------------------------------
ip link set lo up
ip link add "$IFACE" type dummy
ip link set "$IFACE" up
ip link set "$IFACE" mtu "$MTU"
ip addr add "$ADDR/$PREFIX" dev "$IFACE"
ip route add "$GW" dev "$IFACE"
ip route add default via "$GW"
say "link $IFACE up: $ADDR/$PREFIX mtu $MTU, gateway $GW"
ip -o addr show | sed 's/^/e3: addr: /'
ip route show | sed 's/^/e3: route: /'

# The probe targets. The three defaults are compiled into tunneld
# (defaultEgressProbes): tcp/169.254.169.254:80, tcp/8.8.8.8:53, udp/8.8.8.8:53.
# These are the extras:
#
#   the gateway, on two protocols, as ticket 19 probed it — one hop away and
#   genuinely reachable had the rule not been there;
#   the metadata server on the TUNNEL port, which is the one probe ticket 19
#   had no reason to make and this ceiling does: the grant is "udp/4433 to any
#   address", and 169.254.169.254 is an address.
PROBES="udp:$GW:53,tcp:$GW:80,udp:169.254.169.254:$PORT,udp:169.254.169.254:53"

# The controls. A pair with one bit of difference, so that no other explanation
# fits, plus the two that say what "any address" means and where it stops.
CONTROLS="udp:$PEER:$PORT udp:$PEER:4434 udp:8.8.8.8:$PORT udp:169.254.169.254:$PORT"

run_phase() { # TAG NAME
	tag=$1
	say "================ $2 ================"

	say "the rule set the kernel holds, in nft's own words:"
	nft list ruleset | tee "$OUT/ruleset-$tag.txt"

	say "the ticket 19 egress probe, unmodified, against a ceiling it never saw:"
	set +e
	"$BIN/tunneld" -config "$CFG" -author "$CFG/author.pub" \
		-egress probe -egress-probe "$PROBES"
	rc=$?
	set -e
	say "tunneld -egress probe exited $rc (0 means every attempt was refused)"

	say "the positive control: the same address on the tunnel port and beside it"
	set +e
	"$BIN/control" $CONTROLS
	crc=$?
	set -e
	say "control exited $crc (0 means every attempt was classified ALLOWED or REFUSED)"
}

# ---- phase A: the constant as text, installed by the shell ---------------
run_phase a "PHASE A: ceiling.nft, installed by nft -f before the link existed" 2>&1 \
	| tee "$OUT/phase-a-nft.txt"

# ---- phase B: the same constant through the Go renderer -----------------
say "installing the same ceiling through the github.com/google/nftables path"
"$BIN/ceilinginstall" 2>&1 | tee "$OUT/phase-b-install.txt"
run_phase b "PHASE B: the same ceiling, installed by the Go renderer" 2>&1 \
	| tee "$OUT/phase-b-go.txt"

# The two installers agree, or the spike is not evidence of anything.
{
	say "================ the two installers, compared ================"
	say "diff of what the kernel held after nft -f and after the Go renderer:"
	if diff -u "$OUT/ruleset-a.txt" "$OUT/ruleset-b.txt"; then
		say "IDENTICAL: the constant text and the Go renderer install the same rule set"
	else
		say "THEY DIFFER; see above"
	fi
} 2>&1 | tee "$OUT/installers-agree.txt"

say "done"
