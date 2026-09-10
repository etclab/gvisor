Ticket 19: what left the guests, and what did not.

The egress capture from all three scenario runs, in one place. Each file is the
rule set as the signed policy and the peer table imply it, the same rule set as
the kernel handed it back, and every attempt the guest then made at the egress
its policy forbids. Nothing here was edited; each file was cut out of the
guest's own serial console by docs/snp/cloud/tdx/run-tdx-scenario.sh and is
also present in full in the console beside it.

  scenario-one-guest-a.txt     the two guests that admitted each other
  scenario-one-guest-b.txt
  scenario-two-guest-a.txt     the pair that disagreed about a policy digest
  scenario-two-guest-b.txt
  scenario-three-guest-a.txt   the pair on two different images; guest A's peer
  scenario-three-guest-b.txt   table also names an address no guest has

Six guests, six rule sets, thirty attempts, thirty refusals, nothing permitted.

## The rule set

Both base chains default to drop and the forward chain is empty and stays that
way — the guest routes for nobody. The exceptions are the loopback interface,
which the kernel needs in order to deliver a rule's own refusal back to the
socket that tripped it, and four rules per peer: this sandbox dialing the peer's
listener and answering from its own, and the same two inbound. The output chain
then ends in two refusals rather than one, because the kernel turns them into an
answer at the socket by two different routes: a TCP reset, so that connect()
fails at once instead of retransmitting for a minute, and an ICMP
administratively-prohibited for everything else.

## What was attempted, and how it failed

Five attempts per guest, and the errno is the point. EACCES, EPERM or
ECONNREFUSED is a rule refusing; ENETUNREACH or EHOSTUNREACH would be the
routing table having nothing to say, which would mean the rule was never
reached and the capture proved nothing. All thirty were the former:

  tcp/169.254.169.254:80   the provider's metadata server, which is the one
                           address every cloud guest can reach and the first an
                           exfiltrating guest would reach for
                              connect: connection refused
  tcp/8.8.8.8:53           a public resolver, the shape of "anywhere"
                              connect: connection refused
  udp/8.8.8.8:53              write: operation not permitted
  udp/10.128.0.1:53        the guest's own VPC gateway, one hop away and
  tcp/10.128.0.1:80        genuinely reachable had the rule not been there
                              write: operation not permitted
                              connect: connection refused

and each guest ends with

  tunneld: EGRESS PROBE PASSED: every attempt was refused before it left

## In policy and out of policy, on the same guest, in the same minute

The contrast the ticket asks for is on guest A of scenario one. Its rule set
excepts exactly one address, 10.128.0.41 on udp/4433, and that address is the
peer it went on to attest and exchange with eleven times over eight minutes.
Everything else it tried in the same run — including 10.128.0.1, which is on
the same VPC one hop away — was refused by the rule before the packet left. The
difference between the two is not reachability. It is the rule.

## The address that is in the peer table and on no machine

Scenario three asks a further question: what does tunneld's own QUIC dialer do
with a peer the rules do NOT except? It turns out it cannot be asked, and why
not is worth writing down.

Guest A's peer table in scenario three names a third peer, `outsider` at
10.128.0.42:4433, which no instance has. The rule set that guest installed
excepts it anyway — `ip daddr 10.128.0.42 ... udp dport 4433 accept`, four rules
like every other peer — and the dial to it then failed like this:

  tunneld: exercise: pass=1 peer=outsider FAILED: after 11 attempt(s) over 1m0s:
    tunneld: tunnel not established: "outsider" at 10.128.0.42:4433:
    tunnel: dialing 10.128.0.42:4433: timeout: no recent network activity

A timeout, not a refusal: the packets left, and nothing answered.

That is a fact about where the rule set comes from, and it is the honest reading
of it. The rules are generated from the peer table and the listen port
(attest/cmd/tunneld/egress.go, buildEgressRuleSet), not from the policy — because
a policy's `forward_to` names measurements, and a measurement is not an address.
The policy cannot say which addresses may be reached, so the addresses have to
come from the peer table, and every address in the peer table is therefore
permitted by construction. A dial the netfilter rule refuses is one to an
address the peer table does not name, and tunneld's QUIC dialer never makes one:
it dials peers by name and a name it cannot resolve in the table is refused
before a socket is opened (`ErrUnknownPeer`).

So the two mechanisms are disjoint rather than redundant, and each covers what
the other cannot. The peer table decides which addresses the tunnel may be
carried to; the rule set stops everything else in the guest — a compromised
agent, a library phoning home, a resolver lookup — from reaching the network at
all. The thirty refusals above are that second mechanism working. What the
egress rules do not and cannot do is second-guess the peer table, and Milestone
4 will have to say what the policy should express once an agent runs inside and
the peer table is no longer the only thing that opens a socket.

## The guest brings loopback up first, and that is not a formality

With `lo` down, netfilter still builds the refusal but the kernel cannot deliver
it to the local socket, so every attempt times out instead and a transcript
reading "timed out" would not show that a rule refused anything — a black hole,
a missing route and a firewall all look like that. The initrd brings loopback up
before it touches the network for exactly this reason
(docs/snp/cloud/tdx/init.tdx), and the microsecond refusals above are what that
buys.
