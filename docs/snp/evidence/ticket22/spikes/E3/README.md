# E3 — the ceiling as a constant

**Question.** Today the measured guest's init asks tunneld to generate a
default-drop netfilter table from the signed `policy.json` on the config device
and install it (`docs/snp/cloud/tdx/init.tdx` step 5,
`attest/cmd/tunneld/egress.go`). Ticket 22 moves that ceiling out of the policy
and into the measured image as a constant. E3 asks two things: what does the
constant have to contain, and what does `egress.go` shrink to?

**Method.** A workstation user + network namespace (`unshare -rn`, no sudo, no
privileged helper), one dummy interface named and addressed exactly as ticket
19's guests were, the ceiling installed from a hardcoded rule set, and then the
**real, unmodified** ticket 19 egress probe — `tunneld -egress probe`, the same
binary built from `attest/` — run against it.

**Verdict.** Every probe was refused, the metadata address included, under both
installers. The ceiling needs two compiled-in values and nothing else. Nine of
`egress.go`'s twenty-nine declarations die; the probe half and the whole
read-back-and-render half survive, `readInstalledRuleSet`, `renderExprs` and
`cmpValue` among them.

---

## 1. Result

`tunneld -egress probe`, unmodified, against a ceiling it has never heard of
(`out/phase-a-nft.txt`, identical in `out/phase-b-go.txt`):

```
tunneld: EGRESS PROBE: 7 attempt(s) at addresses this policy permits nothing to reach
tunneld: EGRESS REFUSED tcp/169.254.169.254:80: dial tcp 169.254.169.254:80: connect: connection refused (the provider's metadata server) — the netfilter rule refused it
tunneld: EGRESS REFUSED tcp/8.8.8.8:53: dial tcp 8.8.8.8:53: connect: connection refused (a public resolver, over TCP) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/8.8.8.8:53: write udp 10.128.0.40:38968->8.8.8.8:53: write: operation not permitted (a public resolver, over UDP) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/10.128.0.1:53: write udp 10.128.0.40:47005->10.128.0.1:53: write: operation not permitted (named by -egress-probe) — the netfilter rule refused it
tunneld: EGRESS REFUSED tcp/10.128.0.1:80: dial tcp 10.128.0.1:80: connect: connection refused (named by -egress-probe) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/169.254.169.254:4433: write udp 10.128.0.40:36974->169.254.169.254:4433: write: operation not permitted (named by -egress-probe) — the netfilter rule refused it
tunneld: EGRESS REFUSED udp/169.254.169.254:53: write udp 10.128.0.40:60828->169.254.169.254:53: write: operation not permitted (named by -egress-probe) — the netfilter rule refused it
tunneld: EGRESS PROBE PASSED: every attempt was refused before it left
```

Seven for seven REFUSED — not UNROUTED, not TIMEOUT. `udp/169.254.169.254:4433`
is a probe ticket 19 had no reason to make and this ceiling does: the tunnel-port
grant is "to any address", and the metadata server is an address. It is refused
by the carve-out.

The positive control, so that "everything is refused" is not simply "the
namespace has no network":

```
CONTROL ALLOWED  udp/10.128.0.41:4433: write of 15 bytes returned no error; the output hook did not refuse it
CONTROL REFUSED  udp/10.128.0.41:4434: write: write udp 10.128.0.40:59966->10.128.0.41:4434: write: operation not permitted
CONTROL ALLOWED  udp/8.8.8.8:4433: write of 15 bytes returned no error; the output hook did not refuse it
CONTROL REFUSED  udp/169.254.169.254:4433: write: write udp 10.128.0.40:60263->169.254.169.254:4433: write: operation not permitted
```

The first pair is the same address one port apart: 4433 leaves, 4434 is EPERM.
No routing, MTU or device explanation fits a difference of one port. The third
line is what "any address" means — 8.8.8.8 on the tunnel port leaves, and the
attestation layer, not the ceiling, is what stops the guest talking to it. The
fourth is where "any address" stops.

`tunneld -egress probe` exited 0 and the control exited 0 in both phases.

---

## 2. (a) What the constant must contain

The canonical text is [`ceiling.nft`](ceiling.nft). Its rule set, stripped of
commentary:

```nft
flush ruleset

table inet attested_tunnel {
	chain input {
		type filter hook input priority 0; policy drop;
		iifname "lo" accept
		meta nfproto ipv4 iifname "eth0" meta l4proto udp udp sport 4433 accept
		meta nfproto ipv4 iifname "eth0" meta l4proto udp udp dport 4433 accept
	}
	chain output {
		type filter hook output priority 0; policy drop;
		oifname "lo" accept
		meta l4proto tcp reject with tcp reset
		meta nfproto ipv4 ip daddr 169.254.0.0/16 reject with icmpx admin-prohibited
		meta nfproto ipv4 oifname "eth0" meta l4proto udp udp dport 4433 accept
		meta nfproto ipv4 oifname "eth0" meta l4proto udp udp sport 4433 accept
		reject with icmpx admin-prohibited
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
}
```

**SHA-256 of `ceiling.nft`, the name the ticket prints at boot:**

```
197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973  ceiling.nft
```

(`out/ceiling.nft.sha256`. Recompute with `sha256sum ceiling.nft` from this
directory; the hash covers the commentary too, deliberately — the commentary is
the justification and a silent edit to it should show.)

### The assumptions, named

| value | what it is | where it comes from |
|---|---|---|
| `eth0` | the VPC link | **image constant.** The measured initrd loads `gve` and runs no udev, so the kernel's own name stands. Ticket 19 captured `initrd: link eth0 up:` on all six scenario guests and the smoke guest — `grep -rh "initrd: link .* up:" docs/snp/evidence/ticket19/` returns `eth0`, fifteen times, nothing else. |
| `4433` | the tunnel's UDP port | **image constant.** Today it is read from `tunneld.json`'s `listen` on the config device. |
| `169.254.0.0/16` | the metadata block | **image constant**, universal across providers. |
| `attested_tunnel` | the table name | unchanged from today. |

**The interface name is an image constant, not a boot-time discovery.** A name
discovered at boot is a name something outside the measurement chose, and the
point of this file is that nothing outside the measurement chooses anything in
it. It also fails closed: a rule naming an interface that never appears grants
nothing, so the worst a wrong constant can do is leave the guest unable to reach
its peer — loudly, at the first dial — rather than able to reach anything else.
`init.tdx`'s present fallback ("network.conf named no interface; using $NET_IF,
the only one that is not loopback") must **not** be carried into the ceiling: it
would let the set of attached NICs decide which link is permitted.

**What varies per image build:** those two values, and only those two. Changing
either makes a different image with a different RTMR2 / launch digest, which is
exactly the property wanted — a verifier can tell a guest built for `eth0`/4433
from one built for anything else, and the reference value set names which.

### Consequences the ticket has to absorb

1. **The port becomes an image constant, so `tunneld.json` may only agree with
   it.** A `listen` naming any other port must be refused at load, in the
   measured binary. Otherwise the guest comes up with a listener whose traffic
   the ceiling silently drops, which looks like a network fault and is a
   configuration error. (`loadRunConfig` already has the right shape for this —
   it is where `max_age` is clamped for exactly the same reason: "the ceiling
   lives in the measured binary, where the host cannot reach it".)

2. **The ceiling goes in before the link, and the window closes to zero.**
   `init.tdx` installs its rule set at step 5, after mounting the config device
   (3) and configuring the network (4). It had to: the rules named peer
   addresses that were on that device. A constant has no such dependency, so the
   install moves to immediately after the `nf_tables` module load at step 2 —
   before the config device is even looked for. E3 installed the ceiling into a
   namespace with no `eth0` and `lo` still down to prove this works
   (`out/phase-0-before-the-link.txt`).

3. **`iifname`, not `iif` — they are different rules.** `iif` resolves the name
   to an interface index when the rule is *loaded*; `iifname` compares the name
   when a *packet arrives*. E3 tried the index form against a namespace with no
   `eth0`:

   ```
   e3: nft: .../e3-iif-variant.nft:4:5-10: Error: Interface does not exist
   e3: nft:     oif "eth0" accept
   e3: nft:         ^^^^^^
   e3: nft -f with the oif spelling exited 1
   ```

   which is fatal to (2). The name form loads against an empty namespace and
   starts refusing at once. This also exposes a rendering bug in today's
   `egress.go`: `ifaceRule` builds the rule with `expr.MetaKeyIIFNAME`, so the
   kernel has always held `iifname`, but the `text` rendered beside it and
   `renderExprs`' read-back both say `iif`. Ticket 19's evidence files therefore
   describe a rule the guest did not install. Harmless in effect, wrong in the
   record; fix it in the shrink.

4. **Refusal order is load bearing.** The ceiling permits no TCP at all, so the
   TCP reset is hoisted to the top of the output chain, above the link-local
   carve-out and above the tunnel-port grant. It changes nothing about what is
   permitted (every accept below is UDP-only) and it changes what a refusal
   looks like at the socket. E3 first placed the carve-out first and got:

   ```
   tunneld: EGRESS UNROUTED tcp/169.254.169.254:80: dial tcp 169.254.169.254:80: connect: no route to host (the provider's metadata server) — no route, so the rule was never reached; this does not demonstrate the policy
   ```

   The ICMP administratively-prohibited reaches a TCP socket in SYN_SENT as
   EHOSTUNREACH, which the probe classifies — correctly — as UNROUTED. A true
   classification of a misleading refusal. Hoisted, the same attempt gets a
   reset, ECONNREFUSED, REFUSED.

5. **No DHCP, no DNS, no NTP, no ICMP, no IPv6.** Nothing is needed before
   tunneld: `init.tdx` addresses the link statically and says why ("a guest that
   learned its address from the network would be a guest whose address the
   network chose"). Every accept tests `meta nfproto ipv4` first, so IPv6 —
   which the guest does acquire a link-local address for — falls through to the
   chains' drop policy, as it already does today. ARP is unaffected: it is the
   `arp` family, not `inet`.

6. **The tunnel port is granted to any destination on the link, not to listed
   peers.** This is the ticket's own framing and E3 agrees with it. The peer
   addresses live in `peers.json` on the config device; a ceiling that read them
   would be a ceiling the config device could widen, which is the whole thing
   this ticket removes. The two mechanisms stay disjoint, as ticket 19's egress
   README already argued: the ceiling bounds what the guest can reach *at all*,
   and the per-verifier allow-list in `reference-values.json` — plus tunneld's
   own peer table, which refuses an unknown name before a socket is opened
   (`ErrUnknownPeer`) — decides *whom it will speak to*. The cost is stated
   plainly: under the ceiling alone a compromised guest could send UDP/4433 to
   any address on the VPC. It cannot establish anything there without evidence
   the allow-list admits, and it cannot reach the metadata server at all.

7. **Two artefacts must not drift.** E3 carries the constant twice — as
   `ceiling.nft` and as Go in `spike/ceilinginstall` — and proved them equal at
   the only level that matters, what the kernel ends up holding
   (`out/installers-agree.txt`: `diff -u` of `nft list ruleset` after each,
   IDENTICAL). The image has no `nft` binary and adding one would add a measured
   binary for nothing, so the Go form should be the installer. Recommendation
   for the ticket: keep the Go constant as the source of truth, generate
   `ceiling.nft` from `tunneld -egress print`, check it in, print its SHA-256 at
   boot, and add a guard test asserting the two still match.

---

## 3. (b) What `egress.go` shrinks to

`attest/cmd/tunneld/egress.go`, 788 lines today. Line numbers are at
`e787af26e`.

| lines | declaration | after the shrink |
|---|---|---|
| 85–98 | `egressTableName`, `egressChain{Input,Output,Forward}` | **kept**, unchanged |
| 102–106 | `egressMode{Print,Install,Probe}` | **kept**; the modes stay, their inputs go |
| 112–115 | `type egressRule` | **kept**, unchanged |
| 119–124 | `type egressChain` | **kept**, unchanged |
| 128–136 | `type egressRuleSet` | **shrinks**: `SandboxID`, `ListenPort` and `Peers` go; only `chains` is left |
| 139–143 | `type egressPeer` | **dead** — policy-driven rendering only |
| 151–248 | `buildEgressRuleSet(policy, peers, listen)` | **dead** — replaced by `buildCeiling()`, which takes nothing and cannot fail |
| 252–263 | `ifaceRule` | **kept**; its `text` fixed to say `iifname`/`oifname` |
| 267–275 | `type peerRuleSpec` | **dead** |
| 283–301 | `peerRule` | **dead** — replaced by `portRule`, the same shape with the address test removed and an interface test put in |
| 304–317 | `portOf` | **dead** — its only caller read the listen port off the config device |
| 325–336 | `Render` | **kept**, unchanged |
| 338–343 | `policyWord` | **kept**, unchanged |
| 352–379 | `Install` | **kept**, verbatim |
| **387–433** | **`readInstalledRuleSet`** | **kept, verbatim.** Survives intact. It reads the kernel's own bytes back, which is the capture the record keeps, and a constant needs that read-back more than a generated set did — it is the only thing that proves the image's constant is what the kernel is enforcing |
| 435–440 | `priorityOf` | **kept**, verbatim |
| 442–458 | `familyWord` | **kept**, verbatim |
| 460–477 | `hookWord` | **kept**, verbatim |
| **485–555** | **`renderExprs`** | **kept, with two changes.** (i) `MetaKeyIIFNAME`/`OIFNAME` must render as `iifname`/`oifname` — see §2(3). (ii) a new `case *expr.Bitwise:` — six lines. The ceiling's `169.254.0.0/16` is a prefix match, which in the kernel is a mask-and-compare; every rule the old generator emitted compared a whole address, so `renderExprs` has never seen a `Bitwise` and prints `*expr.Bitwise`, losing the mask and making the rule read as an exact match on the network address. **This is the only thing the shrink has to add.** |
| **559–592** | **`cmpValue`** | **kept, with one change**: a `mask []byte` parameter carried from the preceding `Bitwise`, so an address comparison prints `169.254.0.0/16` rather than pretending to be exact |
| 596–600 | `type egressProbe` | **kept**, unchanged |
| 606–612 | `defaultEgressProbes` | **kept**; E3 suggests adding `udp/169.254.169.254:4433` — the attempt the tunnel-port grant would otherwise permit |
| 616 | `egressProbeTimeout` | **kept** |
| 628–638 | `runEgressProbes` | **kept, verbatim** |
| 640–652 | `egressVerdictMeaning` | **kept, verbatim** |
| 655–680 | `attemptEgress` | **kept, verbatim** |
| 683–698 | `classifyEgressError` | **kept, verbatim** |
| 707–761 | `runEgressMode` | **shrinks by half**: the `LoadPolicyFile` call, the two `logf` lines about the policy, and the `buildEgressRuleSet` call go. Signature drops `configDir`, `cfg`, `peers` and `author` — `runEgressMode(mode, extra string, logf, out) int` |
| 768–788 | `parseEgressProbes` | **kept, verbatim** |

**Summary: 9 of 29 declarations die** (`egressPeer`, `buildEgressRuleSet`,
`peerRuleSpec`, `peerRule`, `portOf`, plus the three fields of `egressRuleSet`
and the policy-loading half of `runEgressMode`). Roughly 215 lines out and 80
in, so the file lands near 650. `readInstalledRuleSet`, `renderExprs` and
`cmpValue` all survive, and are the reason the constant can still be read back
out of the kernel and printed on the console.

### What follows outside `egress.go`

- **Imports.** `crypto/ed25519`, `path/filepath` and — notably —
  `gvisor.dev/gvisor/attest` all lose their last user. After the shrink
  `egress.go` does not depend on the attest package at all. `sort`, `strconv`,
  `net`, `strings`, `errors`, `fmt`, `io`, `syscall`, `time`,
  `encoding/binary`, `nftables`, `expr` and `unix` all stay.

- **`main.go:209`.** The `-egress` branch currently sits after
  `loadRunConfig`, `loadPeerTable` and `readAuthorKey`. Once `runEgressMode`
  needs none of them it moves **above** all three, which is what lets init run
  `tunneld -egress install` before a config device has been found — §2(2). It
  also means `-egress install` no longer needs `-config` at all.

- **`egress_test.go`.** Four of six tests are about the policy-driven
  rendering and die with it:
  `TestEgressRuleSetRendersWhatThePolicyImplies` (35),
  `TestEgressRuleSetWithNoPeersPermitsOnlyLoopback` (87),
  `TestEgressRuleSetRefusesAPolicyPermittingUnattestedEgress` (109),
  `TestEgressRuleSetRefusesANamedPeer` (120), plus the `closedPolicy` helper
  (28). `TestParseEgressProbes` (134) is untouched.
  `TestEgressRuleSetInstalls` (158) survives and gets easier — it builds a
  constant instead of a policy — and it is the natural home for the new
  assertion that `readInstalledRuleSet` renders the ceiling's `/16` correctly.
  New tests worth having: the constant renders to exactly the checked-in
  `ceiling.nft`, and `loadRunConfig` refuses a `listen` port that is not the
  ceiling's.

- **The header comment, lines 38–84**, argues at length that the rule set lives
  in tunneld because "a document is only worth generating rules from if the
  generator checked the author's signature over it first". That argument
  disappears with the generation. What replaces it is shorter and stronger: the
  rule set is a constant in the measured image, so there is no document to
  check.

---

## 4. Files

```
E3/
  README.md                       this
  ceiling.nft                     the constant. SHA-256 197d4aae…b973
  run-e3.sh                       the whole experiment, one command, no sudo
  netns-inner.sh                  what runs inside the namespace
  spike/                          a NESTED Go module, so the gvisor root module
    go.mod  go.sum                never builds or vets anything under docs/
    mkconfig/main.go              the minimum config device tunneld's probe
                                  needs to get past its signature check
    ceilinginstall/main.go        the ceiling through the same nftables path
                                  egress.go uses; the surviving half of
                                  egress.go, copied, as a demonstration
    control/main.go               the positive control: stops at the write,
                                  where the output hook has already spoken
  out/
    run-e3-console.txt            the whole run
    ceiling.nft.sha256            the constant's name
    phase-0-before-the-link.txt   the ceiling installed with no eth0 and lo
                                  down, plus the `oif` spelling failing
    phase-a-nft.txt               nft -f: ruleset, 7 probes, 4 controls
    phase-b-install.txt           the Go renderer's render and read-back
    phase-b-go.txt                Go path: ruleset, 7 probes, 4 controls
    ruleset-a.txt, ruleset-b.txt  `nft list ruleset` after each installer
    installers-agree.txt          diff of those two: IDENTICAL
```

## 5. Rerunning

```sh
export PATH="/usr/local/go/bin:$PATH"
docs/snp/evidence/ticket22/spikes/E3/run-e3.sh
```

No sudo, and none was used. `unshare -rn` maps the invoking user to root in a
new user namespace and gives it a new network namespace; nf_tables honours that
namespace's own capabilities, so `nft`, netlink and the dummy interface all work
and the workstation's real network and real ruleset are untouched and out of
reach. Requirements: the `nf_tables` module loaded on the host (`lsmod | grep
nf_tables`), `nft`, `ip`, and Go at `/usr/local/go/bin`. The Go module cache must
already hold `github.com/google/nftables v0.3.0` and its dependencies — it does,
because `attest/` depends on them — since the spike builds with `GOPROXY=off`.

Individual pieces:

```sh
# the constant, rendered from Go without touching the kernel
cd docs/snp/evidence/ticket22/spikes/E3/spike && GOPROXY=off go run ./ceilinginstall -print-only

# the constant's name
cd docs/snp/evidence/ticket22/spikes/E3 && sha256sum ceiling.nft

# the ceiling alone, in a throwaway namespace
unshare -rn sh -c 'nft -f docs/snp/evidence/ticket22/spikes/E3/ceiling.nft && nft list ruleset'
```
