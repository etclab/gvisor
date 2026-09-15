# The policy is pushed over the tunnel, and the egress ceiling is compiled into the measured image

Status: accepted.

A sandbox's policy leaves the config device. It is no longer a signed document the host
delivers on a disk beside the reference value set; it is opaque bytes pushed to a peer over the
tunnel after that peer's evidence has been judged, per delegation, and acknowledged by the
receiver before the delegator's `Open` returns a stream. Nothing signs it and nothing measures
it: once a peer's enforcement stack has been attested, what that stack is told to enforce is
trusted to be honoured, because the instruction arrived over a channel that exists only between
admitted platforms and came from a delegator admitted the same way. What a policy could
previously *loosen* is compiled in instead — package `attest/ceiling` holds the egress ceiling
as a constant: interface `eth0`, UDP port 4433, default-drop, installed by init before the link
is up and before a config device is looked for, its text inside the launch measurement and
SHA-256 over that text (`197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973`)
printed at boot and by `attest-tool ceiling -digest`. The config device shrinks to what cannot
arrive over a tunnel that does not exist yet: reference values, the network bootstrap
(`tunneld.json`, `peers.json`) and the verification collateral of ADR-0005 and ADR-0007.

The trust the push rests on is conditional, and the condition is the ceiling. "This peer's
enforcement stack is attested, so its pushed policy will be honoured" holds only while no
unmeasured input can widen what that stack permits. A policy read off the config device is
exactly such an input: the device is outside the launch measurement, so a verifier who has read
the image cannot say what the guest will enforce, and until ticket 22 the guest could not
install anything at all until it had found, mounted and read that disk — a window between *this
guest is running* and *this guest is constrained* whose length was however long finding a disk
takes. With the ceiling compiled in, the strongest thing a pushed policy can do is narrow, the
window is zero, and a verifier reading the image knows the rule set the guest came up with
(`docs/snp/evidence/ticket22/spikes/E3/`). That is what makes an unsigned push safe, and it is
the whole of why the two halves of this record are one decision rather than two.

The signed-policy construction is abandoned rather than merely bypassed, and tickets 18 and 19
are why. Ticket 18 made a sandbox's policy its own signed reference value set and bound that
set's digest into the evidence; its live run showed the shape cannot stand, because an
allow-list entry names a peer's policy digest, so two peers pinning each other would need A's
set to contain the digest of B's set while B's contained the digest of A's — each digest taken
over a document that would then already have to contain it. Nobody can author that pair.
Constrained admission was one-directional, and the only fully constrained pair admitted nothing
in either direction. Ticket 19 split the policy into its own document to break the cycle, and
that worked: the policy named no digests, so the two digests in a pair were fixed independently
and mutual pinning became ordinary. What it did not fix is the loosening: the document still
came off a disk the host supplies, still generated the netfilter rule set, and still gated
every dial through `forward_to`. Two tickets of construction bought a signature over a document
whose only enforcement job a constant does better, and E4 established that the load was the
single blocking call — a config device carrying no `policy.json` fails at exactly one site, and
the absence deliberately does not wrap `fs.ErrNotExist`, so the behaviour cannot be obtained by
catching it (`docs/snp/evidence/ticket22/spikes/E4/`).

Tunneld is the network boundary and is agnostic about what sits beside it. The contract is
three verbs wide — open a stream to a named peer, accept one with the peer's attested identity
on it, receive a pushed policy and acknowledge it — and a sandbox sees no evidence, no key and
no trust decision (`docs/sandbox-contract.md`). Which sandbox that is follows from the agent
runtime needed, and a different sandbox is only a different measured image; it is not a
different security argument, because nothing above the contract is told which one is there.

Whom a sandbox may talk to and what it may do are now separate mechanisms, and deliberately
disjoint. Whom is the per-verifier allow-list in the signed reference value set, checked at
admission, plus tunneld's own peer table, which refuses a name it does not hold before a socket
is opened. What is the pushed policy, decided after admission by a delegator that has already
been judged. The ceiling sits under both and bounds what the guest can reach at all. The cost
of that disjointness is stated plainly: under the ceiling alone a compromised guest can send
UDP/4433 to any address on the link, establish nothing there without evidence the allow-list
admits, and reach the metadata block not at all.

The binding context stays at version 2 and the digest slot keeps its width, position and
meaning as a check; what changed is what a well-behaved guest puts in it. The slot carries the
ceiling's digest, so an allow-list `policy_digest` entry still says something and says
something narrower than it did — *this enforcer version, this ceiling* — and every format
ticket 18 and ticket 19 shipped stays valid. A version number records a format a verifier must
parse differently, and no byte moved, so bumping to 3 would have made every recorded bundle
unverifiable for no reason a reader could point at in the bytes. The digest is no longer
load-bearing for delegation: both sides of a pair booted from one image present the same
number, so it cannot distinguish them and is not asked to.

The pushed bytes are provisional and opaque: versioned JSON,
`{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}`. Tunneld reads the format and the
version and nothing else, at the boundary and before the sandbox is woken, so an
acknowledgement means a sandbox holds *that* policy on every implementation of the contract;
the null sandbox records the push and acks it, and no line of code in this tree reads `n`, `f`
or `x`. `forward_to` is dropped as a decision — the dialing side asks nothing of a document any
more — while the field and the document format are kept so that every policy tickets 18 and 19
recorded still loads and still hashes to the digest those records name. A push that is refused,
that carries an unknown version, or that is never acknowledged is a new refusal reason,
`PolicyNotApplied`, and it closes the tunnel: a delegation whose terms did not arrive is not a
delegation that proceeds on the older terms.

## Considered Options

**Keep the signed policy on the config device, as ticket 19 left it.** It is the option with
two tickets of working code behind it, and it fails on the argument above: a document outside
the measurement that decides what is enforced is a document the host can use to widen
enforcement, and no signature fixes that — the host does not need to forge one, only to deliver
a differently signed document its author wrote for some other deployment, or a stale one. E4's
C2 capture is what that looks like today: ticket 19's policy loads, its digest becomes the
sandbox's identity, its `egress` section becomes the kernel's rule set, and the console line
says "loaded under the author key", which is true and says nothing about the document being
from a previous world.

**Measure the policy into the image instead.** This closes the same hole and reintroduces the
cascade ADR-0004 exists to prevent: one image per policy, and a policy change that forces every
peer to update. Delegation is per-delegation and per-peer, so the cascade here would be worse
than the one ADR-0004 refused.

**Sign the pushed policy under the author key.** Rejected as a check that protects nothing left
over. The push's authority is already the strongest statement this design can make — a platform
whose hardware evidence chained to a vendor root and satisfied the verifier's own signed
reference values — and it is a stronger statement than *somebody holding the author key wrote
this down beforehand*. A signature would also make delegation require an authoring step ahead
of time, which is the thing a pushed contract exists to avoid. The signing and digest machinery
is kept in `attest/policyfile.go` rather than deleted, because the pushed document is the same
kind of document and may want it later.

**Let the ceiling read the config device for the interface name, the listen port or the peer
addresses.** Rejected in E3, which is where every one of those was tried. A name discovered at
boot is a name something outside the measurement chose; a ceiling that read `peers.json` would
be a ceiling the config device could widen, which is the whole of what this record removes; and
the index form of the interface rule (`iif`, not `iifname`) will not even load before the link
exists, which is fatal to installing the ceiling first. Only two values vary per image build,
and both are compiled in.

## Consequences

**Changing the ceiling moves two numbers at once, and both are in the reference value set.**
The ceiling's text is inside the launch measurement, so editing it — including editing its
commentary, which is inside the digest deliberately — produces a different image with a
different measurement *and* a different `policy_digest`. Every peer that admits such a guest
re-authors and re-signs its set with both. This is the cascade ADR-0004 named as the single
remaining flag day, and there is now a third way to trigger it, alongside rotating the author
key and changing the signed document format (ADR-0006).

**A different ceiling is a different image, and there is no way to have two.** Two deployments
that must enforce different egress bounds are two images with two measurements, which is the
property wanted rather than a defect: a verifier can tell a guest built for `eth0`/4433 from
one built for anything else. It does mean the ceiling is not a deployment knob, and an operator
who wants one has to change the image build and everyone's reference values.

**Two peers can no longer present different policy digests from one image.** Ticket 19's
scenario two authored exactly that — two guests whose sets named the same policy digest, one of
which mismatched — and it is not expressible after this ticket: one image, one ceiling, one
digest. That run stays as a record of what the code did then, in the same way the ticket 05 and
ticket 08 bundles already are, and its `config-src/` directories are records rather than
inputs.

**A config device that still carries the policy stops the guest by name.** Removing the load
alone would make such a device load silently, which is the worst outcome available, so either
`policy.json` or its orphaned signature is refused before the mode split, in a sentence that
names this ticket and tells the operator to rebuild the device. Every script that builds one
was updated; ticket 19's recorded devices are now refused, which is intended.

**Nothing enforces a pushed policy yet.** The mechanism is complete — pushed, checked at the
boundary, acknowledged before a stream is handed over, `PolicyNotApplied` if it is not — and
the sandbox on the far end records and acks. Until a sandbox does something with `n`, `f` and
`x`, the pushed policy is a statement delivered and acknowledged, not a control, and this
record should not be read as claiming otherwise. The ceiling is the control that exists today.

**Cross-references.** ADR-0002 is amended: the digest slot it reserved and ticket 18 spent now
names the ceiling rather than a signed document on the config device, and its status line says
so. ADR-0004 and ADR-0006 are unchanged and are what this decision leans on — the reference
value set is still signed, still the one trust root, still a plain document with a detached
signature over its exact bytes, and it is still what decides whom a guest admits. This ticket
removes the second signed document, not the first. ADR-0005 and ADR-0007 are unaffected: the
collateral they place on the config device is public, self-validating material that cannot
widen anything, which is exactly the test the policy failed.
