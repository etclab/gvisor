# Intel collateral is provisioned onto the config device, and expires on a calendar

Verifying a TDX quote needs three documents the quote does not carry: Intel's TCB info for the
platform's FMSPC, the quoting enclave's identity, and the revocation lists for the PCK chain.
Intel signs and dates them and serves them from its provisioning service, and Intel's terms of
use prohibit fetching them at verification time — caching is mandatory, not an optimisation. They
are therefore fetched once, ahead of use, and delivered on the same read-only block device that
carries the reference value set and the AMD chain, in a directory whose file names are fixed by
the FMSPC and certificate authority they answer for. The verifier hands the library a getter that
serves those files and refuses every other URL, so a fetch reintroduced by accident fails loudly
rather than silently reinstating a dependency on Intel on the critical path of every tunnel.

This keeps ADR-0005's spirit — do not call the vendor while establishing a channel — for a vendor
whose distribution model is the opposite of AMD's. There is no per-chip chain to provision: the PCK
chain travels inside the quote. What has to be provisioned is the material that says whether that
chain, and the platform it names, are still good.

## Consequences

**The failure mode inverts.** An AMD chain goes stale when *the platform's* TCB moves, and the
design detects that by comparing the chain's TCB to the report's; the stale side is the peer's,
and the refusal appears at everyone else. Intel's collateral goes stale on *the verifier's*
calendar — Intel dates each document with a `nextUpdate` about a month out — independently of any
platform. A verifier whose collateral has passed that date refuses every TDX peer, including
perfectly healthy ones, and refuses them locally. That is the right direction for the failure to
point. It does not get a reason of its own: the SEV-SNP verifier already reports an AMD certificate
that is not valid at the verifier's clock as `ReasonChainNotRooted`, and collateral past its date
is the same fact — the chain cannot be judged rooted *now* — so the reason is reused and the
refusal's detail carries what is different: that the peer forged nothing, that the verifier's own
provisioning has lapsed, and that the fix is re-provisioning on the verifier's side, naming this
record. Re-provisioning is therefore a monthly operational task, in the same family as reference
value rollout, and a tunneld whose collateral is missing or expired fails closed rather than
fetching.

**A TCB recovery obsoletes collateral silently.** When Intel raises the bar for a platform family
it publishes a new TCB info with a higher `tcbEvaluationDataNumber`; the old one still verifies,
is still within its dates, and still calls a since-vulnerable platform up to date. No local
comparison can see this, and the config device is supplied by the untrusted host, so a host can
provision last month's collateral on purpose. The defence is in the trust root: a TDX reference
value carries the lowest evaluation number its author will accept, and a verifier holding older
collateral refuses with `ReasonTCBBelowFloor`. Raising that floor is the reference value author's
job on every recovery, which is the TDX counterpart of raising an AMD TCB floor.

**Provisioning is the only network access, and it is not the verifier's.** The one fetch for the
recorded platform is transcribed in `docs/snp/evidence/tdx/collateral/FETCH.txt`; the packaged
binary links nothing that can perform it.
