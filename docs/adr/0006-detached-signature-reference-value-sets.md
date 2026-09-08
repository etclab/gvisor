# A reference value set is a plain document with a detached signature over its exact bytes

The signed set is two files: a JSON document a reference value author writes and a reviewer
reads, and an Ed25519 signature beside it. The signature covers a fixed domain separation
prefix followed by the document's **exact bytes as delivered**. Nothing is canonicalised,
nothing is re-serialised and then checked, and the loader verifies before it parses — a
substituted document never reaches the JSON parser at all.

ADR-0004 established that the set is signed and that only the author's public key lives inside
the launch measurement. This is the shape that decision takes on disk, and it is frozen into
the measured image: changing it is a flag day in the same family as rotating the author key.

## Considered Options

**An envelope whose payload is an opaque blob**, parsed only after the blob's signature
verifies, is equally sound — it gives the same unambiguous signed region and closes the same
trap. It was rejected on reviewability alone. The entire reason this file exists outside the
measurement in a form a human writes is that the trust root should be auditable by eye, and a
base64 payload cannot be read or reviewed. Nothing is gained by hiding the trust root from the
person whose job is to audit it.

**Signing the parsed structure**, or re-serialising before verifying, is the failure both
shapes exist to prevent, and it is the one worth naming: a verifier that checks a signature
against a re-encoding accepts whatever its own encoder produces, rejects whatever anyone
else's does, and silently stops enforcing every field its parser dropped. The API forecloses
it rather than warning about it — both the signer and the loader take the document as bytes,
and there is no path from a parsed set back to a signature check.

**Algorithm agility** was rejected. There is no `alg` field in either file: a signature scheme
named by the document lets an attacker choose the scheme the verifier applies, which is the
oldest mistake in signed-document formats. The loader knows one scheme, and the scheme is
bound into the signature by the domain separation prefix rather than declared anywhere a
document can reach.

**A bare signature over the document**, without the prefix, was rejected because the reference
value author's key is this system's trust root and may one day sign something else. Without
domain separation, a signature it produces over any other artefact of the same bytes is also a
valid reference value set.

Ed25519 rather than any parameterised scheme, because it is the key type tunneld already uses
and offers no curve, hash or padding choice for two implementations to disagree about.

## Consequences

A set is two files rather than one, and both must be delivered. A document with no signature
beside it is refused, not loaded — and refused indistinguishably from one whose signature does
not hold, because a caller that can tell "there is no set here" from "the set here does not
verify" is a caller that can be tempted to treat the first as permission to proceed. Every
failure matches one sentinel and none matches the filesystem's not-found error, so that branch
cannot be written rather than merely being discouraged.

Changing the envelope, the prefix or the signature algorithm requires a new loader and
therefore a new measurement. That is a flag day, and it is the same one ADR-0004 already
accepts as the single remaining cascade; there is now a second way to trigger it.

Because there is no canonical form, an author must sign the bytes they intend to ship and ship
the bytes they signed. Rendering a set twice and signing one rendering to check the other does
not work and is not meant to.

## Addendum: format version 2, one vendor per value (ticket 17)

Version 1 of the document could name an SEV-SNP launch digest and nothing else. Intel TDX
admits a peer on a different shape of evidence — several registers, of which one is predicted
from the image and three are constants observed on the provider's hardware — so a second
vendor could not be expressed in it at all. That is the cost `docs/tdx-as-a-second-vendor.md`
priced under *`ReferenceValue.LaunchMeasurement []byte` — cannot express TDX evidence*: the
problem was never the digest's width, which this format already refused to check, but its
**arity and selectivity**. Version 2 is that price paid.

**What version 2 adds.** Every reference value carries a required `"vendor"`, `"amd-sev-snp"`
or `"intel-tdx"`. An `amd-sev-snp` value holds exactly what version 1 held —
`launch_measurement`, a four-component `minimum_tcb`, `guest_policy` — under exactly the old
rules. An `intel-tdx` value holds `observed_mrtd`, `observed_rtmr0` and `observed_rtmr1`, each
a non-empty list of which a peer must match one; `predicted_rtmr2`; an optional
`td_attributes_policy`; and a `minimum_tcb` that is Intel's shape, a `status` and a
`tcb_evaluation_data_number`, both required. One file holds values of both vendors, because a
peer group can span hardware and a format that carried the vendor once at the top would make
the mixed group the special case. A value carrying the other vendor's field is refused rather
than ignored, for the same reason an unknown field is: its author was writing down a
constraint this value cannot enforce, and enforcing the half that parsed would admit more than
they wrote.

**Why version 1 is refused rather than read as SEV-SNP.** Reading it as SEV-SNP would be
right about every version 1 document that exists, and is still wrong: it is the loader
deciding what an author did not write down. This file is the design's trust root and the one
place where nothing may be inferred — the same argument ADR-0002 makes about an unrecognised
binding context, and the same argument that refuses an unknown field and a repeated one. The
refusal says so in words and names the fix, because a set that will not load is a guest that
will not boot and the operator reading the log needs to know to re-emit and re-sign. The
signature is no help here either: a version 1 document is perfectly signed by its author, and
what it lacks is not integrity but a statement of what it means.

**Consequence.** Every set recorded under `docs/snp` is version 1 and this loader now refuses
it. The recorded evidence is not regenerated — it is the record of runs on real hardware
(tickets 05, 07, 08) and each run's author key was thrown away with it — so the tests that
replay those runs re-author the recorded values in-process, tagging them with the vendor the
run was on and signing them with a key the test generates. What that preserves is the
measurement, the floor and the policy, predicted and written down before the guest booted; the
original signature having held is what the recorded run itself records. Deployments re-emit:
`docs/snp/image/emit-refvals` for SEV-SNP and `docs/snp/cloud/tdx/emit-tdx-refvals` for TDX
both write version 2.

The version number is the document's own and is separate from the signature scheme's, which is
still v1 in the domain separation prefix: a document that gains a field does not change how it
is signed, and no key rotates. What does change is the loader, and the loader is inside the
launch measurement — so version 2 is a new measurement and therefore the same flag day this
ADR already accepts, spent on the format rather than on the key.
