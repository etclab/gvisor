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
