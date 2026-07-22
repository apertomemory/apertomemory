# ApertoMemory test vectors — format_version 2

These vectors are the **normative artefact** for `format_version` 2. An
implementation is conformant if it reproduces the byte strings in the
`expect` blocks *and* refuses every case marked `MUST-REJECT`.

Reproducing the bytes is not sufficient on its own. The three rejection
vectors exist because the previous version of this format was byte-compatible
with implementations that did not check anything: vectors 004, 005 and 006
each encode an attack that a naive reader will happily accept.

## The two bindings

Everything in v2 follows from two rules that v1 lacked.

**Envelope binding.** `external_aad = canonical CBOR [format_version, id, scope_id]`
is supplied to *both* the COSE_Sign1 and the COSE_Encrypt0. A storage server
that rewrites the cleartext envelope invalidates the AEAD tag, and a version
downgrade is detected for the same reason (vectors 005, 006).

**Author binding.** The payload's `author_key_id` MUST equal
`sha256(verifying public key)[:8]`. A signer cannot claim an identity it
cannot prove (vector 004). Trust is *derived* from which key verified —
never read from the payload.

## Custody records (payload key 20)

Re-sealing an object changes its signer, so a migrated object's signature
proves custody, not authorship. Objects carrying a custody record MUST NOT
open as `trust="self"`, whoever signed them:

| custody | field 4 (proven author) | trust | `authorship` | `author_key_id` |
|---|---|---|---|---|
| absent | — | `self` / `trusted` | `signed` | the verified signer |
| present | names an accepted key | `trusted` | `attested` | the proven author |
| present | absent | `unverified` | `unknown` | `null` |

Trust is evaluated at read time against the current keyring, never frozen
into the object: revoking a key downgrades the memories attributed to it.

## Legacy

`format_version` 1 objects carry neither binding. They MUST NOT be reported
as verified (vector 009); reading them requires an explicit opt-in and yields
`trust="unverified"`.

## Regenerating

`generate.py` produces this file from the Python reference implementation
0.2.0. The vectors, not the implementation, are what other implementations
are written against.
