# EMILIA interop — ApertoMemory source facts

This folder holds ApertoMemory's own independent copy of the source-fidelity
values used in the interoperability sets shared with the
[EMILIA Trusted Context Pack](https://github.com/emiliaprotocol/emilia-protocol).

Two interop sets are covered:

- `apertomemory-source-facts.v2.json` — the **trust-and-custody** set.
- `apertomemory-source-facts.projection-v1.json` — the **Projection v1** set.

## What this is

`apertomemory-source-facts.v2.json` records the native ApertoMemory results for
the five trust-and-custody interop vectors (007, 008, 011, 012, 014):
`derived_trust`, `authorship`, native 8-byte hexadecimal author/signer key
identifiers, custody fields, and the SHA-256 digest over the exact complete
sealed-object CBOR bytes.

`apertomemory-source-facts.projection-v1.json` records the same kind of native
facts for the two source objects the EMILIA Projection v1 positive record draws
from: 007 (delivered position 0) and 003 (delivered position 1). It covers
**only** those ApertoMemory-native facts. The neutral projection-record
mechanics — context fragments, projection bytes, adapter identity, and the
signature/proof — are EMILIA's and are deliberately absent here; they are not
part of the ApertoMemory format.

These are native ApertoMemory source facts. They are **not** the EMILIA
composition representation: there is no `_b64u` key encoding, no `trust_basis`,
and no JCS record wrapper. That representation, and the signed composition
records, live on the EMILIA side.

## What this is NOT

This is **not** the format's conformance suite. The normative artefact is the
14-vector set in [`test-vectors/v2/`](../../test-vectors/v2/); an implementation
is conformant if it reproduces those. This folder is interop material only: it
pins the subset of source facts that the EMILIA adapter consumes, so both
projects can diff a common ground truth.

## How it was generated

Every value is produced by running this repository's reference `open_sealed`
against `test-vectors/v2/apertomemory-v2-test-vectors.json` and computing the
digest as `"sha256:" + hex(SHA-256(exact sealed-object CBOR bytes))`, without
parsing or reserialization. Nothing here is copied from any EMILIA file.

## Cross-check

**Trust-and-custody set.** Generated independently from the reference, these
values matched EMILIA's checked-in fixtures
(`interop/apertomemory-emilia/apertomemory-source-fixtures.v2.json`) at commit
`961f101f`, field for field, across all five vectors: digest, trust, authorship,
author/signer key identifiers, and custody claimed/proven authors. The negative
cases (008, 011, 012, 014) all resolve to `unverified` / `unknown` with a null
author; 011's signer is the non-owner key `d05309cbd3b55f3b`; and 014's empty
custody map degrades to `unverified` without aborting the open.

**Projection v1 set.** Generated independently from the reference, the native
facts for 007 and 003 matched EMILIA's checked-in Projection v1 vectors
(`interop/apertomemory-emilia/memory-projection-record.v1.vectors.json`) at
commit `c737f37277c85117ff05963ed6f8f14d03c5e6b3`, field for field: 007 is
`trusted` / `attested` with proven author `d05309cbd3b55f3b`, and 003 is `self` /
`signed` by the owner `63c1e89c009c5ad7` with no custody. Only the
ApertoMemory-native facts were cross-checked; the neutral projection mechanics
(fragments, projection bytes, signature) are EMILIA's and out of scope here.
