# EMILIA interop — ApertoMemory source facts

This folder holds ApertoMemory's own independent copy of the source-fidelity
values used in the trust-and-custody interoperability set shared with the
[EMILIA Trusted Context Pack](https://github.com/emiliaprotocol/emilia-protocol).

## What this is

`apertomemory-source-facts.v2.json` records the native ApertoMemory results for
the five interop vectors (007, 008, 011, 012, 014): `derived_trust`,
`authorship`, native 8-byte hexadecimal author/signer key identifiers, custody
fields, and the SHA-256 digest over the exact complete sealed-object CBOR bytes.

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

Generated independently from the reference, these values matched EMILIA's
checked-in fixtures
(`interop/apertomemory-emilia/apertomemory-source-fixtures.v2.json`) at commit
`961f101f`, field for field, across all five vectors: digest, trust, authorship,
author/signer key identifiers, and custody claimed/proven authors. The negative
cases (008, 011, 012, 014) all resolve to `unverified` / `unknown` with a null
author; 011's signer is the non-owner key `d05309cbd3b55f3b`; and 014's empty
custody map degrades to `unverified` without aborting the open.
