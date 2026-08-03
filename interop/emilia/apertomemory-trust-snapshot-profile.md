# ApertoMemory Trust-Snapshot Profile (v0)

**Status:** normative for ApertoMemory. Defines the byte-exact serialization of
the read-time keyring snapshot that `draft-ferro-schrock-memory-projection-record-00`
delegates to the source profile ("`trust_snapshot_digest` is SHA-256 over the
source-profile-defined trust snapshot"). This document IS that source-profile
definition for ApertoMemory sources.

**Profile identifier:** `urn:apertomemory:trust-snapshot:v0`

## 1. Purpose

A Memory Projection Record commits to the trust state used when the projection
was selected, via `selection_context.trust_snapshot_digest`. Because
ApertoMemory derives trust at read time from the keyring (never from the
object), that trust state is exactly the read-time keyring. This profile fixes
how that keyring is serialized to bytes so that `trust_snapshot_digest` is
independently reproducible: two conforming implementations MUST produce
byte-identical snapshots for the same keyring.

## 2. What the snapshot contains

The snapshot commits to exactly two things, and nothing else:

- the **owner signing key-id** — the vault's own signing key, which yields
  trust `self`; and
- the set of **accepted author key-ids** — the third-party author keys the
  vault has accepted, which yield trust `trusted`.

This mirrors precisely what the ApertoMemory reference keyring holds at read
time. In the reference, `open_sealed` derives trust from two inputs only:
`owner_sign_pub` (→ `self`) and `known_keys`, the `{key_id: sign_pub}` map of
accepted third-party authors (→ `trusted`) (`src/amem/objects.py`,
`src/amem/vault.py: known_keys()`). There is no other trust input:

- **No scope.** Trust is keyring-derived, not scope-derived; scope belongs to
  the object, not the trust decision.
- **No evaluation timestamp.** The record already carries
  `selection_context.trust_evaluated_at`; duplicating it inside the snapshot
  would create two copies that could disagree.
- **No algorithm identifier.** All ApertoMemory signing keys are Ed25519 by
  format definition; an algorithm field would be a constant.

## 3. Key-id representation

A key-id is the ApertoMemory-native author key identifier:

    key_id = SHA-256(Ed25519 signing public key)[:8]   # first 8 bytes

(`src/amem/objects.py: key_id()`; `keys.py: author_key_id`). It is an **8-byte
value**. In this profile the key-id is carried as its **raw 8 bytes** inside a
CBOR byte string — NOT hex text, NOT base64url. (ApertoMemory represents key-ids
as lowercase hex in human-facing contexts; inside the CBOR snapshot the value is
the raw bytes those hex digits denote.)

## 4. Container: canonical CBOR

The snapshot is serialized as a single CBOR data item using **canonical /
deterministic encoding per RFC 8949 §4.2** (the same deterministic CBOR
ApertoMemory already uses for sealed objects: `cbor2.dumps(..., canonical=True)`).

Rationale for CBOR over JSON: consistency with ApertoMemory's native wire format
(the format is CBOR throughout), and stronger reproducibility for a committed
digest — a single deterministic-CBOR regime rather than a second text
canonicalization. Raw-byte key-ids also avoid any text-encoding ambiguity in the
committed bytes.

## 5. Structure (byte-exact)

The snapshot is a **CBOR map** with two entries, integer keys:

| Key | Meaning | Value type |
| --- | --- | --- |
| `1` | owner signing key-id | CBOR byte string, exactly 8 bytes |
| `2` | accepted author key-ids | CBOR array of CBOR byte strings, each exactly 8 bytes |

Deterministic-encoding rules (RFC 8949 §4.2), all mandatory:

- Map keys are encoded in canonical order (shortest encoding, then bytewise);
  for the two integer keys `1` and `2` this is simply `1` before `2`.
- Integer keys use the minimal integer encoding (`0x01`, `0x02`).
- Each key-id byte string uses the minimal length prefix (`0x48` = byte string
  of length 8) followed by the 8 raw bytes.
- No indefinite-length items, no tags, no duplicate keys.

### 5.1 Accepted-array ordering

The `accepted` array (key `2`) MUST be sorted by **raw key-id bytes, ascending**
(bytewise, unsigned). Sorting is on the 8 raw bytes, NOT on any text encoding of
them.

Rationale: raw-byte ordering is encoding-stable — it is independent of how a
key-id is ever textually rendered (hex, base64url, etc.), so the order is the
same regardless of representation choices elsewhere. (Base64url text order in
particular is NOT the same as byte order, so sorting encoded text would couple
the ordering to the encoding.)

Duplicate key-ids MUST NOT appear in the array. If the source keyring somehow
holds a duplicate, it is collapsed to one entry before sorting.

### 5.2 Empty accepted set

When the vault has accepted no third-party author keys, key `2` is a **present,
empty CBOR array** (`0x80`). It is NOT omitted. The map always has exactly two
entries.

### 5.3 Owner key

Key `1` is always present and is exactly one 8-byte key-id (the vault owner
signing key-id). The owner key-id is not repeated inside the accepted array even
if, in some construction, the owner also appears as an accepted author; the
accepted array is the third-party set as held in `known_keys`.

## 6. Digest

    trust_snapshot_digest = "sha256:" + lowercase_hex( SHA-256( canonical_cbor_snapshot_bytes ) )

i.e. SHA-256 over the exact canonical-CBOR bytes defined above, rendered in the
record's standard `sha256:<64 lowercase hex>` digest form.

## 7. Worked example (byte-exact)

Owner key-id `63c1e89c009c5ad7`, one accepted key-id `d05309cbd3b55f3b`:

- Accepted array (raw-byte ascending): a single accepted key-id, so the array
  is just `[d05309cbd3b55f3b]`; no ordering is exercised here.
- CBOR map: `{1: h'63c1e89c009c5ad7', 2: [h'd05309cbd3b55f3b']}`
- Canonical CBOR (hex):
  `a2` (map, 2 pairs) `01` (key 1) `48 63c1e89c009c5ad7` (bstr8)
  `02` (key 2) `81` (array, 1) `48 d05309cbd3b55f3b` (bstr8)

The `trust_snapshot_digest` is SHA-256 over those exact bytes. See
`projection_producer.build_trust_snapshot_v1` for the reference producer and the
regenerated digest values.

## 8. Compatibility note — this CHANGES the provisional encoding

Earlier interop convergence with EMILIA's checked-in vectors used a PROVISIONAL
serialization: **base64url** key-ids in a **JSON/JCS** object
(`{"accepted_key_ids_b64u":[...],"owner_key_id_b64u":...}`), accepted array
sorted by **base64url text**. Those choices produced byte-identical snapshots to
EMILIA's vectors, but the convergence was on an under-specified point, not a
written profile.

This profile deliberately supersedes all three provisional choices:

| Aspect | Provisional (converged w/ EMILIA vector) | This profile (normative) |
| --- | --- | --- |
| Container | JSON / JCS | canonical CBOR (RFC 8949 §4.2) |
| Key-id encoding | base64url text | raw 8 bytes in a CBOR byte string |
| Accepted-array order | base64url text ascending | raw key-id bytes ascending |
| Member keys | `owner_key_id_b64u`, `accepted_key_ids_b64u` | integer map keys `1`, `2` |

**Consequence: `trust_snapshot_digest` values change.** EMILIA's current
`memory-projection-record.v1.vectors.json` snapshot digests (positive case and
the three `source_profile_edge_cases`) were computed under the provisional
serialization and will NOT match this profile. EMILIA's vectors need
regeneration against this profile once it is adopted. This is expected and
intended: the point of the profile is to replace lucky convergence with a
byte-exact specification. The regenerated digests this profile produces are
listed alongside the producer update.

Only `selection_context.trust_snapshot_digest` (and, transitively, any record
signature computed over a record containing it) changes. The context-frame
fragments, `sealed_object_digest`, and the native trust/authorship/custody facts
are unaffected by this profile.
