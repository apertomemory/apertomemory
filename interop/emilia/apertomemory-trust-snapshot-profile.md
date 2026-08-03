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

This differs deliberately from the ApertoMemory Context-Frame Profile v0, which
renders `author_key` in base64url: that profile mirrors the neutral projection
record's `author_key_id_b64u` field, whereas this snapshot is a standalone CBOR
blob that only ever gets hashed, so it uses raw bytes. The two encodings are
independent and each is native to its own artifact.

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

Key `1` is always present and is exactly one 8-byte key-id: the vault owner
signing key-id.

Key `2` (the accepted array) is exactly the `known_keys` set, de-duplicated and
sorted by raw bytes ascending per §5.1. The owner key-id and the accepted
key-ids are conceptually distinct roles — the owner yields trust `self`, an
accepted author yields `trusted` — and `known_keys` is the set of accepted
third-party authors. If the owner key-id also appears in `known_keys`, it is
kept in the accepted array, not stripped: it is redundant (the owner key already
yields `self`, which outranks `trusted`, so an owner entry in the accepted set
never changes any trust outcome) but it is not removed. The snapshot serializes
the keyring as held.

## 6. Digest

    trust_snapshot_digest = "sha256:" + lowercase_hex( SHA-256( canonical_cbor_snapshot_bytes ) )

i.e. SHA-256 over the exact canonical-CBOR bytes defined above, rendered in the
record's standard `sha256:<64 lowercase hex>` digest form.

## 7. Worked examples (byte-exact)

### 7.1 Single accepted key

Owner key-id `63c1e89c009c5ad7`, one accepted key-id `d05309cbd3b55f3b`:

- Accepted array (raw-byte ascending): a single accepted key-id, so the array
  is just `[d05309cbd3b55f3b]`; no ordering is exercised here.
- CBOR map: `{1: h'63c1e89c009c5ad7', 2: [h'd05309cbd3b55f3b']}`
- Canonical CBOR (hex):
  `a2` (map, 2 pairs) `01` (key 1) `48 63c1e89c009c5ad7` (bstr8)
  `02` (key 2) `81` (array, 1) `48 d05309cbd3b55f3b` (bstr8)
- Full canonical bytes:
  `a2014863c1e89c009c5ad7028148d05309cbd3b55f3b`
- `trust_snapshot_digest`:
  `sha256:ad677e36d1ac311f758cefeb41069704d1bc995612db0bc1029e239ecfcc2b5d`

### 7.2 Two accepted keys — ordering exercised

Owner key-id `0102030405060708`, two distinct accepted key-ids
`0000000000000001` and `d000000000000000` (illustrative 8-byte values, none of
them the owner). This pair is chosen so the raw-byte order and the base64url-text
order differ, showing why §5.1 pins the sort to raw bytes.

- Accepted key-ids, as held (unsorted): `d000000000000000`, `0000000000000001`.
- Sorted by **raw key-id bytes, ascending** (the rule): `0000000000000001`
  then `d000000000000000`, because the first byte `0x00 < 0xd0`.
- For contrast, sorting by **base64url text** would give the OPPOSITE sequence:
  the base64url forms are `0000000000000001` → `AAAAAAAAAAE` and
  `d000000000000000` → `0AAAAAAAAAA`, and `"0AAAAAAAAAA" < "AAAAAAAAAAE"` in text
  order (the digit `'0'` sorts before the letter `'A'` in ASCII), so text
  sorting would place `d000000000000000` first. The two rules produce different
  byte sequences and therefore different digests; this profile mandates the
  raw-byte order.
- CBOR map: `{1: h'0102030405060708', 2: [h'0000000000000001', h'd000000000000000']}`
- Canonical CBOR (hex):
  `a2` (map, 2 pairs) `01` (key 1) `48 0102030405060708` (bstr8)
  `02` (key 2) `82` (array, 2) `48 0000000000000001` (bstr8)
  `48 d000000000000000` (bstr8)
- Full canonical bytes:
  `a201480102030405060708028248000000000000000148d000000000000000`
- `trust_snapshot_digest`:
  `sha256:a6cec9a790d68dda6df60477c802cd3738650cd8f1b38fcc21125de51762e231`

### 7.3 Empty accepted set

Owner key-id `63c1e89c009c5ad7`, no accepted third-party keys (§5.2). Key `2` is
a present, empty array.

- CBOR map: `{1: h'63c1e89c009c5ad7', 2: []}`
- Canonical CBOR (hex):
  `a2` (map, 2 pairs) `01` (key 1) `48 63c1e89c009c5ad7` (bstr8)
  `02` (key 2) `80` (empty array)
- Full canonical bytes:
  `a2014863c1e89c009c5ad70280`
- `trust_snapshot_digest`:
  `sha256:eddde59fb79cca10fdadf0c5bfc7c3b7e466cab79dcb95a5c4ea165fc8eb5bf0`

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
byte-exact specification. The digests this profile produces for the positive,
two-key, and empty-accepted cases are the worked examples in §7.1–§7.3.

Only `selection_context.trust_snapshot_digest` (and, transitively, any record
signature computed over a record containing it) changes. The context-frame
fragments, `sealed_object_digest`, and the native trust/authorship/custody facts
are unaffected by this profile.
