# MEMORY-PROJECTION-RECORD-v1 — Producer Implementation Spec

Implementation spec for an independent ApertoMemory-side producer of
`MEMORY-PROJECTION-RECORD-v1`, derived only from the published draft, the
JSON Schema, and the interop vectors — **not** from EMILIA's implementation
source. Independence from their code is deliberate: two implementations that
agree only because one copied the other prove nothing.

**Sources**

- `draft-ferro-schrock-memory-projection-record-00` (normative sections),
  EMILIA repo commit `ad7dac30`.
- `memory-projection-record-v1.schema.json` (sha256 `fdc18919…`).
- `memory-projection-record.v1.vectors.json` (sha256 `1e2167bd…`).
- ApertoMemory reference: `~/Downloads/apertomemory-repo`, native facts from
  `open_sealed`.

## 0. Record model

A **closed I-JSON object** (RFC 7493). JSON member order carries no
significance. Unknown members MUST be refused. `additionalProperties:false` at
every level. All numbers are non-negative safe integers.

## 1. Complete field list

Origin legend: **[NATIVE]** = comes from `open_sealed`; **[RECORD]** = a new
record-level field the producer constructs.

### Top level (11 members, all required)

| Field | Type | Origin | Notes |
|---|---|---|---|
| `@version` | const string | [RECORD] | `"MEMORY-PROJECTION-RECORD-v1"` |
| `source_profile` | string 1–1024 | [RECORD] | `"draft-ferro-apertomemory-02"` |
| `projection_id` | URI ≤2048 | [RECORD] | globally unique URI |
| `created_at` | UTC RFC3339, ends `Z` | [RECORD] | record build time |
| `adapter` | object | [RECORD] | see 1.1 |
| `selection_context` | object | [RECORD] | see 1.2 |
| `delivered` | array (maxItems 65535) | mixed | ordered; see 1.3 |
| `exclusions` | object | [RECORD] | see 1.4 |
| `projection` | object | [RECORD] | see 1.5 |
| `nonclaims` | object | [RECORD] | see 1.6; all four const `NOT_ESTABLISHED` |
| `proof` | object | [RECORD] | see 1.7; added after signing |

### 1.1 `adapter` (both required)

- `id`: URI ≤2048 — producer identity.
- `key_id`: string 1–1024 — selects the signing key from relying-party policy.
  **MUST equal `proof.key_id`.**

### 1.2 `selection_context` (5 required)

- `recall_request_digest`: `sha256:<64hex>` [RECORD] — see 2.4
- `selection_policy_digest`: `sha256:<64hex>` [RECORD] — see 2.4
- `trust_snapshot_digest`: `sha256:<64hex>` [RECORD, ApertoMemory-shaped] — see 2.5
- `trust_evaluated_at`: UTC RFC3339 `Z` [RECORD] — keyring read time
- `context_frame_profile`: string 1–1024 [RECORD] — names the object→fragment
  transform (vectors: `urn:apertomemory:context-frame:v0`)

### 1.3 `delivered[]` — each entry (7 required), in array-index order

| Field | Type | Origin |
|---|---|---|
| `position` | int ≥0 | [RECORD] MUST equal zero-based index, MUST NOT repeat |
| `object.format_version` | int ≥1 | [NATIVE] `out["format_version"]` |
| `object.sealed_object_digest` | `sha256:<64hex>` | [RECORD from native bytes] (2.1) |
| `context_fragment_digest` | `sha256:<64hex>` | [RECORD] (2.2) |
| `derived_trust` | enum `self`\|`trusted`\|`unverified` | [NATIVE] `out["trust"]` |
| `authorship` | enum `signed`\|`attested`\|`unknown` | [NATIVE] `provenance["authorship"]` |
| `author_key_id_b64u` | b64u or `null` | [NATIVE, re-encoded] b64u(hex author_key_id) or null |
| `custody_present` | boolean | [NATIVE] `out["custody"] is not None` |

Cross-field invariants (from §Delivered; `open_sealed` already satisfies them):

- `authorship == "attested"` ⟹ `custody_present == true`
- `derived_trust == "unverified"` ⟹ `authorship == "unknown"` AND `author_key_id_b64u == null`
- verified content (`self`/`trusted`) ⟹ `author_key_id_b64u != null`

### 1.4 `exclusions` (2 required)

- `total`: int ≥0
- `by_reason`: exactly 4 int≥0 counters: `authentication_failed`,
  `schema_invalid`, `policy_filtered`, `context_limit`
- Invariant: `total == sum(by_reason values)`

### 1.5 `projection` (3 required)

- `encoding`: const `"utf-8"`
- `byte_length`: int ≥0 — see 2.3
- `digest`: `sha256:<64hex>` — see 2.3

### 1.6 `nonclaims` (4 required, all const `NOT_ESTABLISHED`)

`model_use`, `action_linkage`, `action_authorization`, `execution_outcome`.

### 1.7 `proof` (3 required)

- `alg`: const `"Ed25519"`
- `key_id`: string 1–1024, MUST equal `adapter.key_id`
- `signature_b64u`: b64u, **exactly 86 chars** (64-byte Ed25519 sig, unpadded)

## 2. Commitment computation — exact byte inputs

Every digest is the ASCII string `"sha256:"` + lowercase-hex SHA-256 of the
byte input below.

- **2.1 `sealed_object_digest`** — SHA-256 over the exact complete sealed-object
  CBOR bytes as stored, no parse/reserialize. (007 → 278 B → `025672…f63620`;
  003 → 257 B → `7634d1…1ccdb4`.)
- **2.2 `context_fragment_digest`** — SHA-256 over the exact fragment bytes,
  including framing labels, separators, and line endings. Fragment is UTF-8.
  Observed frame layout (see §4 ambiguity 2):
  ```
  [ApertoMemory trust=<t> authorship=<a> author_key=<b64u|…> custody=<true|false>]\n
  <free-text body>\n
  [/ApertoMemory]\n
  ```
- **2.3 complete projection** — `projection_bytes = concat(fragment_bytes[i] in
  ascending position)`; `byte_length = len(projection_bytes)`;
  `digest = sha256 over projection_bytes`. Pure bytewise concatenation, no
  inserted separator. (Positive vector: 328 B, `a58a3e…`.)
- **2.4 `recall_request_digest` / `selection_policy_digest`** — SHA-256 over the
  exact request/policy bytes. Cleartext NOT carried in the record; serialization
  profile is producer-defined (see §4 ambiguity 3).
- **2.5 `trust_snapshot_digest`** — SHA-256 over the source-profile-defined trust
  snapshot. Vector snapshot is compact JSON, sorted keys:
  `{"accepted_key_ids_b64u":["0FMJy9O1Xzs"],"owner_key_id_b64u":"Y8HonACcWtc"}`
  (see §4 ambiguity 1).

## 3. Signing boundary

1. Build the complete record **without** `proof`.
2. Canonicalize with **JCS (RFC 8785)** → UTF-8 bytes.
3. Signing input = `b"MEMORY-PROJECTION-RECORD-v1\x00"` **||** `JCS(record-without-proof)`.
4. Sign with **Ed25519** (RFC 8032). `signature_b64u` = unpadded base64url of
   the 64-byte signature (86 chars).
5. Attach `proof = {alg, key_id (== adapter.key_id), signature_b64u}`.

Verified independently: the vector signature validates under this exact domain
and does NOT validate under the legacy `AMEM-EMILIA-PROJECTION-RECORD-v0\0`
domain. Adapter public key is relying-party-pinned SPKI-DER→base64url (a key
carried in the record is not a trust anchor) — verifier's concern.

## 4. NATIVE vs RECORD split

**From `open_sealed` (native — MUST NOT be recomputed under new rules,
§Delivered):** `format_version`, `trust`, `provenance.authorship`,
`provenance.author_key_id` (hex → b64u, or null), `custody is not None`; the
sealed CBOR bytes (for 2.1); owner + accepted key-ids (for the snapshot).

**Record-level (new, not from ApertoMemory):** `@version`, `source_profile`,
`projection_id`, `created_at`, `adapter.*`, `selection_context.*`, the fragment
framing text and its digests, the concatenated projection + digest/length,
`exclusions`, `nonclaims`, `proof`, per-entry `position` and ordering.

## 5. Producer algorithm (normative order, §Producer)

1. Open + verify candidates via `open_sealed`; capture trust snapshot and
   `trust_evaluated_at`.
2. Commit to recall request + full selection policy BEFORE selecting.
3. Apply auth/schema/policy/ordering/size rules; count each excluded candidate
   under exactly one reason.
4. Build each final fragment, hash exact bytes, append entry in order. Fragments
   frozen after this step.
5. Concatenate fragments → `byte_length` + `digest`; set `nonclaims`; sign the
   closed record.
6. Return projection bytes + record together. A post-signing/pre-delivery
   failure MUST NOT be reported as model receipt.

## 6. Ambiguities / underspecified points

Places the draft prose does not pin down, where the byte-exact contract lives in
the fixtures rather than the text. Independent implementations will diverge here
unless these are written into a profile.

1. **Trust-snapshot serialization (highest risk).** §Selection says only
   "SHA-256 over the source-profile-defined trust snapshot"; the byte layout is
   undefined. The vector uses compact JSON, sorted keys
   (`accepted_key_ids_b64u` before `owner_key_id_b64u`), b64u 8-byte key-ids,
   accepted array sorted, no whitespace. This ApertoMemory-profile structure is
   only implied by one example. **Needs a written definition.**
2. **`context_frame_profile` transform is a named URN with no published
   definition.** `urn:apertomemory:context-frame:v0` and the exact frame
   template (label names, `true/false` spelling, `\n` endings, body content) are
   only inferable from the vector bytes. Two producers will diverge on fragment
   bytes → different fragment/projection digests. **Needs a written template.**
3. **`recall_request` / `selection_policy` serialization profiles are
   undefined.** Fine for producing a digest (producer defines its own bytes) but
   a verifier "relying on" them needs the same profile.
4. **`author_key_id_b64u` byte width not pinned at record level** (schema only
   requires charset + `minLength:2`). ApertoMemory is always 8 bytes → 11 b64u
   chars. Non-issue for this producer; noted for neutrality.
5. **JSON number canonicalization** — non-issue: all numbers are small
   non-negative safe integers, no floats.
6. **`projection_id` scheme** is producer-chosen; draft prescribes only global
   uniqueness (vectors use `urn:memory-projection:<profile>:<id>`).
7. **Draft inline example `byte_length` (314) differs from the positive vector
   (328).** Both synthetic, different fragment text — not a contradiction. Build
   against the vectors (byte-exact ground truth), not the draft example.
