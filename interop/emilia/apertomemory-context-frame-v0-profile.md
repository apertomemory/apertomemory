# ApertoMemory Context-Frame Profile v0

**Status:** normative for ApertoMemory. Defines the byte-exact transformation
from one opened ApertoMemory object (its native trust/authorship/custody labels
plus its cleartext body) to one context fragment, which
`draft-ferro-schrock-memory-projection-record-00` names but does not define
("`context_frame_profile` names the deterministic transformation from one opened
source object and its labels to one context fragment"). This document IS that
transformation for ApertoMemory sources.

**Profile identifier:** `urn:apertomemory:context-frame:v0`

This is the value carried in `selection_context.context_frame_profile`, and it
is the transform whose output each `delivered[].context_fragment_digest` and the
concatenated `projection.digest` commit to.

## 1. Purpose and status — this RATIFIES existing bytes

Unlike the ApertoMemory Trust-Snapshot Profile (which changes the provisional
serialization and requires EMILIA to regenerate its snapshot digests), this
profile **does not change any bytes**. The framing the reference producer
already emits (`projection_producer.build_fragment_v0`) is byte-identical to
EMILIA's current `memory-projection-record.v1.vectors.json` fragments, including
the `null_author` edge case. This profile formalizes those existing convergent
bytes so the transform is written down and independently reproducible, rather
than an implicit shared reading. See §7 (compatibility note): EMILIA's vectors
do NOT need regeneration for framing.

## 2. Fragment template

A context fragment is exactly three lines, each terminated by a single line
feed (`\n`, 0x0A), encoded as UTF-8:

    [ApertoMemory trust=<trust> authorship=<authorship> author_key=<author_key> custody=<custody>]\n
    <body>\n
    [/ApertoMemory]\n

- Line 1 is the **header**: the literal `[ApertoMemory ` prefix, four
  space-separated `label=value` fields in fixed order, and a closing `]`.
- Line 2 is the **body**: the memory content, verbatim (§5).
- Line 3 is the literal closing delimiter `[/ApertoMemory]`.

The complete fragment is `header + "\n" + body + "\n" + "[/ApertoMemory]" +
"\n"`. There is no leading whitespace, no trailing content after the final `\n`,
and no blank lines.

## 3. Header fields — names, order, sources

The header carries exactly four fields, in this fixed order, sourced verbatim
from the delivered entry's native labels:

| Field (header label) | Value | Source (delivered-entry native field) |
| --- | --- | --- |
| `trust` | `self` \| `trusted` \| `unverified` | `derived_trust` |
| `authorship` | `signed` \| `attested` \| `unknown` | `authorship` |
| `author_key` | base64url key-id, or `none` (§4) | `author_key_id_b64u` |
| `custody` | `true` \| `false` (§4.1) | `custody_present` |

Fields are separated by a single space (0x20). The field order is fixed and
mirrors the delivered-entry field order; it MUST NOT vary.

### 3.1 Values are native — MUST NOT be recomputed

`trust`, `authorship`, `author_key`, and `custody` are the source-profile
result produced by ApertoMemory's `open_sealed` at read time
(`derived_trust`, `authorship`, `author_key_id_b64u`, `custody_present`). The
frame carries them verbatim. A producer MUST NOT recompute or reinterpret these
under rules of its own; the frame is a rendering of the native result, not a
second trust evaluation. (This matches the draft's Delivered-Entries rule that
those four values "preserve the source-profile result used at selection time"
and "MUST NOT be recomputed under rules invented by the projection producer.")

## 4. The `author_key` value and the null-author token

`author_key` renders `author_key_id_b64u` from the delivered entry:

- When `author_key_id_b64u` is a key-id (verified content: `self` or `trusted`
  trust), `author_key` is that base64url key-id verbatim (e.g.
  `author_key=0FMJy9O1Xzs`).
- When `author_key_id_b64u` is null (unverified content, where the draft
  requires `authorship=unknown` and a null author key), `author_key` is the
  literal token **`none`**: `author_key=none`.

The `none` token is reserved: a real key-id is base64url of an 8-byte value (11
characters), so it can never equal the 4-character literal `none`, and the two
are unambiguous. The header always carries the `author_key=` field (fixed
four-field arity); it is never omitted and never left empty.

Ratification note: draft -00 requires unverified content to use a null author
key but does not mandate how a null author renders in a fragment. This profile
ratifies `author_key=none`, which is the token the reference producer already
emits and which matches EMILIA's `null_author` vector byte-for-byte.

### 4.1 Boolean spelling

`custody` is spelled in lowercase: `true` when `custody_present` is true,
`false` otherwise. No other spelling (`True`, `yes`, `1`) is permitted.

## 5. Body

The body (line 2) is the memory object's cleartext content, verbatim, encoded
as UTF-8. It is the plaintext that ApertoMemory `open_sealed` yields for the
object; the frame does not transform, trim, normalize, or re-encode it. The
projection as a whole is UTF-8 (the record mandates `projection.encoding =
utf-8`), so the body MUST be valid UTF-8.

Because each fragment is length- and digest-committed (`context_fragment_digest`
per entry, `projection.byte_length` and `projection.digest` for the whole), a
body that happened to contain a line such as `[/ApertoMemory]` cannot forge
fragment boundaries: verification is by digest over exact bytes, not by parsing
the delimiters. The delimiters are for human/tool legibility; the commitments
are authoritative.

## 6. Which values come from `open_sealed` vs the frame structure

- **Native, from `open_sealed` (MUST NOT be recomputed):** the four header
  values — `derived_trust`, `authorship`, `author_key_id_b64u`,
  `custody_present` — and the body (object cleartext content).
- **Frame structure (this profile):** the `[ApertoMemory …]` / `[/ApertoMemory]`
  delimiters, the four label names and their fixed order, the single-space field
  separator, the `author_key=none` null token, the lowercase boolean spelling,
  and the single-LF line endings.

## 7. Worked examples (byte-exact)

### 7.1 Verified object (007 case: trusted / attested / custody)

Native labels: `derived_trust=trusted`, `authorship=attested`,
`author_key_id_b64u=0FMJy9O1Xzs`, `custody_present=true`. Body:
`Source vector 007: fact authored by a third party and re-sealed by the vault owner.`

Fragment (UTF-8, `\n` shown literally):

    [ApertoMemory trust=trusted authorship=attested author_key=0FMJy9O1Xzs custody=true]\n
    Source vector 007: fact authored by a third party and re-sealed by the vault owner.\n
    [/ApertoMemory]\n

- Length: 185 bytes.
- `context_fragment_digest`:
  `sha256:8705dd3315ac111cc0531f1f6cbc99df6542eec56fd732db95e37d1a15f15ecc`

### 7.2 Unverified object (null-author: `author_key=none`)

Native labels: `derived_trust=unverified`, `authorship=unknown`,
`author_key_id_b64u=null`, `custody_present=false`. Body:
`Source edge: native verification did not resolve an author.`

Fragment (UTF-8, `\n` shown literally):

    [ApertoMemory trust=unverified authorship=unknown author_key=none custody=false]\n
    Source edge: native verification did not resolve an author.\n
    [/ApertoMemory]\n

- Length: 157 bytes.
- `context_fragment_digest`:
  `sha256:e14214df9b4b22487c19458a0d7c800ebe19435bc46f6109a7377c5ca156f9eb`

Both digests are what `projection_producer.build_fragment_v0` +
`fragment_commitment` produce, and both match EMILIA's current
`memory-projection-record.v1.vectors.json` (the positive `delivered[0]` fragment
and the `source_profile_edge_cases.null_author` fragment, respectively).

## 8. Compatibility note — no regeneration needed

This profile ratifies the framing bytes the reference producer already emits and
that EMILIA's vectors already contain; it changes nothing. EMILIA's current
`memory-projection-record.v1.vectors.json` fragment digests, `projection.digest`,
and any record signature over them remain valid under this profile. No
regeneration is required for framing.

(Contrast the ApertoMemory Trust-Snapshot Profile, which deliberately changes
the snapshot serialization and does require EMILIA to regenerate its
`trust_snapshot_digest` values. The two profiles are independent: adopting this
context-frame profile has no effect on the trust-snapshot digests, and vice
versa.)
