"""Independent ApertoMemory-side producer for MEMORY-PROJECTION-RECORD-v1.

Implemented from draft-ferro-schrock-memory-projection-record-00 (normative
sections) plus the published JSON Schema. NOT ported from EMILIA's
implementation source: the point of a second producer is that it agrees with
the first only because both follow the draft, never because one copied the
other.

Built one layer at a time. Present layers:

  Layer 1 — per-fragment commitments (draft section "Delivered Entries and
            Projection Bytes"): the context_fragment_digest for each delivered
            fragment.
  Layer 2 — fragment framing (context-frame:v0): build a fragment's exact bytes
            from a delivered object's native labels plus its body text.
  Layer 3 — trust-snapshot serialization: build and commit the read-time
            keyring snapshot the draft delegates to the source profile.
"""
from __future__ import annotations
import base64
import hashlib
from dataclasses import dataclass


def sha256_commitment(data: bytes) -> str:
    """The draft's digest form: "sha256:" + lowercase hex of SHA-256(data).

    Used for every commitment in the record (sealed_object_digest,
    context_fragment_digest, projection.digest, and the selection-context
    digests). Layer 1 uses it only for fragment commitments.
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fragment_commitment(fragment_bytes: bytes) -> str:
    """context_fragment_digest for one delivered entry.

    Draft, section "Delivered Entries and Projection Bytes":
      "context_fragment_digest is SHA-256 over the exact bytes of the fragment
       emitted for that entry, including framing labels, separators, and line
       endings."

    So the input is the fragment's exact emitted bytes, verbatim: no trimming,
    no normalization, no re-encoding. The producer hashes what it will place in
    the projection, byte for byte.
    """
    if not isinstance(fragment_bytes, (bytes, bytearray)):
        raise TypeError("fragment_bytes must be raw bytes (the exact emitted fragment)")
    return sha256_commitment(bytes(fragment_bytes))


def fragment_commitments(fragments: list[bytes]) -> list[str]:
    """context_fragment_digest for an ordered list of delivered fragments.

    Order is significant: delivered entries are in projection order and
    `position` equals the zero-based index. This returns one commitment per
    fragment, in the same order.
    """
    return [fragment_commitment(f) for f in fragments]


# --------------------------------------------------------------------------
# Layer 2 — fragment framing (context-frame:v0)
# --------------------------------------------------------------------------
#
# WHAT THE DRAFT ACTUALLY SAYS
# ----------------------------
# The draft does NOT define a frame template. The only two normative statements
# that bear on fragment bytes are:
#
#   * Selection Context: "context_frame_profile names the deterministic
#     transformation from one opened source object and its labels to one
#     context fragment."  -> it is a NAMED profile; the transform lives outside
#     this draft.
#
#   * Delivered Entries: "context_fragment_digest is SHA-256 over the exact
#     bytes of the fragment emitted for that entry, including framing labels,
#     separators, and line endings."  -> tells us a fragment HAS labels,
#     separators and line endings, but not what they are.
#
# So everything below the byte level is a producer choice, not a draft rule:
# the label names, their order, the wrapper delimiters, the boolean spelling,
# the separator/newline placement, and where the body text comes from. This
# module makes the most literal choice available from the record's OWN
# vocabulary (the delivered-entry field names and enum values, which the draft
# and schema DO define), and emits the memory content as the body.
#
# This is the exact spot flagged in projection-v1-producer-spec.md section 6.2:
# "context_frame_profile is a named URN with no published definition." Layer 2
# is where an independent producer either happens to converge with the other
# implementation or exposes the gap.

# The four native labels the draft lists as belonging to a delivered entry, in
# the order the record schema lists them (derived_trust, authorship,
# author_key_id_b64u, custody_present). Independent choice of label KEYS: reuse
# the record's own member semantics, shortened to the natural nouns.
_FRAME_PROFILE_V0 = "urn:apertomemory:context-frame:v0"


@dataclass(frozen=True)
class DeliveredObject:
    """The native, source-authoritative labels for one selected object, plus
    the plaintext body to frame. `derived_trust`, `authorship`,
    `author_key_id_b64u` and `custody_present` come verbatim from open_sealed
    (the draft forbids recomputing them); `body` is the memory content the
    fragment carries.
    """
    derived_trust: str
    authorship: str
    author_key_id_b64u: str | None
    custody_present: bool
    body: str


def _bool_token(value: bool) -> str:
    # Draft is silent on boolean spelling. Independent choice: lowercase JSON
    # spelling, matching how booleans appear everywhere else in the record.
    return "true" if value else "false"


def build_fragment_v0(obj: DeliveredObject) -> bytes:
    """Build one fragment's exact UTF-8 bytes under context-frame:v0.

    INDEPENDENT reading (the draft does not specify this template):

      * A single header line carrying the four native labels, wrapped in a
        delimiter that marks the ApertoMemory-sourced region.
      * The body text on its own line.
      * A closing delimiter line.
      * Every line terminated by a single LF (\\n) -- the "line endings" the
        draft says the digest must cover.

    Concretely:

        [ApertoMemory trust=<derived_trust> authorship=<authorship> \\
          author_key=<author_key_id_b64u> custody=<true|false>]\\n
        <body>\\n
        [/ApertoMemory]\\n

    Label KEYS chosen from the record's own field names, shortened to the
    natural nouns: derived_trust -> trust, authorship -> authorship,
    author_key_id_b64u -> author_key, custody_present -> custody. author_key
    emits the b64u value, or the literal "none" when null.
    """
    author = obj.author_key_id_b64u if obj.author_key_id_b64u is not None else "none"
    header = (
        f"[ApertoMemory trust={obj.derived_trust} "
        f"authorship={obj.authorship} "
        f"author_key={author} "
        f"custody={_bool_token(obj.custody_present)}]"
    )
    text = f"{header}\n{obj.body}\n[/ApertoMemory]\n"
    return text.encode("utf-8")


# --------------------------------------------------------------------------
# Layer 3 — trust-snapshot serialization
# --------------------------------------------------------------------------
#
# WHAT THE DRAFT ACTUALLY SAYS
# ----------------------------
# Only two statements bear on the trust-snapshot bytes:
#
#   * Terminology (Trust snapshot): "A commitment to the source-profile trust
#     state used when the selection decision was made. For ApertoMemory this is
#     a read-time keyring snapshot, because trust is derived rather than stored
#     in the object."
#
#   * Selection Context: "trust_snapshot_digest is SHA-256 over the
#     source-profile-defined trust snapshot."
#
# That is the whole specification. The draft is EXPLICIT that the snapshot is
# "source-profile-defined" -- i.e. it deliberately delegates the structure and
# byte layout to ApertoMemory and defines nothing itself. So every byte-level
# decision here is a source-profile choice, and it belongs in the ApertoMemory
# profile, not in this neutral draft:
#
#   * what the snapshot contains (owner key, accepted keys, anything else);
#   * the key-id encoding (native 8-byte hex? base64url?);
#   * the container format (JSON? CBOR? a flat concatenation?);
#   * for JSON: key order, member names, array order, whitespace, i.e. whether
#     it is JCS-canonicalized.
#
# INDEPENDENT READING taken here
# ------------------------------
# The one concrete anchor is "read-time keyring snapshot". ApertoMemory's
# keyring at read time is exactly: the vault owner signing key (yields trust
# "self") plus the set of accepted third-party author keys in `known_keys`
# (yields "trusted"). So the snapshot commits to those two things.
#
# Choices I make, none of them dictated by the draft:
#   * Represent key-ids as unpadded base64url of the native 8-byte key-id. The
#     draft defines a b64u term and uses it for author_key_id_b64u, so reusing
#     b64u for keyring key-ids is the most consistent record-level choice --
#     though ApertoMemory-native key-ids are hex, so this is a re-encoding.
#   * Container = JSON, canonicalized like the rest of the record (JCS: sorted
#     keys, minimal separators, no whitespace), since the record already
#     mandates JCS for signing. Member names mirror the record's vocabulary:
#     owner_key_id_b64u and accepted_key_ids_b64u.
#   * accepted_key_ids_b64u sorted ascending (JCS-style determinism for a set).
#
# This is spec section 6.1: "Trust-snapshot serialization (highest risk)... the
# byte layout is undefined." Layer 3 is where an independent producer converges
# with or diverges from the other implementation.


def _hex_keyid_to_b64u(hex_key_id: str) -> str:
    """Re-encode an ApertoMemory native 8-byte hex key-id as unpadded base64url.

    ApertoMemory produces key-ids as lowercase hex (e.g. "63c1e89c009c5ad7").
    The record's b64u term (RFC 4648 sec 5, unpadded) is reused here for the
    keyring snapshot -- a producer choice, since the draft does not say how a
    keyring key-id is encoded.
    """
    raw = bytes.fromhex(hex_key_id)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jcs_compact_object(members: dict[str, object]) -> bytes:
    """Serialize a flat JSON object the way JCS (RFC 8785) would for these
    value types: keys sorted lexicographically, no whitespace, strings and
    arrays of strings only. This mirrors the canonicalization the record
    already requires for signing, applied to the snapshot.
    """
    import json
    return json.dumps(
        members,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_trust_snapshot_v0(owner_key_id_hex: str,
                            accepted_key_ids_hex: list[str]) -> bytes:
    """Build the read-time keyring snapshot's exact bytes.

    Input is ApertoMemory-native (hex key-ids: the owner signing key-id and the
    accepted third-party author key-ids from the vault keyring). Output is the
    byte string that trust_snapshot_digest commits to.

    Structure (a source-profile choice, NOT specified by the draft):

        {"accepted_key_ids_b64u":[<sorted b64u>...],"owner_key_id_b64u":<b64u>}

    JCS-compact JSON, keys sorted, accepted array sorted ascending.
    """
    accepted = sorted(_hex_keyid_to_b64u(k) for k in accepted_key_ids_hex)
    members = {
        "owner_key_id_b64u": _hex_keyid_to_b64u(owner_key_id_hex),
        "accepted_key_ids_b64u": accepted,
    }
    return _jcs_compact_object(members)


def trust_snapshot_commitment(owner_key_id_hex: str,
                              accepted_key_ids_hex: list[str]) -> tuple[bytes, str]:
    """Return (snapshot_bytes, trust_snapshot_digest) for the given keyring."""
    snapshot = build_trust_snapshot_v0(owner_key_id_hex, accepted_key_ids_hex)
    return snapshot, sha256_commitment(snapshot)
