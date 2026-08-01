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
"""
from __future__ import annotations
import hashlib


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
