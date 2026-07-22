"""ApertoMemory v0.2 — Memory Object seal/open (spec §3-§4).

sealed-object: {1: id, 2: scope_id, 3: format_version, 4: COSE_Encrypt0(COSE_Sign1(payload))}

Security model (format_version 2):
  * Envelope binding — the outer fields (format_version, id, scope_id) are fed
    as COSE external_aad to BOTH the signature and the AEAD. Rewriting them
    invalidates the object.  [fixes: unauthenticated outer metadata]
  * Author binding — author_key_id in the payload MUST equal
    sha256(verifying public key)[:8]. A signer cannot claim someone else's
    authorship.  [fixes: forgeable provenance]
  * Trust is DERIVED from which key verified, never read from the payload.
  * Verification is mandatory: opening without a key requires an explicit
    opt-in and the result is marked unverified with trust="unverified".

format_version 1 objects have none of these bindings: they are readable in
legacy mode but are always reported as unverified. Use `amem migrate`.
"""
from __future__ import annotations
import hashlib
import math
import os
import time as _time
from dataclasses import dataclass, field

import cbor2
from pycose.messages import Sign1Message, Enc0Message
from pycose.keys import OKPKey, SymmetricKey
from pycose.keys.curves import Ed25519
from pycose.algorithms import EdDSA, A256GCM
from pycose.headers import Algorithm, IV, KID

from .keys import Identity

FORMAT_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)

TYPE = {"episodic": 1, "semantic": 2, "procedural": 3}
TYPE_INV = {v: k for k, v in TYPE.items()}
TRUST = {"self": 1, "trusted": 2, "third-party": 3, "unverified": 4}
TRUST_INV = {v: k for k, v in TRUST.items()}

CUSTODY = 20          # custody record for migrated objects, see below
# custody = {1: original_version, 2: claimed_author_key_id,
#            3: migrated_at, 4: proven_author_key_id (absent = NOT proven)}
# The record is inside the signed payload: only the vault owner can write it,
# and by writing it the owner vouches for what it says.
KNOWN_PAYLOAD_KEYS = {1, 2, 3, 4, 5, 6, 7, CUSTODY}


class SignatureError(ValueError):
    """The object failed an authenticity check. Never return content."""


def _cose_decode(cls, data: bytes):
    """Compat shim: cbor2>=5.5 (tuple/frozendict) with pycose."""
    t = cbor2.loads(data)
    obj = [dict(x) if type(x).__name__ == "frozendict" else x for x in t.value]
    return cls.from_cose_obj(obj, True)


def envelope_aad(version: int, oid: bytes, scope_id: bytes) -> bytes:
    """Canonical binding of the cleartext envelope, fed to sign and AEAD."""
    return cbor2.dumps([version, oid, scope_id], canonical=True)


def key_id(sign_pub: bytes) -> bytes:
    return hashlib.sha256(sign_pub).digest()[:8]


def _check_confidence(c) -> float:
    c = float(c)
    if math.isnan(c) or math.isinf(c) or not (0.0 <= c <= 1.0):
        raise ValueError(f"confidence out of range [0.0, 1.0]: {c!r}")
    return c


@dataclass
class MemoryObject:
    content: str
    mem_type: str = "semantic"            # episodic | semantic | procedural
    confidence: float = 0.8
    tags: list[str] = field(default_factory=list)
    tool: str = "amem-cli/0.2"
    created: int = 0                       # epoch; 0 = now
    object_id: bytes = b""                 # 16B; empty = random
    extensions: dict | None = None         # preserved verbatim
    custody: dict | None = None            # set ONLY by migrate/quarantine

    def payload_map(self, author_key_id: bytes) -> dict:
        if self.mem_type not in TYPE:
            raise ValueError(f"unknown mem_type {self.mem_type!r}")
        if not isinstance(self.content, str) or not self.content:
            raise ValueError("content must be a non-empty string")
        m = {
            1: TYPE[self.mem_type],
            2: self.content,
            3: _check_confidence(self.confidence),
            4: {1: self.tool, 2: author_key_id},
            5: TRUST["self"],              # informational; trust is derived
            7: {1: self.created or int(_time.time())},
        }
        if self.tags:
            m[6] = [str(t) for t in self.tags]
        if self.custody:
            m[CUSTODY] = self.custody
        if self.extensions:
            for k, v in self.extensions.items():   # preserve unknown fields
                if k not in KNOWN_PAYLOAD_KEYS:
                    m[k] = v
        return m


def seal(obj: MemoryObject, identity: Identity, scope_id: bytes,
         dek: bytes, _nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """-> (sealed_object_cbor, object_id). Always writes format_version 2."""
    oid = obj.object_id or os.urandom(16)
    akid = key_id(identity.sign_pub)
    aad = envelope_aad(FORMAT_VERSION, oid, scope_id)
    payload = cbor2.dumps(obj.payload_map(akid), canonical=True)

    s = Sign1Message(phdr={Algorithm: EdDSA, KID: akid}, payload=payload)
    s.key = OKPKey(crv=Ed25519, d=identity.sign_seed)
    s.external_aad = aad
    signed = s.encode()

    e = Enc0Message(phdr={Algorithm: A256GCM},
                    uhdr={IV: _nonce or os.urandom(12)}, payload=signed)
    e.key = SymmetricKey(k=dek)
    e.external_aad = aad
    sealed = {1: oid, 2: scope_id, 3: FORMAT_VERSION, 4: e.encode()}
    return cbor2.dumps(sealed, canonical=True), oid


def open_sealed(sealed_cbor: bytes, dek: bytes, *,
                owner_sign_pub: bytes | None = None,
                known_keys: dict[bytes, bytes] | None = None,
                allow_unverified: bool = False) -> dict:
    """Decrypt, authenticate, and decode a sealed object.

    owner_sign_pub : the vault owner's Ed25519 public key -> trust "self".
    known_keys     : {key_id: sign_pub} of accepted third parties -> "trusted".
    allow_unverified: explicit opt-in to read an object we cannot authenticate;
                      the result is marked trust="unverified".

    Raises SignatureError on any authenticity failure. Fail-closed by default.
    """
    sealed = cbor2.loads(sealed_cbor)
    if not isinstance(sealed, dict) or not {1, 2, 3, 4} <= set(sealed):
        raise ValueError("malformed sealed-object")
    oid, scope_id, ver = sealed[1], sealed[2], sealed[3]
    if ver not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported format_version {ver}")

    aad = envelope_aad(ver, oid, scope_id) if ver >= 2 else b""

    enc = _cose_decode(Enc0Message, sealed[4])
    enc.key = SymmetricKey(k=dek)
    enc.external_aad = aad
    inner = _cose_decode(Sign1Message, enc.decrypt())   # AEAD covers the AAD
    inner.external_aad = aad

    p = cbor2.loads(inner.payload)
    if not isinstance(p, dict):
        raise ValueError("malformed payload")
    claimed_kid = p.get(4, {}).get(2)

    # ---- authenticate -------------------------------------------------
    candidates: list[tuple[bytes, str]] = []
    if owner_sign_pub is not None:
        candidates.append((owner_sign_pub, "self"))
    for kid, pub in (known_keys or {}).items():
        candidates.append((pub, "trusted"))

    verified_pub = None
    derived_trust = "unverified"
    if ver >= 2:
        for pub, level in candidates:
            if key_id(pub) != claimed_kid:
                continue                      # author binding: kid must match
            inner.key = OKPKey(crv=Ed25519, x=pub)
            if inner.verify_signature():
                verified_pub, derived_trust = pub, level
                break
        if verified_pub is None and not allow_unverified:
            raise SignatureError(
                "object not authenticated: no known key matches its author_key_id "
                "or the signature is invalid")
    elif not allow_unverified:
        raise SignatureError(
            "format_version 1 objects carry no envelope/author binding and "
            "cannot be authenticated; re-seal with `amem migrate` or pass "
            "allow_unverified=True to read them as untrusted")

    # ---- custody overrides trust --------------------------------------
    # A custody record means: the owner re-sealed content whose authorship it
    # could NOT prove. The signature is genuine, the authorship is not. Trust
    # must never be "self" for such an object, no matter who signed it.
    custody = p.get(CUSTODY)
    if custody is not None:
        # Re-sealing changes the signer, so the signature proves custody, not
        # authorship. Authorship comes from what was PROVEN at migration time:
        #   proven under a key we still accept -> "trusted"
        #   not proven                          -> "unverified"
        # Never "self": the owner did not author this object.
        proven = custody.get(4)
        accepted = set(known_keys or {})
        if owner_sign_pub is not None:
            accepted.add(key_id(owner_sign_pub))
        derived_trust = "trusted" if (proven and proven in accepted) else "unverified"

    # ---- decode (preserving unknown fields) ---------------------------
    out = {
        "id": oid.hex(),
        "scope_id": scope_id.hex(),
        "format_version": ver,
        "type": TYPE_INV.get(p.get(1), p.get(1)),
        "content": p.get(2),
        "confidence": p.get(3),
        "provenance": _provenance(p, claimed_kid, custody),
        "trust": derived_trust,
        "claimed_trust": TRUST_INV.get(p.get(5), p.get(5)),
        "tags": list(p.get(6, [])),
        "created": p.get(7, {}).get(1),
        "signature_verified": verified_pub is not None,
        "custody": ({"original_version": custody.get(1),
                     "claimed_author_key_id": (custody.get(2) or b"").hex() or None,
                     "migrated_at": custody.get(3),
                     "proven_author_key_id": (custody.get(4) or b"").hex() or None}
                    if custody else None),
        "extensions": {k: v for k, v in p.items() if k not in KNOWN_PAYLOAD_KEYS},
        "_payload": inner.payload,          # verbatim, for lossless re-encoding
    }
    try:
        out["confidence"] = _check_confidence(out["confidence"])
    except (TypeError, ValueError):
        out["confidence"] = None
        out["schema_violation"] = "confidence out of range"
    return out


def _provenance(p: dict, signer_kid: bytes | None, custody: dict | None) -> dict:
    """Who signed it, who wrote it, and how well we know.

    For a re-sealed (migrated) object the signer is the custodian, not the
    author. Reporting the custodian as the author would misattribute a third
    party's memory to the vault owner, so the two are kept separate:

      authorship = "signed"   the signer IS the author (normal objects)
                 = "attested" the custodian proved another author at migration
                 = "unknown"  authorship could not be proven; do not attribute
    """
    signer = signer_kid.hex() if signer_kid else None
    prov = {"tool": p.get(4, {}).get(1), "signer_key_id": signer}
    if custody is None:
        prov["author_key_id"] = signer
        prov["authorship"] = "signed"
        return prov
    proven = custody.get(4)
    if proven:
        prov["author_key_id"] = proven.hex()
        prov["authorship"] = "attested"
    else:
        prov["author_key_id"] = None
        prov["authorship"] = "unknown"
        prov["claimed_author_key_id"] = (custody.get(2) or b"").hex() or None
    return prov


def verify_legacy_author(sealed_cbor: bytes, dek: bytes,
                         candidates: dict[bytes, bytes]) -> bytes | None:
    """Migration-only: prove who authored a format_version 1 object.

    v1 has no envelope binding, so this proves authorship of the CONTENT only,
    not of the (id, scope_id) placement: an adversary with write access could
    have relocated a genuine object to another scope. That residual risk is
    accepted for migration and disappears once the object is re-sealed as v2.
    Returns the verifying public key, or None.
    """
    sealed = cbor2.loads(sealed_cbor)
    if sealed[3] != 1:
        return None
    enc = _cose_decode(Enc0Message, sealed[4])
    enc.key = SymmetricKey(k=dek)
    enc.external_aad = b""
    inner = _cose_decode(Sign1Message, enc.decrypt())
    inner.external_aad = b""
    claimed = cbor2.loads(inner.payload).get(4, {}).get(2)
    for pub in candidates.values():
        if key_id(pub) != claimed:
            continue
        inner.key = OKPKey(crv=Ed25519, x=pub)
        if inner.verify_signature():
            return pub
    return None
