"""ApertoMemory v0.1 — Memory Object seal/open (spec §3-§4, CDDL amem-schema).

sealed-object: {1: id, 2: scope_id, 3: version, 4: COSE_Encrypt0(COSE_Sign1(payload))}
Sign-then-encrypt: the signature lives inside the ciphertext (the server never
sees authorship). AEAD MTI: AES-256-GCM (COSE alg 3). Serialisation: canonical
CBOR (RFC 8949 §4.2).
"""
from __future__ import annotations
import os, time as _time
from dataclasses import dataclass, field
import cbor2
from pycose.messages import Sign1Message, Enc0Message
from pycose.keys import OKPKey, SymmetricKey
from pycose.keys.curves import Ed25519
from pycose.algorithms import EdDSA, A256GCM
from pycose.headers import Algorithm, IV, KID

from .keys import Identity

FORMAT_VERSION = 1
TYPE = {"episodic": 1, "semantic": 2, "procedural": 3}
TYPE_INV = {v: k for k, v in TYPE.items()}
TRUST = {"self": 1, "trusted": 2, "third-party": 3, "unverified": 4}
TRUST_INV = {v: k for k, v in TRUST.items()}


def _cose_decode(cls, data: bytes):
    """Compat shim: cbor2>=5.5 (tuple/frozendict) with pycose."""
    t = cbor2.loads(data)
    obj = [dict(x) if type(x).__name__ == "frozendict" else x for x in t.value]
    return cls.from_cose_obj(obj, True)


@dataclass
class MemoryObject:
    content: str
    mem_type: str = "semantic"            # episodic | semantic | procedural
    confidence: float = 0.8
    trust: str = "self"
    tags: list[str] = field(default_factory=list)
    tool: str = "amem-cli/0.1"
    created: int = 0                       # epoch; 0 = now
    object_id: bytes = b""                 # 16B; empty = random

    def payload_map(self, author_key_id: bytes) -> dict:
        m = {
            1: TYPE[self.mem_type],
            2: self.content,
            3: float(self.confidence),
            4: {1: self.tool, 2: author_key_id},
            5: TRUST[self.trust],
            7: {1: self.created or int(_time.time())},
        }
        if self.tags:
            m[6] = list(self.tags)
        return m


def seal(obj: MemoryObject, identity: Identity, scope_id: bytes,
         dek: bytes, _nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """-> (sealed_object_cbor, object_id)"""
    oid = obj.object_id or os.urandom(16)
    payload = cbor2.dumps(obj.payload_map(identity.author_key_id), canonical=True)

    s = Sign1Message(phdr={Algorithm: EdDSA, KID: identity.author_key_id},
                     payload=payload)
    s.key = OKPKey(crv=Ed25519, d=identity.sign_seed)
    signed = s.encode()

    e = Enc0Message(phdr={Algorithm: A256GCM},
                    uhdr={IV: _nonce or os.urandom(12)}, payload=signed)
    e.key = SymmetricKey(k=dek)
    sealed = {1: oid, 2: scope_id, 3: FORMAT_VERSION, 4: e.encode()}
    return cbor2.dumps(sealed, canonical=True), oid


def open_sealed(sealed_cbor: bytes, dek: bytes,
                expected_sign_pub: bytes | None = None) -> dict:
    """Decrypt, verify the signature, return the decoded payload.
    If expected_sign_pub is given, the signature MUST verify with that key."""
    sealed = cbor2.loads(sealed_cbor)
    if sealed[3] != FORMAT_VERSION:
        raise ValueError(f"unsupported format_version {sealed[3]}")
    enc = _cose_decode(Enc0Message, sealed[4])
    enc.key = SymmetricKey(k=dek)
    inner = _cose_decode(Sign1Message, enc.decrypt())

    verified = False
    if expected_sign_pub is not None:
        inner.key = OKPKey(crv=Ed25519, x=expected_sign_pub)
        if not inner.verify_signature():
            raise ValueError("invalid signature: possible tampering")
        verified = True

    p = cbor2.loads(inner.payload)
    return {
        "id": sealed[1].hex(),
        "scope_id": sealed[2].hex(),
        "type": TYPE_INV.get(p[1], p[1]),
        "content": p[2],
        "confidence": p[3],
        "provenance": {"tool": p[4][1], "author_key_id": p[4][2].hex()},
        "trust": TRUST_INV.get(p[5], p[5]),
        "tags": p.get(6, []),
        "created": p[7][1],
        "signature_verified": verified,
    }
