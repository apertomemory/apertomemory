#!/usr/bin/env python3
"""
ApertoMemory v0.1 — test vector generator (Appendix A).
Implements the full path: passphrase -> keys -> object -> COSE_Sign1 -> COSE_Encrypt0 -> sealed-object CBOR.
COSE_Sign1 signing -> COSE_Encrypt0 encryption -> sealed-object CBOR.
All "random" values are fixed for reproducibility.
"""
import json, hashlib
import cbor2
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pycose.messages import Sign1Message, Enc0Message
from pycose.keys import OKPKey, SymmetricKey
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import OKPKpCurve, OKPKpD, OKPKpX, KpKty, SymKpK
from pycose.keys.keytype import KtyOKP, KtySymmetric
from pycose.algorithms import EdDSA, A256GCM
from pycose.headers import Algorithm, IV, KID

H = lambda b: b.hex()

def cose_decode(cls, data):
    """Compat: cbor2>=5.5 decodes arrays as tuples, pycose expects lists."""
    t = cbor2.loads(data)
    obj = [dict(x) if type(x).__name__ == 'frozendict' else x for x in t.value]
    return cls.from_cose_obj(obj, True)


# ---------------------------------------------------------------- 1. KDF
PASSPHRASE = b"correct horse battery staple"
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")   # fixed for the vector
ARGON = dict(time_cost=3, memory_cost=64 * 1024, parallelism=4)  # RFC 9106 2nd rec.
master_secret = hash_secret_raw(PASSPHRASE, SALT, hash_len=32, type=Type.ID, **ARGON)

def hkdf(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)

ed_seed = hkdf(master_secret, b"apertomemory/v1/sign")
# (X25519 not needed for this vector: fixed DEK/KEK wrap below)

# --------------------------------------------------- 2. COSE signing key
sign_key = OKPKey.generate_key(crv=Ed25519)  # placeholder, replaced by fixed seed:
sign_key = OKPKey(crv=Ed25519, d=ed_seed, optional_params={'KID': b'author01'})
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
pub = Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes_raw()
author_key_id = hashlib.sha256(pub).digest()[:8]

# ------------------------------------------------- 3. Memory payload CBOR
payload = {
    1: 2,                                   # type: semantic
    2: "L'utente preferisce email B2B formali, senza emoji, con bullet point",
    3: 0.9,                                 # confidence
    4: {1: "amem-testvector/0.1", 2: author_key_id},
    5: 1,                                   # trust: self
    6: ["preferences", "communication"],
    7: {1: 1752915600},                     # created: 2026-07-19T09:00:00Z
}
payload_cbor = cbor2.dumps(payload, canonical=True)

# ------------------------------------------------------ 4. COSE_Sign1
msg = Sign1Message(phdr={Algorithm: EdDSA, KID: b'author01'}, payload=payload_cbor)
msg.key = sign_key
signed = msg.encode()

# ------------------------------------------------------ 5. COSE_Encrypt0
DEK = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"
                    "f0e1d2c3b4a5968778695a4b3c2d1e0f")      # fixed for the vector
NONCE = bytes.fromhex("000102030405060708090a0b")            # 96 bit
enc = Enc0Message(phdr={Algorithm: A256GCM}, uhdr={IV: NONCE}, payload=signed)
enc.key = SymmetricKey(k=DEK)
envelope = enc.encode()

# ------------------------------------------------------ 6. sealed-object
sealed = {
    1: bytes.fromhex("a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8"),    # id
    2: bytes.fromhex("c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8"),    # scope_id
    3: 1,                                                     # format_version
    4: envelope,
}
sealed_cbor = cbor2.dumps(sealed, canonical=True)

# ------------------------------------------------------ 7. Round-trip check
back = cbor2.loads(sealed_cbor)
dec = cose_decode(Enc0Message, back[4]); dec.key = SymmetricKey(k=DEK)
inner = cose_decode(Sign1Message, dec.decrypt())
verify_key = OKPKey(crv=Ed25519, x=pub, optional_params={'KID': b'author01'})
inner.key = verify_key
assert inner.verify_signature(), "SIGNATURE NOT VERIFIED"
assert cbor2.loads(inner.payload) == payload, "PAYLOAD MISMATCH"
print("round-trip: encrypt -> decrypt -> verify signature -> payload identical")

# ------------------------------------------------------ 8. Output vectors
vectors = {
  "description": "ApertoMemory v0.1 test vector 001 — semantic memory, trust=self",
  "kdf": {"algorithm": "Argon2id", "params": {"m_KiB": 65536, "t": 3, "p": 4},
          "passphrase": PASSPHRASE.decode(), "salt_hex": H(SALT),
          "master_secret_hex": H(master_secret)},
  "hkdf_info_sign": "apertomemory/v1/sign",
  "ed25519": {"seed_hex": H(ed_seed), "public_hex": H(pub),
              "author_key_id_hex": H(author_key_id)},
  "payload_cbor_hex": H(payload_cbor),
  "cose_sign1_hex": H(signed),
  "dek_hex": H(DEK), "nonce_hex": H(NONCE),
  "cose_encrypt0_hex": H(envelope),
  "sealed_object_cbor_hex": H(sealed_cbor),
  "sizes_bytes": {"payload": len(payload_cbor), "signed": len(signed),
                   "envelope": len(envelope), "sealed": len(sealed_cbor)},
}
with open("amem-testvector-001.json", "w") as f:
    json.dump(vectors, f, indent=2)
print("test vector written: amem-testvector-001.json")
print(json.dumps(vectors["sizes_bytes"]))
