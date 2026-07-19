#!/usr/bin/env python3
"""
ApertoMemory v0.1 — test vector 002: full key hierarchy (spec §6).
passphrase -> master -> X25519 utente
scope KEK (random) --wrap ECDH-ES+HKDF+AES-KW--> per l'utente
object DEK (random) --wrap AES-KW--> sotto la KEK
Full round trip: unwrap KEK -> unwrap DEK -> decrypt the vector-001 object.
"""
import json, hashlib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

H = lambda b: b.hex()

# ---- 1. Master (same parameters and inputs as vector 001)
PASSPHRASE = b"correct horse battery staple"
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
master = hash_secret_raw(PASSPHRASE, SALT, hash_len=32, type=Type.ID,
                         time_cost=3, memory_cost=64*1024, parallelism=4)

def hkdf(ikm, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)

# ---- 2. User X25519 key derived from the master
ka_seed = hkdf(master, b"apertomemory/v1/ka")
user_priv = X25519PrivateKey.from_private_bytes(ka_seed)
user_pub = user_priv.public_key().public_bytes_raw()

# ---- 3. Scope KEK (fixed for the vector) wrapped for the user
KEK = bytes.fromhex("0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"[:64].ljust(64,'0'))
KEK = bytes.fromhex("0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829")  # 32B
eph_seed = bytes.fromhex("4e6f6e63652d66697373612d7065722d746573742d76303032"[:64].ljust(64,'0'))
eph_seed = hashlib.sha256(b"amem-tv002-ephemeral").digest()          # deterministic
eph_priv = X25519PrivateKey.from_private_bytes(eph_seed)
eph_pub = eph_priv.public_key().public_bytes_raw()

shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(user_pub))
# context binding: HKDF info ties protocol, version, scope
scope_id = bytes.fromhex("c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8")        # same as vector 001
wrap_key = hkdf(shared, b"apertomemory/v1/kek-wrap" + scope_id)
kek_wrapped = keywrap.aes_key_wrap(wrap_key, KEK)                    # RFC 3394

# ---- 4. Vector-001 DEK wrapped under the KEK
DEK = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f"*2)
dek_wrapped = keywrap.aes_key_wrap(KEK, DEK)

# ---- 5. Round trip: from the other side, passphrase + blobs only
m2 = hash_secret_raw(PASSPHRASE, SALT, hash_len=32, type=Type.ID,
                     time_cost=3, memory_cost=64*1024, parallelism=4)
priv2 = X25519PrivateKey.from_private_bytes(hkdf(m2, b"apertomemory/v1/ka"))
shared2 = priv2.exchange(X25519PublicKey.from_public_bytes(eph_pub))
kek2 = keywrap.aes_key_unwrap(hkdf(shared2, b"apertomemory/v1/kek-wrap"+scope_id), kek_wrapped)
dek2 = keywrap.aes_key_unwrap(kek2, dek_wrapped)
assert kek2 == KEK and dek2 == DEK
print("key round-trip: passphrase -> master -> X25519 -> unwrap KEK -> unwrap DEK")

# ---- 6. Full chain: decrypt the vector-001 object with the unwrapped DEK
import cbor2
from pycose.messages import Enc0Message, Sign1Message
from pycose.keys import SymmetricKey, OKPKey
from pycose.keys.curves import Ed25519
def cose_decode(cls, data):
    t = cbor2.loads(data)
    obj = [dict(x) if type(x).__name__=='frozendict' else x for x in t.value]
    return cls.from_cose_obj(obj, True)
tv1 = json.load(open("amem-testvector-001.json"))
sealed = cbor2.loads(bytes.fromhex(tv1["sealed_object_cbor_hex"]))
dec = cose_decode(Enc0Message, sealed[4]); dec.key = SymmetricKey(k=dek2)
inner = cose_decode(Sign1Message, dec.decrypt())
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ed_seed = hkdf(m2, b"apertomemory/v1/sign")
pub = Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes_raw()
inner.key = OKPKey(crv=Ed25519, x=pub); assert inner.verify_signature()
print("full chain: passphrase -> ... -> DEK -> object decrypted, signature verified")

# ---- 7. Output
out = {
 "description": "ApertoMemory v0.1 test vector 002 — key hierarchy (spec §6)",
 "hkdf_infos": {"sign":"apertomemory/v1/sign","ka":"apertomemory/v1/ka",
                "kek_wrap":"apertomemory/v1/kek-wrap || scope_id"},
 "x25519": {"user_seed_hex": H(ka_seed), "user_pub_hex": H(user_pub),
            "ephemeral_seed_hex": H(eph_seed), "ephemeral_pub_hex": H(eph_pub)},
 "scope_id_hex": H(scope_id),
 "kek_hex": H(KEK), "kek_wrapped_hex": H(kek_wrapped),
 "dek_hex": H(DEK), "dek_wrapped_hex": H(dek_wrapped),
 "wrap_algorithms": {"kek_under_master": "ECDH-ES(X25519) + HKDF-SHA256 + AES-256-KW (RFC 3394)",
                      "dek_under_kek": "AES-256-KW (RFC 3394)"},
 "sizes_bytes": {"kek_wrapped": len(kek_wrapped), "dek_wrapped": len(dek_wrapped),
                  "ephemeral_pub": len(eph_pub)},
}
json.dump(out, open("amem-testvector-002.json","w"), indent=2)
print("written: amem-testvector-002.json"); print(json.dumps(out["sizes_bytes"]))
