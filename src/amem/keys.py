"""ApertoMemory v0.1 — key hierarchy (spec §6, test vectors 001/002).

passphrase --Argon2id(m=64MiB,t=3,p=4)--> master secret (32B)
master --HKDF--> Ed25519 seed (signing) + X25519 seed (key agreement)
scope KEK (32B random) --ECDH-ES+HKDF+AES-KW--> wrapped for the user
object DEK (32B random, single object) --AES-KW--> under the KEK
"""
from __future__ import annotations
import os, hashlib
from dataclasses import dataclass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ARGON2_PARAMS = dict(time_cost=3, memory_cost=64 * 1024, parallelism=4)
INFO_SIGN = b"apertomemory/v1/sign"
INFO_KA = b"apertomemory/v1/ka"
INFO_KEK_WRAP = b"apertomemory/v1/kek-wrap"


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=None, info=info).derive(ikm)


def master_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(passphrase.encode(), salt, hash_len=32,
                           type=Type.ID, **ARGON2_PARAMS)


@dataclass
class Identity:
    """User long-term keys, derived from the master secret."""
    sign_seed: bytes          # Ed25519 private seed
    sign_pub: bytes           # Ed25519 public (32B raw)
    ka_seed: bytes            # X25519 private seed
    ka_pub: bytes             # X25519 public (32B raw)

    @classmethod
    def from_master(cls, master: bytes) -> "Identity":
        ss = _hkdf(master, INFO_SIGN)
        ks = _hkdf(master, INFO_KA)
        sp = Ed25519PrivateKey.from_private_bytes(ss).public_key().public_bytes_raw()
        kp = X25519PrivateKey.from_private_bytes(ks).public_key().public_bytes_raw()
        return cls(sign_seed=ss, sign_pub=sp, ka_seed=ks, ka_pub=kp)

    @property
    def author_key_id(self) -> bytes:
        return hashlib.sha256(self.sign_pub).digest()[:8]


def new_scope_kek() -> bytes:
    return os.urandom(32)


def wrap_kek(kek: bytes, user_ka_pub: bytes, scope_id: bytes,
             _eph_seed: bytes | None = None) -> tuple[bytes, bytes]:
    """KEK -> (kek_wrapped 40B, ephemeral_pub 32B) for the user X25519 key.
    _eph_seed is for deterministic test vectors only."""
    eph = (X25519PrivateKey.from_private_bytes(_eph_seed) if _eph_seed
           else X25519PrivateKey.generate())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(user_ka_pub))
    wk = _hkdf(shared, INFO_KEK_WRAP + scope_id)
    return keywrap.aes_key_wrap(wk, kek), eph.public_key().public_bytes_raw()


def unwrap_kek(kek_wrapped: bytes, eph_pub: bytes, scope_id: bytes,
               identity: Identity) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(identity.ka_seed)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    wk = _hkdf(shared, INFO_KEK_WRAP + scope_id)
    return keywrap.aes_key_unwrap(wk, kek_wrapped)


def new_dek() -> bytes:
    return os.urandom(32)


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    return keywrap.aes_key_wrap(kek, dek)


def unwrap_dek(dek_wrapped: bytes, kek: bytes) -> bytes:
    return keywrap.aes_key_unwrap(kek, dek_wrapped)
