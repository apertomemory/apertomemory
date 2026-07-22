"""Revisione rev4 — chiusura di L2 (provenance a tre campi) e attacco al nuovo
campo `authorship` (signed / attested / unknown) e a `signer_key_id`.

Convenzione:
  test_OK_...  -> difesa che deve reggere (PASSA su rev4).
  test_Lx_...  -> problema dimostrato (FALLISCE su rev4).

Esegui:  python3 -m pytest tests/test_security_review_v5.py -v
"""
from __future__ import annotations
import os
import sys
import tempfile
import shutil
import cbor2
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from amem import keys as K, Vault
from amem.objects import (MemoryObject, seal, open_sealed, SignatureError,
                          envelope_aad, key_id, CUSTODY)

from pycose.messages import Sign1Message, Enc0Message
from pycose.keys import OKPKey, SymmetricKey
from pycose.keys.curves import Ed25519
from pycose.algorithms import EdDSA, A256GCM
from pycose.headers import Algorithm, IV, KID


def idn(pw, salt):
    return K.Identity.from_master(K.master_from_passphrase(pw, salt))


def v1_object(*, signer, dek, scope_id, content, oid=None):
    oid = oid or os.urandom(16)
    pm = {1: 2, 2: content, 3: 0.9, 4: {1: "amem", 2: key_id(signer.sign_pub)},
          5: 1, 7: {1: 1}}
    s = Sign1Message(phdr={Algorithm: EdDSA, KID: key_id(signer.sign_pub)},
                     payload=cbor2.dumps(pm, canonical=True))
    s.key = OKPKey(crv=Ed25519, d=signer.sign_seed)
    e = Enc0Message(phdr={Algorithm: A256GCM},
                    uhdr={IV: os.urandom(12)}, payload=s.encode())
    e.key = SymmetricKey(k=dek)
    return oid, cbor2.dumps({1: oid, 2: scope_id, 3: 1, 4: e.encode()},
                            canonical=True)


def v2_raw(*, signer, dek, scope_id, payload_map, oid=None):
    oid = oid or os.urandom(16)
    aad = envelope_aad(2, oid, scope_id)
    s = Sign1Message(phdr={Algorithm: EdDSA, KID: key_id(signer.sign_pub)},
                     payload=cbor2.dumps(payload_map, canonical=True))
    s.key = OKPKey(crv=Ed25519, d=signer.sign_seed); s.external_aad = aad
    e = Enc0Message(phdr={Algorithm: A256GCM},
                    uhdr={IV: os.urandom(12)}, payload=s.encode())
    e.key = SymmetricKey(k=dek); e.external_aad = aad
    return oid, cbor2.dumps({1: oid, 2: scope_id, 3: 2, 4: e.encode()},
                            canonical=True)


def _deposit_v1(v, kek, sid, signer, content):
    dek = K.new_dek()
    oid, sealed = v1_object(signer=signer, dek=dek, scope_id=sid, content=content)
    (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
    (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))
    return oid.hex()


# ==========================================================================
# OK1 (era L2) — provenance a tre campi: un oggetto normale del proprietario
#   e' "signed" con author == signer == owner.
# ==========================================================================
def test_OK_normal_object_is_signed_by_author():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        dek = K.new_dek()
        sealed, oid = seal(MemoryObject(content="my own"), me, sid, dek)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        p = v.open_object(oid.hex(), "pw")["provenance"]
        assert p["authorship"] == "signed"
        assert p["author_key_id"] == key_id(me.sign_pub).hex()
        assert p["signer_key_id"] == key_id(me.sign_pub).hex()
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK2 (era L2) — un oggetto di terzo fidato MIGRATO e' "attested": author =
#   vero autore (amico), signer = custode (proprietario). L'autore reale NON e'
#   piu' fuso col proprietario (il difetto L2 e' chiuso).
# ==========================================================================
def test_OK_migrated_third_party_is_attested_to_real_author():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        oid = _deposit_v1(v, kek, sid, friend, "friend's note")

        v.migrate("pw")
        p = v.open_object(oid, "pw")["provenance"]
        assert p["authorship"] == "attested"
        assert p["author_key_id"] == key_id(friend.sign_pub).hex(), (
            "autore reale non attribuito all'amico"
        )
        assert p["signer_key_id"] == key_id(me.sign_pub).hex()
        # il proprietario NON e' mai indicato come autore
        assert p["author_key_id"] != key_id(me.sign_pub).hex()
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK3 — un consumatore che legge SOLO author_key_id non e' fuorviato: per un
#   oggetto la cui paternita' non e' provata (quarantena) author_key_id e' None,
#   authorship = "unknown". Nessuna falsa attribuzione.
# ==========================================================================
def test_OK_unprovable_object_reports_no_author():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        atk = idn("attacker", b"a" * 16)
        oid = _deposit_v1(v, kek, sid, atk, "evil")

        v.migrate("pw", quarantine=True)
        p = v.open_object(oid, "pw")["provenance"]
        assert p["authorship"] == "unknown"
        assert p["author_key_id"] is None, (
            "un oggetto non provato riporta comunque un autore: "
            f"{p['author_key_id']}"
        )
        # il vero firmatario ostile NON e' promosso ad autore
        assert p.get("author_key_id") != key_id(atk.sign_pub).hex()
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK4 — 'attested' non e' forgiabile da un attaccante SENZA chiavi accettate.
#   Firma con la propria chiave (fuori keyring), custody[4]=amico -> respinto
#   in verifica: non arriva mai a calcolare authorship.
# ==========================================================================
def test_OK_attested_not_forgeable_by_untrusted_signer():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        attacker = idn("attacker", b"a" * 16)   # NON accettato

        dek = K.new_dek()
        pm = {1: 2, 2: "evil attested as friend", 3: 0.9,
              4: {1: "x", 2: key_id(attacker.sign_pub)}, 5: 1, 7: {1: 1},
              CUSTODY: {1: 1, 2: key_id(attacker.sign_pub), 3: 0,
                        4: key_id(friend.sign_pub)}}
        oid, sealed = v2_raw(signer=attacker, dek=dek, scope_id=sid,
                             payload_map=pm)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        with pytest.raises(SignatureError):
            v.open_object(oid.hex(), "pw")
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK5 — 'signed' implica sempre signer == author. Non esiste percorso in cui
#   authorship="signed" ma il firmatario non sia l'autore (custody assente =>
#   author copiato dal signer). Verificato per l'oggetto di un terzo fidato
#   che firma un oggetto v2 NORMALE (senza custody): e' "signed" e author=lui.
# ==========================================================================
def test_OK_signed_always_means_signer_is_author():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")

        dek = K.new_dek()
        sealed, oid = seal(MemoryObject(content="friend v2 diretto"), friend,
                           sid, dek)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        p = v.open_object(oid.hex(), "pw")["provenance"]
        assert p["authorship"] == "signed"
        assert p["author_key_id"] == p["signer_key_id"] == key_id(friend.sign_pub).hex()
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK6 — reachability: un terzo fidato SENZA la passphrase non puo' piazzare un
#   oggetto decifrabile (serve la KEK dello scope). Quindi gli scenari Q3b/Q3d
#   (forgiare authorship a piacere) non sono raggiungibili da chi non ha gia'
#   le chiavi del proprietario.
# ==========================================================================
def test_OK_third_party_cannot_derive_scope_kek():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw")
        sc = v._meta()["scopes"]["default"]
        friend = idn("friend", b"f" * 16)
        with pytest.raises(Exception):
            K.unwrap_kek(sc["kek_wrapped"], sc["eph_pub"], sc["scope_id"], friend)
    finally:
        shutil.rmtree(d)
