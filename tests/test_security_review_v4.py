"""Revisione rev3 — chiusura di L1 (migrate consulta il keyring) e attacco alla
nuova superficie: custody field 4 (proven_author_key_id) e rivalutazione del
trust in lettura (revoca / keyring vuoto / re-add / sostituzione).

Convenzione:
  test_OK_...  -> difesa che deve reggere (PASSA su rev3).
  test_Lx_...  -> problema dimostrato (FALLISCE su rev3).

Esegui:  python3 -m pytest tests/test_security_review_v4.py -v
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


def idn(pw: str, salt: bytes) -> K.Identity:
    return K.Identity.from_master(K.master_from_passphrase(pw, salt))


def v1_object(*, signer, dek, scope_id, content, claimed_kid=None, oid=None):
    oid = oid or os.urandom(16)
    pm = {1: 2, 2: content, 3: 0.9,
          4: {1: "amem", 2: claimed_kid or key_id(signer.sign_pub)},
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
    """v2 grezzo con external_aad, per iniettare payload arbitrari (custody)."""
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


def _deposit_v1(v, kek, sid, signer, content, claimed_kid=None):
    dek = K.new_dek()
    oid, sealed = v1_object(signer=signer, dek=dek, scope_id=sid,
                            content=content, claimed_kid=claimed_kid)
    (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
    (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))
    return oid.hex()


# ==========================================================================
# OK1 (era L1) — la migrazione consulta il keyring: un oggetto v1 di un terzo
#   FIDATO conserva trust="trusted" dopo la migrazione (contato "attributed").
# ==========================================================================
def test_OK_trusted_third_party_v1_retains_trusted_after_migrate():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        oid = _deposit_v1(v, kek, sid, friend, "consiglio dell'amico")

        res = v.migrate("pw")
        assert res["attributed"] == 1, res
        out = v.open_object(oid, "pw")
        assert out["trust"] == "trusted", f"trust={out['trust']}"
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK2 — RE-ATTRIBUZIONE del TRUST: un oggetto altrui migrato non diventa MAI
#   trust="self", qualunque cosa dica il custody record.
# ==========================================================================
def test_OK_migrated_third_party_never_becomes_self():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        oid = _deposit_v1(v, kek, sid, friend, "roba dell'amico")

        v.migrate("pw")
        out = v.open_object(oid, "pw")
        assert out["trust"] != "self", (
            f"oggetto altrui migrato attribuito come proprio: trust={out['trust']}"
        )
        # il vero autore e' preservato nel custody, non nel signer
        assert out["custody"]["proven_author_key_id"] == key_id(friend.sign_pub).hex()
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK3 — custody[4] FORGIATO: l'attaccante firma con la propria chiave (non nel
#   keyring), dichiara il proprio kid, e mette custody[4]=chiave-fidata.
#   Deve essere respinto (author binding: il signer non e' un candidato accettato
#   per la sua stessa chiave... in realta' passa il binding ma il signer non e'
#   accettato -> unverified/reject). Verifichiamo che NON diventi "trusted".
# ==========================================================================
def test_OK_forged_custody4_does_not_elevate():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        attacker = idn("attacker", b"a" * 16)   # NON nel keyring

        dek = K.new_dek()
        pm = {1: 2, 2: "EVIL elevated", 3: 0.9,
              4: {1: "x", 2: key_id(attacker.sign_pub)}, 5: 1, 7: {1: 1},
              CUSTODY: {1: 1, 2: key_id(attacker.sign_pub), 3: 0,
                        4: key_id(friend.sign_pub)}}       # punta a chiave fidata
        oid, sealed = v2_raw(signer=attacker, dek=dek, scope_id=sid,
                             payload_map=pm)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        # l'attaccante non e' nel keyring: la firma non verifica con nessun
        # candidato accettato -> deve fallire, mai "trusted".
        with pytest.raises(SignatureError):
            v.open_object(oid.hex(), "pw")
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK4 — custody[4] = OWNER: un terzo fidato firma e mette custody[4]=owner.
#   La firma verifica (chiave fidata), quindi e' "trusted"; NON deve diventare
#   "self" solo perche' custody[4] nomina il proprietario.
# ==========================================================================
def test_OK_custody4_naming_owner_does_not_yield_self():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")

        dek = K.new_dek()
        pm = {1: 2, 2: "friend dice: proved by owner", 3: 0.9,
              4: {1: "x", 2: key_id(friend.sign_pub)}, 5: 1, 7: {1: 1},
              CUSTODY: {1: 1, 2: key_id(friend.sign_pub), 3: 0,
                        4: key_id(me.sign_pub)}}           # punta all'owner
        oid, sealed = v2_raw(signer=friend, dek=dek, scope_id=sid,
                             payload_map=pm)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        out = v.open_object(oid.hex(), "pw")
        assert out["trust"] != "self", f"custody[4]=owner ha elevato a self: {out['trust']}"
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK5 — RE-EVALUATION: revoca. Un oggetto di terzo fidato, dopo la rimozione
#   della chiave dal keyring, non e' piu' "trusted": la lettura fallisce
#   (fail-closed) o e' "unverified" con allow_unverified.
# ==========================================================================
def test_OK_revocation_downgrades_trust():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        dek = K.new_dek()
        sealed, oid = seal(MemoryObject(content="friend note"), friend, sid, dek)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))
        assert v.open_object(oid.hex(), "pw")["trust"] == "trusted"

        # revoca
        meta = v._meta(); meta["known_keys"] = {}; v._write_meta(meta)
        with pytest.raises(SignatureError):
            v.open_object(oid.hex(), "pw")
        assert v.open_object(oid.hex(), "pw", allow_unverified=True)["trust"] == "unverified"

        # re-add ripristina
        v.trust_key(friend.sign_pub, "pw")
        assert v.open_object(oid.hex(), "pw")["trust"] == "trusted"
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK6 — RE-EVALUATION: sostituzione di chiave. Mettere una pub DIVERSA sotto il
#   kid hex di un amico (corruzione del keyring da parte di chi ha accesso al
#   file) non fa verificare l'oggetto -> respinto.
# ==========================================================================
def test_OK_key_substitution_is_rejected():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        dek = K.new_dek()
        sealed, oid = seal(MemoryObject(content="friend note"), friend, sid, dek)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))

        evil = idn("evil", b"e" * 16)
        meta = v._meta()
        meta["known_keys"] = {key_id(friend.sign_pub).hex(): evil.sign_pub}
        v._write_meta(meta)
        with pytest.raises(SignatureError):
            v.open_object(oid.hex(), "pw")
    finally:
        shutil.rmtree(d)


# ==========================================================================
# OK7 — RE-EVALUATION: un firmatario REVOCATO non e' resuscitato da custody[4].
#   Amico fidato firma un oggetto v2 con custody[4]=owner. Dopo la revoca
#   dell'amico, l'oggetto non deve piu' verificare (il signer non e' un
#   candidato accettato), anche se custody[4] nomina una chiave ancora accettata.
# ==========================================================================
def test_OK_revoked_signer_not_resurrected_by_custody4():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        dek = K.new_dek()
        pm = {1: 2, 2: "content by friend, custody names owner", 3: 0.9,
              4: {1: "x", 2: key_id(friend.sign_pub)}, 5: 1, 7: {1: 1},
              CUSTODY: {1: 1, 2: key_id(friend.sign_pub), 3: 0,
                        4: key_id(me.sign_pub)}}
        oid, sealed = v2_raw(signer=friend, dek=dek, scope_id=sid, payload_map=pm)
        (v.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (v.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))
        assert v.open_object(oid.hex(), "pw")["trust"] == "trusted"

        meta = v._meta(); meta["known_keys"] = {}; v._write_meta(meta)   # revoca friend
        with pytest.raises(SignatureError):
            v.open_object(oid.hex(), "pw")
    finally:
        shutil.rmtree(d)


# ==========================================================================
# L2 — BASSO: provenance.author_key_id di un oggetto di terzo MIGRATO viene
#   riscritto col kid del PROPRIETARIO (perche' il re-seal cambia il firmatario).
#   Il trust e' corretto ("trusted") e il vero autore e' nel custody, ma il
#   campo provenance.author_key_id — che un consumatore potrebbe leggere da solo
#   — nomina il proprietario, non l'autore reale. Fuorviante, non un bypass.
# ==========================================================================
def test_L2_migrated_provenance_author_is_not_misattributed_to_owner():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v", "pw"); v.add_scope("default", "pw")
        me = v.unlock("pw"); kek, sid = v.scope_kek("default", me)
        friend = idn("friend", b"f" * 16); v.trust_key(friend.sign_pub, "pw")
        oid = _deposit_v1(v, kek, sid, friend, "friend's genuine note")

        v.migrate("pw")
        out = v.open_object(oid, "pw")
        # PROPRIETA' attesa: provenance.author_key_id non deve indicare il
        # proprietario per un contenuto che il proprietario non ha scritto.
        assert out["provenance"]["author_key_id"] != key_id(me.sign_pub).hex(), (
            "provenance.author_key_id riscritto come proprietario per un "
            f"oggetto di terzi (vero autore = {key_id(friend.sign_pub).hex()}, "
            f"custody.proven = {out['custody']['proven_author_key_id']})"
        )
    finally:
        shutil.rmtree(d)
