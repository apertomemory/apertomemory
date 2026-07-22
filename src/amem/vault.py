"""ApertoMemory v0.1 — local vault and .amem export/import.

Layout vault (directory):
  vault.cbor    — {salt, sign_pub, ka_pub, scopes:{name:{scope_id, kek_wrapped, eph_pub}}}
  objects/<id_hex>.bin  — sealed-object CBOR
  objects/<id_hex>.dek  — DEK avvolta sotto la KEK dello scope (40B)

The vault NEVER contains cleartext keys: everything re-derives from the passphrase.
Export .amem: CBOR {1: version, 2: vault-pubblico, 3: [oggetti], 4: {id: dek_wrapped}}
— everything is already encrypted/wrapped, the file is safe by construction.
"""
from __future__ import annotations
import os
import time as _time
from pathlib import Path
import cbor2

from . import keys as K
from .objects import (MemoryObject, seal, open_sealed, SignatureError,
                      FORMAT_VERSION, key_id, verify_legacy_author)

EXPORT_VERSION = 1


class Vault:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.meta_path = self.path / "vault.cbor"
        self.obj_dir = self.path / "objects"

    # ---------------- lifecycle ----------------
    @classmethod
    def init(cls, path: str | Path, passphrase: str) -> "Vault":
        v = cls(path)
        if v.meta_path.exists():
            raise FileExistsError(f"vault already exists at {v.path}")
        v.obj_dir.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        ident = K.Identity.from_master(K.master_from_passphrase(passphrase, salt))
        meta = {"salt": salt, "sign_pub": ident.sign_pub,
                "ka_pub": ident.ka_pub, "scopes": {}}
        v._write_meta(meta)
        return v

    def unlock(self, passphrase: str) -> K.Identity:
        meta = self._meta()
        ident = K.Identity.from_master(
            K.master_from_passphrase(passphrase, meta["salt"]))
        if ident.sign_pub != meta["sign_pub"]:
            raise ValueError("wrong passphrase")
        return ident

    # ---------------- scopes ----------------
    def add_scope(self, name: str, passphrase: str) -> bytes:
        meta = self._meta()
        if name in meta["scopes"]:
            raise ValueError(f"scope '{name}' already exists")
        ident = self.unlock(passphrase)
        scope_id = os.urandom(16)
        kek = K.new_scope_kek()
        kek_wrapped, eph_pub = K.wrap_kek(kek, ident.ka_pub, scope_id)
        meta["scopes"][name] = {"scope_id": scope_id,
                                "kek_wrapped": kek_wrapped, "eph_pub": eph_pub}
        self._write_meta(meta)
        return scope_id

    def scope_kek(self, name: str, ident: K.Identity) -> tuple[bytes, bytes]:
        s = self._meta()["scopes"][name]
        kek = K.unwrap_kek(s["kek_wrapped"], s["eph_pub"], s["scope_id"], ident)
        return kek, s["scope_id"]

    # ---------------- objects ----------------
    def seal_object(self, obj: MemoryObject, scope: str, passphrase: str) -> str:
        ident = self.unlock(passphrase)
        kek, scope_id = self.scope_kek(scope, ident)
        dek = K.new_dek()
        sealed, oid = seal(obj, ident, scope_id, dek)
        (self.obj_dir / f"{oid.hex()}.bin").write_bytes(sealed)
        (self.obj_dir / f"{oid.hex()}.dek").write_bytes(K.wrap_dek(dek, kek))
        return oid.hex()

    def _dek_for(self, oid_hex: str, ident: K.Identity):
        sealed = (self.obj_dir / f"{oid_hex}.bin").read_bytes()
        scope = self._scope_by_id(cbor2.loads(sealed)[2])
        kek, _ = self.scope_kek(scope, ident)
        return K.unwrap_dek((self.obj_dir / f"{oid_hex}.dek").read_bytes(), kek), scope

    def open_object(self, oid_hex: str, passphrase: str, *,
                    allow_unverified: bool = False) -> dict:
        ident = self.unlock(passphrase)
        sealed = (self.obj_dir / f"{oid_hex}.bin").read_bytes()
        dek, scope = self._dek_for(oid_hex, ident)
        out = open_sealed(sealed, dek, owner_sign_pub=ident.sign_pub,
                          known_keys=self.known_keys(),
                          allow_unverified=allow_unverified)
        out["scope"] = scope
        return out

    def open_all(self, passphrase: str, *, allow_unverified: bool = False
                 ) -> tuple[list[dict], list[tuple[str, str]]]:
        """Open every object, isolating failures. -> (objects, [(id, error)]).

        One hostile or corrupt object must never take down the whole recall.
        """
        ident = self.unlock(passphrase)
        ok, bad = [], []
        for oid in self.list_objects():
            try:
                ok.append(self.open_object(oid, passphrase,
                                           allow_unverified=allow_unverified))
            except Exception as e:                    # noqa: BLE001 - isolation
                bad.append((oid, f"{type(e).__name__}: {e}"))
        return ok, bad

    def known_keys(self) -> dict[bytes, bytes]:
        """{key_id: sign_pub} of accepted third-party authors."""
        return {bytes.fromhex(k): v
                for k, v in dict(self._meta().get("known_keys", {})).items()}

    def trust_key(self, sign_pub: bytes, passphrase: str) -> str:
        """Accept a third-party author key (enables trust='trusted')."""
        self.unlock(passphrase)
        meta = self._meta()
        kk = dict(meta.get("known_keys", {}))
        kk[key_id(sign_pub).hex()] = sign_pub
        meta["known_keys"] = kk
        self._write_meta(meta)
        return key_id(sign_pub).hex()

    def migrate(self, passphrase: str, *, quarantine: bool = False
                ) -> dict:
        """Re-seal format_version 1 objects as v2.

        Migration is a TRANSFER OF TRUST, not a format conversion: re-sealing
        changes the signer, so an object may only keep trust="self" if its
        original signature actually verifies under the owner's key. Objects
        whose authorship cannot be proven are LEFT UNTOUCHED and reported;
        with quarantine=True they are re-sealed carrying a custody record,
        which permanently prevents them from being trusted as "self".

        Each object is handled in isolation and written atomically.
        -> {"migrated": n, "quarantined": n, "refused": [(id, reason)],
            "failed": [(id, error)], "already_v2": n}
        """
        ident = self.unlock(passphrase)
        keyring = self.known_keys()
        res = {"migrated": 0, "attributed": 0, "quarantined": 0,
               "refused": [], "failed": [], "already_v2": 0}

        for oid in self.list_objects():
            try:
                path = self.obj_dir / f"{oid}.bin"
                sealed = path.read_bytes()
                if cbor2.loads(sealed)[3] >= FORMAT_VERSION:
                    res["already_v2"] += 1
                    continue
                dek, scope = self._dek_for(oid, ident)

                # Can we PROVE who wrote it? Only the owner's own objects may
                # keep trust="self" after re-sealing under the owner's key.
                # Prove authorship against the owner key AND the keyring.
                candidates = {**keyring, key_id(ident.sign_pub): ident.sign_pub}
                verifier = verify_legacy_author(sealed, dek, candidates)
                proven = verifier is not None
                mine = proven and verifier == ident.sign_pub

                old = open_sealed(sealed, dek, owner_sign_pub=ident.sign_pub,
                                  known_keys=keyring, allow_unverified=True)
                if not mine and not proven and not quarantine:
                    res["refused"].append(
                        (oid, "authorship not provable; re-run with "
                              "quarantine=True to keep it as untrusted"))
                    continue

                # Only the owner's OWN objects survive re-sealing without a
                # custody record: for anything else, re-signing would silently
                # transfer authorship to the owner.
                custody = None
                if not mine:
                    claimed = old["provenance"]["author_key_id"]
                    custody = {1: old["format_version"],
                               2: bytes.fromhex(claimed) if claimed else b"",
                               3: int(_time.time())}
                    if proven:
                        custody[4] = key_id(verifier)
                obj = MemoryObject(
                    content=old["content"], mem_type=old["type"],
                    confidence=old["confidence"] if old["confidence"] is not None else 0.8,
                    tags=old["tags"], tool=old["provenance"]["tool"] or "amem",
                    created=old["created"] or 0,
                    object_id=bytes.fromhex(old["id"]),
                    extensions=old["extensions"], custody=custody)
                _, scope_id = self.scope_kek(scope, ident)
                new_sealed, _ = seal(obj, ident, scope_id, dek)

                tmp = path.with_suffix(".bin.tmp")      # atomico per oggetto
                tmp.write_bytes(new_sealed)
                os.replace(tmp, path)
                if mine:
                    res["migrated"] += 1
                elif proven:
                    res["attributed"] += 1
                else:
                    res["quarantined"] += 1
            except Exception as e:                       # isolamento per oggetto
                res["failed"].append((oid, f"{type(e).__name__}: {e}"))
        return res

    def list_objects(self) -> list[str]:
        return sorted(p.stem for p in self.obj_dir.glob("*.bin"))

    # ---------------- export ----------------
    def export(self, out_path: str | Path) -> int:
        meta = self._meta()
        objs, deks = [], {}
        for oid in self.list_objects():
            objs.append((self.obj_dir / f"{oid}.bin").read_bytes())
            deks[bytes.fromhex(oid)] = (self.obj_dir / f"{oid}.dek").read_bytes()
        blob = cbor2.dumps({1: EXPORT_VERSION, 2: meta, 3: objs, 4: deks},
                           canonical=True)
        Path(out_path).write_bytes(blob)
        return len(objs)

    # ------------- import: ONE hardened implementation -------------
    @staticmethod
    def _read_export(amem_path: str | Path) -> tuple[dict, list, dict]:
        try:
            data = cbor2.loads(Path(amem_path).read_bytes())
            if not isinstance(data, dict) or data.get(1) != EXPORT_VERSION:
                raise ValueError("unsupported or malformed .amem export")
            src_meta = dict(data[2])
            for k in ("salt", "sign_pub", "ka_pub", "scopes"):
                if k not in src_meta:
                    raise ValueError(f"malformed .amem: missing {k!r}")
            src_meta["scopes"] = {k: dict(x)
                                  for k, x in dict(src_meta["scopes"]).items()}
            return src_meta, list(data[3]), dict(data[4])
        except ValueError:
            raise
        except Exception as e:                       # corrupt file -> clean error
            raise ValueError(f"corrupt .amem file: {type(e).__name__}") from e

    def import_file_into(self, amem_path: str | Path, passphrase: str) -> int:
        """Import an .amem into THIS vault. Returns objects added.

        fresh vault   -> adopt the file identity ("new device"), passphrase first
        same identity -> merge; scopes are added, never overwritten
        other identity-> refused (cross-identity needs KEK re-wrapping)
        Nothing is written until every check has passed.
        """
        src_meta, objs, deks = self._read_export(amem_path)

        src_ident = K.Identity.from_master(
            K.master_from_passphrase(passphrase, src_meta["salt"]))
        if src_ident.sign_pub != src_meta["sign_pub"]:
            raise ValueError("wrong passphrase for this .amem file")

        if self.meta_path.exists():
            meta = self._meta()
            if meta["sign_pub"] != src_meta["sign_pub"]:
                raise ValueError(
                    "import refused: this file belongs to a different identity "
                    "(v0.2 imports your own memory only; cross-identity import "
                    "requires KEK re-wrapping)")
            for name, sc in src_meta["scopes"].items():
                meta["scopes"].setdefault(name, sc)      # never overwrite
        else:
            meta = src_meta                               # new-device flow

        known = {sc["scope_id"] for sc in meta["scopes"].values()}
        for sealed in objs:
            o = cbor2.loads(sealed)
            if not isinstance(o, dict) or not {1, 2, 3, 4} <= set(o):
                raise ValueError("corrupt .amem: malformed sealed-object")
            if o[2] not in known:
                raise ValueError("corrupt .amem: object in an unknown scope")

        self.obj_dir.mkdir(parents=True, exist_ok=True)
        self._write_meta(meta)
        n = 0
        for sealed in objs:
            oid = cbor2.loads(sealed)[1].hex()
            dest = self.obj_dir / f"{oid}.bin"
            if dest.exists():
                continue
            dest.write_bytes(sealed)
            n += 1
        for oid, dw in deks.items():
            dp = self.obj_dir / f"{oid.hex()}.dek"
            if not dp.exists():
                dp.write_bytes(dw)
        return n

    @classmethod
    def import_file(cls, amem_path: str | Path, dest: str | Path,
                    passphrase: str) -> "Vault":
        v = cls(dest)
        v.import_file_into(amem_path, passphrase)
        return v

    # ---------------- internals ----------------
    def _meta(self) -> dict:
        m = cbor2.loads(self.meta_path.read_bytes())
        m["scopes"] = {k: dict(v) for k, v in dict(m["scopes"]).items()}
        return dict(m)

    def _write_meta(self, meta: dict) -> None:
        self.meta_path.write_bytes(cbor2.dumps(meta, canonical=True))

    def _scope_by_id(self, scope_id: bytes) -> str:
        for name, s in self._meta()["scopes"].items():
            if s["scope_id"] == scope_id:
                return name
        raise KeyError("unknown scope for this object")
