"""ApertoMemory v0.1 — local vault and .amem export/import.

Layout vault (directory):
  vault.cbor    — {salt, sign_pub, ka_pub, scopes:{name:{scope_id, kek_wrapped, eph_pub}}}
  objects/<id_hex>.bin  — sealed-object CBOR
  objects/<id_hex>.dek  — DEK wrapped under the scope KEK (40B)

The vault NEVER contains cleartext keys: everything re-derives from the passphrase.
Export .amem: CBOR {1: version, 2: vault-pubblico, 3: [oggetti], 4: {id: dek_wrapped}}
— everything is already encrypted/wrapped, the file is safe by construction.
"""
from __future__ import annotations
import os
from pathlib import Path
import cbor2

from . import keys as K
from .objects import MemoryObject, seal, open_sealed

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

    def open_object(self, oid_hex: str, passphrase: str) -> dict:
        ident = self.unlock(passphrase)
        sealed = (self.obj_dir / f"{oid_hex}.bin").read_bytes()
        scope_id = cbor2.loads(sealed)[2]
        scope = self._scope_by_id(scope_id)
        kek, _ = self.scope_kek(scope, ident)
        dek = K.unwrap_dek((self.obj_dir / f"{oid_hex}.dek").read_bytes(), kek)
        out = open_sealed(sealed, dek, expected_sign_pub=ident.sign_pub)
        out["scope"] = scope
        return out

    def list_objects(self) -> list[str]:
        return sorted(p.stem for p in self.obj_dir.glob("*.bin"))

    # ---------------- export / import ----------------
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

    @classmethod
    def import_file(cls, amem_path: str | Path, dest: str | Path,
                    passphrase: str) -> "Vault":
        data = cbor2.loads(Path(amem_path).read_bytes())
        if data[1] != EXPORT_VERSION:
            raise ValueError("unsupported export version")
        v = cls(dest)
        v.obj_dir.mkdir(parents=True, exist_ok=True)
        v._write_meta(dict(data[2]))
        v.unlock(passphrase)  # fail fast if the passphrase is wrong
        for sealed in data[3]:
            oid = cbor2.loads(sealed)[1].hex()
            (v.obj_dir / f"{oid}.bin").write_bytes(sealed)
        for oid, dw in data[4].items():
            (v.obj_dir / f"{oid.hex()}.dek").write_bytes(dw)
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
