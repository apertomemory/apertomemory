import subprocess, sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from amem import Vault, MemoryObject

def test_full_cycle():
    d = tempfile.mkdtemp()
    try:
        v = Vault.init(f"{d}/v1", "test-passphrase")
        v.add_scope("work", "test-passphrase")
        oid = v.seal_object(MemoryObject(content="prefers formal B2B emails",
                                         tags=["preferences"]), "work", "test-passphrase")
        out = v.open_object(oid, "test-passphrase")
        assert out["content"].startswith("prefers")
        assert out["signature_verified"] is True
        # export -> import into a fresh vault -> same content
        v.export(f"{d}/backup.amem")
        v2 = Vault.import_file(f"{d}/backup.amem", f"{d}/v2", "test-passphrase")
        out2 = v2.open_object(oid, "test-passphrase")
        assert out2 == out or out2["content"] == out["content"]
        # wrong passphrase -> must fail
        try:
            v.open_object(oid, "wrong"); assert False
        except ValueError:
            pass
        print("test_full_cycle OK")
    finally:
        shutil.rmtree(d)

if __name__ == "__main__":
    test_full_cycle()
