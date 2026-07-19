"""amem — ApertoMemory reference CLI."""
from __future__ import annotations
import argparse, getpass, json, os, sys
from .objects import MemoryObject
from .vault import Vault


def _pw(args) -> str:
    return (args.passphrase or os.environ.get("AMEM_PASSPHRASE")
            or getpass.getpass("passphrase: "))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="amem",
        description="ApertoMemory — portable, encrypted, user-owned AI memory.")
    p.add_argument("--vault", default=os.environ.get("AMEM_VAULT", "./amem-vault"))
    p.add_argument("--passphrase", help="(discouraged: use AMEM_PASSPHRASE or the prompt)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create a new vault")

    sp = sub.add_parser("scope", help="manage scopes")
    sp.add_argument("action", choices=["add", "list"])
    sp.add_argument("name", nargs="?")

    ss = sub.add_parser("seal", help="encrypt and sign a new memory")
    ss.add_argument("content")
    ss.add_argument("--scope", default="default")
    ss.add_argument("--type", default="semantic",
                    choices=["episodic", "semantic", "procedural"])
    ss.add_argument("--confidence", type=float, default=0.8)
    ss.add_argument("--tags", default="", help="comma-separated")
    ss.add_argument("--tool", default="amem-cli/0.1")

    so = sub.add_parser("open", help="decrypt and verify a memory")
    so.add_argument("id")

    sub.add_parser("list", help="list object ids")

    se = sub.add_parser("export", help="export everything to an .amem file")
    se.add_argument("out")

    si = sub.add_parser("import", help="import an .amem file into a new vault")
    si.add_argument("file")

    args = p.parse_args(argv)
    v = Vault(args.vault)

    if args.cmd == "init":
        Vault.init(args.vault, _pw(args))
        v.add_scope("default", _pw(args)) if False else None
        print(f"vault created at {args.vault} (create a scope with: amem scope add default)")
        return 0

    if args.cmd == "scope":
        if args.action == "add":
            if not args.name:
                p.error("scope name required")
            sid = v.add_scope(args.name, _pw(args))
            print(f"scope '{args.name}' created (id {sid.hex()[:8]}...)")
        else:
            for name in v._meta()["scopes"]:
                print(name)
        return 0

    if args.cmd == "seal":
        obj = MemoryObject(content=args.content, mem_type=args.type,
                           confidence=args.confidence, tool=args.tool,
                           tags=[t for t in args.tags.split(",") if t])
        oid = v.seal_object(obj, args.scope, _pw(args))
        print(oid)
        return 0

    if args.cmd == "open":
        print(json.dumps(v.open_object(args.id, _pw(args)),
                         indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "list":
        for oid in v.list_objects():
            print(oid)
        return 0

    if args.cmd == "export":
        n = v.export(args.out)
        print(f"{n} objects exported to {args.out}")
        return 0

    if args.cmd == "import":
        Vault.import_file(args.file, args.vault, _pw(args))
        print(f"imported into {args.vault}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
