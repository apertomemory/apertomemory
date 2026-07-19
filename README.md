# ApertoMemory

**Portable, client-side-encrypted, user-owned AI memory.**

Every AI tool remembers you differently — and only within its own walls.
Switch tools and your AI forgets who you are. ApertoMemory fixes this with
an open format: your AI's memory of you lives in a file that is **yours**,
encrypted with **your** keys, portable across any compatible system. No
provider can read it. No vendor can hold it hostage.

- **Zero-access**: content, authorship, and semantic timestamps are
  encrypted client-side; a sync/storage server sees only opaque blobs.
- **Signed provenance**: every memory object is Ed25519-signed inside the
  encryption; imported third-party memories are cryptographically
  distinguishable from your own (persistent-prompt-injection defence).
- **Portable**: export your entire memory as a single `.amem` file and
  import it anywhere — a complete vault fits in kilobytes.
- **Open**: MIT-licensed reference implementation, CDDL schema, test
  vectors, and an IETF Internet-Draft (`draft-ferro-apertomemory`).

Website: https://apertomemory.org

## Install

```bash
pip install apertomemory
```

The command-line tool is `amem`; the file format is `.amem`.

## Quick start

```bash
export AMEM_PASSPHRASE="your-passphrase"
amem --vault ~/.amem init
amem --vault ~/.amem scope add default
amem --vault ~/.amem seal "prefers formal B2B emails" --tags preferences
amem --vault ~/.amem open <id>
amem --vault ~/.amem export my-memory.amem     # take it anywhere
amem --vault other-device import my-memory.amem
```

## Cryptography

Argon2id (m=64 MiB, t=3, p=4) -> HKDF-SHA256 -> Ed25519 (signing,
sign-then-encrypt) + X25519 (ECDH-ES + AES-KW for per-scope KEKs) ->
AES-256-GCM per object (COSE alg 3), canonical CBOR (RFC 8949 s4.2).
The vault and the `.amem` file never contain cleartext keys or content.

Run the tests: `python3 tests/test_roundtrip.py`

## MCP adapter (Claude Desktop / Claude Code)

```bash
pip install "apertomemory[mcp]"
```

```json
{
  "mcpServers": {
    "amem": {
      "command": "python3",
      "args": ["-m", "amem.mcp_server"],
      "env": {"AMEM_VAULT": "/path/to/vault", "AMEM_PASSPHRASE": "your-passphrase"}
    }
  }
}
```

Exposed tools: `amem_remember`, `amem_recall`, `amem_export`,
`amem_import`, `amem_status`. The passphrase lives only in your local
environment: the model never sees it. "New device" demo: `amem_export` ->
move the `.amem` file -> `amem_import` into a fresh vault -> `amem_recall`
and the AI already knows you.

## Specification

The format is specified in an IETF Internet-Draft
(`draft-ferro-apertomemory`), with a normative CDDL schema and
machine-readable test vectors in this repository under `spec/` and
`test-vectors/`.

## License

MIT — see [LICENSE](LICENSE).
