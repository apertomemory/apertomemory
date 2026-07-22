# ApertoMemory

[![CI](https://github.com/apertomemory/apertomemory/actions/workflows/ci.yml/badge.svg)](https://github.com/apertomemory/apertomemory/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/apertomemory)](https://pypi.org/project/apertomemory/)
[![IETF I-D](https://img.shields.io/badge/IETF-draft--ferro--apertomemory--02-blue)](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

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
  vectors, and an IETF Internet-Draft
  ([draft-ferro-apertomemory](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/)).

Website: https://apertomemory.org

## Install

Requires **Python ≥ 3.10**.

`amem` is a command-line tool, so the recommended install is [pipx](https://pipx.pypa.io/)
(isolated, on your PATH):

```bash
pipx install apertomemory
```

On macOS/Homebrew and other PEP 668 "externally-managed" environments a bare
`pip install` into the system interpreter will be refused; use pipx, or pip
inside a virtualenv:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install apertomemory
```

The command-line tool is `amem`; the file format is `.amem`.

**New here? Follow the [5-minute getting started guide](GETTING-STARTED.md)** - from install to an assistant that remembers you, including where the MCP config goes for each client.

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

### Upgrading from 0.1.x

`format_version 2` binds each signature to its author and to the object
envelope. Existing 0.1.x objects carry no such binding and open as
`unverified` until re-sealed:

```bash
amem --vault ~/.amem migrate              # re-seal your own memories as v2
amem --vault ~/.amem migrate --quarantine # also carry over ones it cannot vouch for
```

Migration is a **transfer of trust, not a format conversion** — it deliberately
refuses to re-sign anything whose authorship it cannot prove. See
[CHANGELOG.md](CHANGELOG.md) for the full migration semantics and what is still open.

## Cryptography

Argon2id (m=64 MiB, t=3, p=4) -> HKDF-SHA256 -> Ed25519 (signing,
sign-then-encrypt) + X25519 (ECDH-ES + AES-KW for per-scope KEKs) ->
AES-256-GCM per object (COSE alg 3), canonical CBOR (RFC 8949 s4.2).
The vault and the `.amem` file never contain cleartext keys or content.

Run the tests: `python3 tests/test_roundtrip.py`

## Security

This project has not had an independent external audit.

The 0.2.x releases were reworked over repeated adversarial review, and
every defect found has a regression test under `tests/`. Some were found
by reviewing this implementation; others only surfaced when the
TypeScript implementation, written against the test vectors without
reading this code, disagreed with it. That is evidence of scrutiny, not
a substitute for an audit.

All 0.1.x releases are yanked, as is 0.2.0. Use 0.2.1 or later.

Cryptographic review of the specification is explicitly invited.

If you find a vulnerability, please report it privately: see
[SECURITY.md](SECURITY.md).

## MCP adapter (Claude Desktop / Claude Code)

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
([draft-ferro-apertomemory](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/)),
with a normative CDDL schema and machine-readable test vectors in this
repository under `spec/` and `test-vectors/`.

## License

MIT — see [LICENSE](LICENSE).

## Implementations

- **Python** (this repository) - reference implementation, generates the test vectors
- **TypeScript** - https://github.com/apertomemory/apertomemory-js - noble crypto stack, Node.js 20+ and browsers; interoperability with this implementation verified in both directions
