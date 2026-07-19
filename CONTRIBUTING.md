# Contributing

ApertoMemory is an open format with a reference implementation. The most
valuable contributions right now:

- **Spec review** — read `draft/draft-ferro-apertomemory-00.txt` and open
  issues on ambiguities, security concerns, or interoperability gaps.
- **Independent implementations** — any language. The CDDL schema is in
  `spec/`, machine-readable test vectors in `test-vectors/`. If your
  implementation reproduces the vectors, it interoperates.
- **Adapters** — connect more AI tools (an adapter is typically small;
  see `src/amem/mcp_server.py` as the reference).

Ground rules: security-relevant changes need test vectors; the Blind
Server must never gain the ability to read content, authorship, or
semantic timestamps; unknown fields are preserved, never dropped.

By contributing you agree your contributions are licensed under MIT.
