# Contributing

ApertoMemory is an open format with a reference implementation. The most
valuable contributions right now:

- **Spec review** — read the latest draft in `draft/` and the CDDL schema
  in `spec/`, and open issues on ambiguities, security concerns, or
  interoperability gaps.
- **Independent implementations** — any language. The CDDL schema is in
  `spec/`, machine-readable test vectors in `test-vectors/v2`.

  Reproducing the vectors is necessary but **not sufficient**: six of the
  fourteen are refusal cases. An implementation that reproduces every
  byte and refuses none of them is not conformant — it is the bug the
  vectors exist to catch, and it is what the first release of this
  format shipped.

  Write against the vectors, not against an existing implementation. The
  TypeScript port was written that way deliberately, and the
  disagreements between the two uncovered three defects that four rounds
  of security review had missed — one of them in this reference.
- **Adapters** — connect more AI tools (an adapter is typically small;
  see `src/amem/mcp_server.py` as the reference).

Ground rules: security-relevant changes need test vectors; the Blind
Server must never gain the ability to read content, authorship, or
semantic timestamps; unknown fields are preserved, never dropped.

By contributing you agree your contributions are licensed under MIT.
