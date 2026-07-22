# IETF Internet-Draft

The ApertoMemory format is specified in an IETF Internet-Draft.

**Current published version: draft-ferro-apertomemory-02**
https://datatracker.ietf.org/doc/draft-ferro-apertomemory/

-02 is the normative description of `format_version` 2, the current
format. It specifies the envelope and author bindings, trust derived
from which key verified rather than declared, custody records for
re-sealed objects, the conversion paths between trust levels
(migration, import, and the AI boundary), and the container rules.

## Do not implement from -00 or -01

The earlier drafts describe `format_version` 1, which has a known
security defect: nothing binds a signature to the author it claims or to
the object envelope around it, so a forged provenance verifies as valid.
See [GHSA-jwrj-j847-ph54](https://github.com/apertomemory/apertomemory/security/advisories/GHSA-jwrj-j847-ph54).
Implementations of -00 and -01 do **not** conform to -02.

## Conformance

Conformance for `format_version` 2 is defined by the machine-readable
test vectors in [`test-vectors/v2/`](../test-vectors/v2/), referenced
normatively by -02:

- fourteen vectors, six of which are refusal cases;
- reproducing the byte strings is necessary but not sufficient: an
  implementation that reproduces every byte and refuses none of the
  attacks is the defect the vectors exist to catch.

The CDDL schema lives in [`spec/`](../spec/).

## Changes

**-02** specifies `format_version` 2: the two bindings (COSE
`external_aad` over the cleartext envelope; `author_key_id` bound to the
verifying key, with a `kid` consistency rule), read-time fail-closed
trust derivation, custody records, the trust-level conversion paths, and
the v2 test-vector set as the normative conformance artefact.
Implementations of -00 and -01 do **not** remain conforming.

**-01** expanded the Security Considerations (nonce management and AEAD
limits, key rotation, device and key revocation) and added an
Implementation Status section. No wire-format changes relative to -00.

## Sources

`draft-ferro-apertomemory-02.xml` (canonical, RFC 7991 v3) and the
compiled `.txt`.
