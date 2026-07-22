# IETF Internet-Draft

The ApertoMemory format is specified in an IETF Internet-Draft.

**Current published version: draft-ferro-apertomemory-01**
https://datatracker.ietf.org/doc/draft-ferro-apertomemory/

## Do not implement from -01

The published drafts describe `format_version` 1, which has a known
security defect: nothing binds a signature to the author it claims or to
the object envelope around it, so a forged provenance verifies as valid.
See [GHSA-jwrj-j847-ph54](https://github.com/apertomemory/apertomemory/security/advisories/GHSA-jwrj-j847-ph54).

`format_version` 2 fixes it, and until -02 is published the normative
description of the current format lives in this repository:

- the CDDL schema in [`spec/`](../spec/)
- the test vectors in [`test-vectors/v2/`](../test-vectors/v2/), which
  are the conformance artefact

Six of the fourteen vectors are refusal cases. Reproducing the byte
strings is necessary but not sufficient: an implementation that
reproduces every byte and refuses none of the attacks is the defect the
vectors exist to catch.

## Changes

**-02 (in preparation)** will specify `format_version` 2: the envelope
and author bindings, trust derived from which key verified rather than
declared, custody records for re-sealed objects, and the container
rules. Implementations of -00 and -01 do **not** remain conforming.

**-01** expanded the Security Considerations (nonce management and AEAD
limits, key rotation, device and key revocation) and added an
Implementation Status section. No wire-format changes relative to -00.

## Sources

`draft-ferro-apertomemory-01.xml` (canonical, RFC 7991 v3) and the
compiled `.txt`.
