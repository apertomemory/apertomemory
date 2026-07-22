# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in the
ApertoMemory format, the reference implementation, or the test
vectors, please report it privately to **irn@irn3.com**. Please do
not open a public issue for security reports.

Include, where possible: the affected component (format / library /
MCP adapter), a description of the issue, and steps or code to
reproduce it. Reports about cryptographic design flaws in the
specification itself are as welcome as implementation bugs — arguably
more so.

## What to Expect

- **Acknowledgement within 72 hours** of your report.
- An assessment and, if confirmed, a fix timeline within **14 days**.
- Coordinated disclosure: we ask for up to **90 days** before public
  disclosure, and we will credit you in the release notes unless you
  prefer otherwise.

## Audit Status

The cryptographic design follows well-established primitives and
constructions (COSE, Ed25519, AES-256-GCM, Argon2id, HKDF, AES-KW),
but **neither the specification nor the reference implementation has
undergone an independent security audit yet.** Until an audit is
completed, do not rely on ApertoMemory as the sole protection for
high-stakes secrets. Review of the specification
(`draft-ferro-apertomemory`) by cryptographers and security
researchers is explicitly invited.

## Past Advisories

- [GHSA-jwrj-j847-ph54](https://github.com/apertomemory/apertomemory/security/advisories/GHSA-jwrj-j847-ph54)
  — forgeable memory provenance in `format_version` 1. Affects
  `apertomemory` on PyPI < 0.2.0 and on npm <= 0.1.1. Fixed by
  `format_version` 2.

## Supported Versions

Only the latest released version receives security fixes. All 0.1.x
releases are yanked on PyPI and deprecated on npm, as is 0.2.0. Use
0.2.1 or later on both.
