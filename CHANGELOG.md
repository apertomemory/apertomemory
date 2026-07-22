# Changelog

## 0.2.1 — custody attestations are only honoured from the vault owner

Found by adversarial probing across the two independent implementations,
before either had a user affected.

* **Custody is an attestation by the custodian.** A custody record is now
  honoured only when the verified signer is the vault owner. Previously any
  third party in your keyring could write a custody record attributing content
  to you — or to anyone else — and have it read as `trusted`. This was
  provenance laundering in the opposite direction from the one 0.2.0 closed:
  not the owner appropriating a stranger's memory, but a stranger putting words
  in the owner's mouth.
* **Self-inconsistent objects are refused.** The COSE protected header `kid`
  and the payload `author_key_id` are both signed. If they disagree, the object
  is refused rather than resolved in favour of one of them: two consumers
  reading different fields would otherwise disagree about who wrote it.
* **Unaccepted attestations name no author.** When a custody record names a
  proven author that is not in the keyring, `author_key_id` is `null` and
  `authorship` is `unknown` — not the key we declined to accept.
* **Out-of-range `confidence` is not propagated.** The object is authentic so
  it still opens, but the value is reported as `null` with the schema violation
  flagged. Consumers rank memories by confidence; propagating a value outside
  [0.0, 1.0] lets a non-conformant producer dominate every ranking.
* **Malformed custody sub-maps degrade instead of throwing.** An empty custody
  record yields `unverified`, never an exception.

Test vectors 010–014 cover all five. Two tests in the review suite had quietly
become defenders of the defect rather than of the code, and were inverted.

## 0.2.0 — security release (format_version 2)

**Users of 0.1.x should upgrade and run `amem migrate`. Read the migration
note below before doing so: migration is a transfer of trust, not a format
conversion, and it deliberately refuses to migrate anything it cannot vouch
for.**

An independent review of 0.1.3 found that objects carried no cryptographic
binding between the signature, the claimed author, and the cleartext envelope.
0.1.x made a provenance claim it could not keep; that claim has been corrected
in the README and is now actually enforced.

### Security fixes

* **Author binding.** `author_key_id` in the payload MUST equal
  `sha256(verifying key)[:8]`. Previously a signer could sign with their own
  key while claiming another identity, and verification still succeeded — which
  defeated the persistent-prompt-injection defence. Forged authorship is now
  refused.
* **Envelope binding.** `format_version`, `id` and `scope_id` are fed as COSE
  `external_aad` to both the signature and the AEAD. A storage server rewriting
  those fields now invalidates the object. Version downgrade (2 -> 1) is
  likewise detected.
* **Trust is derived, never declared.** The `trust` level comes from which key
  verified the signature (owner -> `self`, accepted third-party key ->
  `trusted`), not from a self-asserted payload field.
* **Fail-closed verification.** `open_sealed` refuses to return content it
  cannot authenticate. Reading unauthenticated objects requires an explicit
  `allow_unverified=True` and yields `trust="unverified"`.
* **Import hardened, and unified.** The guard that existed only in the MCP
  adapter now lives in a single implementation used by the library, the CLI and
  MCP: a passphrase check before any write, refusal of files belonging to a
  different identity, scope merge that never overwrites, and structural
  validation of every object. `Vault.import_file` no longer destroys the
  identity of an existing vault (data loss in 0.1.x).
* **Denial-of-service isolation.** `Vault.open_all` isolates failures per
  object: one hostile or corrupt object no longer takes down the whole recall.
  `amem_recall` reports excluded objects instead of crashing.
* **Unknown fields preserved.** Payload keys outside the known set survive a
  read/re-seal cycle, as the specification requires.
* **Schema validation.** `confidence` must be a finite float in [0.0, 1.0];
  NaN/inf/out-of-range values are refused at seal time.
* **Corrupt `.amem` files** raise a clean `ValueError` instead of leaking
  parser exceptions.

### Migration semantics (read this)

Re-sealing an object changes its signer. An object may therefore keep
`trust="self"` only if its original signature actually verifies under the
owner's key. `amem migrate`:

* **migrates** v1 objects proven to be the owner's own — these keep
  `trust="self"` and carry no custody record;
* **attributes** v1 objects proven to be authored by a key in your keyring:
  they are re-sealed with a custody record naming the *proven* author, and
  open as `trust="trusted"` — never as yours. Revoking that key later
  downgrades them to `unverified`, because trust is evaluated at read time and
  never frozen into the object;
* **refuses**, and leaves untouched, every object whose authorship cannot be
  proven under any key you accept — reporting each one;
* with `--quarantine`, re-seals those objects carrying a **custody record**
  (original version, originally claimed author, migration time). A custody
  record permanently prevents `trust="self"`, whoever signed the object.

Re-sealing changes the signer, so a migrated object's signature proves
**custody, not authorship** — and the decoded object says so. `provenance` now
reports three separate things: `signer_key_id` (who signed the object as it
stands), `author_key_id` (who wrote it, where that is supported), and
`authorship`, which is `signed` for ordinary objects, `attested` when a
custodian proved a different author at migration, and `unknown` when
authorship could not be proven — in which case `author_key_id` is `null`
rather than a guess, and the unproven claim is kept separately as
`claimed_author_key_id`. That is why every object that is not the owner's
own carries a custody record: without one, migrating a friend's memory would
silently re-attribute it to you.

Without this, `migrate` would have been a provenance laundry: any hostile v1
object sitting in a scope would have come out of an ordinary upgrade signed by
you and trusted as your own. An earlier draft of this release had exactly that
defect; it was caught in review before publication.

Residual, accepted: v1 carries no envelope binding, so migration proves
authorship of the *content*, not of the object's (id, scope) placement. An
adversary with write access could have relocated a genuine object to another
scope before migration. The exposure ends once objects are v2.

Each object is migrated in isolation and written atomically: a corrupt object
is reported and skipped, never leaving the vault half-migrated.

### New

* `amem migrate [--quarantine]` — see migration semantics above.
* `amem trust <sign_pub_hex>` — accept a third-party author key, enabling
  verifiable `trust="trusted"` memories.

### Compatibility

`format_version` 1 objects remain readable with `allow_unverified=True` and are
always reported as `unverified`. They carry no binding and should be migrated.
`open_sealed` is now keyword-only for its key arguments: third-party callers
must update. This is a deliberate breaking change on a security boundary.

### Still open

* No independent audit. The primitives are standard; the construction is not
  audited.
* An `.amem` file contains the vault salt and public signing key, which gives
  an offline verification oracle against the passphrase. Argon2id
  (m=64 MiB, t=3, p=4) is the only barrier: use a strong passphrase.
* No recovery code yet: a lost passphrase means lost memory.
* The TypeScript implementation still writes format_version 1 and has the same
  binding defects. It must be updated before interoperability can be claimed.
