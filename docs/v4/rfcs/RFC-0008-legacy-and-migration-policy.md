# RFC-0008: Legacy Compatibility and Migration Policy

- **Status:** Proposed for v4 implementation
- **Owner:** Compatibility and migration architecture
- **Last updated:** 2026-07-29

## Context

Legacy support exists to move data into v4, not to preserve unsafe encryption
APIs. `LegacyFormat` is always supplied explicitly; v4 parse failure never
invokes a legacy parser.

## Phase 1 evidence

[Serialized formats](../baseline/serialized-format-inventory.md) identifies all
current formats and gaps. [Security findings](../baseline/security-findings.md)
records missing CSF KDF factors, unbounded hybrid decoding, path escape,
destructive encryption, and non-durable demo audit claims.

## Problem statement

Ambiguous unversioned inputs, missing parameters, and broad parsers can create
downgrade, resource, oracle, and data-loss risks if compatibility is automatic.

## Goals

Give every serialized format a destination, explicit identifier/permission,
quota, vector requirement, deadline, corruption behavior, and transactional
migration workflow.

## Non-goals

No legacy encryption, silent autodetection, raw-key export, source deletion, or
claim that old formats gain v4 security properties.

## Binding decision

Stable legacy adapters ship in `cryptography_suite.legacy` only where the matrix
says “stable”; the namespace is never root-imported. “Explicit” means named
format plus `Policy.migration()` permission and deadline.

| Format | Identification | v4 encrypt / decrypt / migrate | Default and opt-in | Limits/context and corruption | Distribution and timeline |
| --- | --- | --- | --- | --- | --- |
| CSF v2 | `CSF!`, version 2 | No / yes / yes | Denied; explicit `csf-v2` | 64 KiB header, 16 GiB input default; password source and migration context required; tag failure leaves destination unchanged | Stable adapter through v4 security support; removal no earlier than v5 and 2031-12-31 |
| CSF v1 | `CSF!`, version 1 | No / yes / yes | Denied; explicit `csf-v1` | Same bounds; unauthenticated-header limitation in receipt; corruption fails closed | Stable adapter until 2029-12-31, then separately maintained migration tool/labs |
| Raw legacy AES | No magic; caller declares exact layout and KDF | No / yes / yes | Denied; explicit `raw-aes` plus exact KDF parameters | 16 GiB; no probing; highest-risk receipt; authentication failure indistinguishable | Stable adapter until 2029-12-31 |
| One-shot password AES | Declared `password-aes-v3`; salt/nonce fixed layout | No / yes / yes | Denied; explicit format and KDF inputs | 64 MiB; no Base64 guessing; policy KDF bounds; tag failure closed | Stable migration adapter until 2029-12-31; new portable password output is RFC-0005 |
| Generic hybrid JSON/Base64 | Declared schema; no trustworthy magic | No / no / no in stable | Never | Labs parser capped at 16 MiB, depth 6, exact fields; corruption closed | Labs only; no stable support |
| ML-KEM envelope | `CSKEM1` | No / no / no in stable | Never | Existing fixed fields; PQC assurance absent | Labs only; no stable support/post-quantum claim |
| Local-keystore metadata | Explicit inventory source; JSON shape | No / metadata read only / inventory only | Denied; explicit local-keystore adapter | 1 MiB/file, depth 6, confined resolved paths, identifier grammar; malformed entry quarantined | Stable migration inventory until 2029-12-31; no raw private-key transfer |
| PEM/DER PKCS#8/SPKI | Standard parser plus declared key purpose | No generic export / provider-approved import only / yes | Denied; explicit encrypted-PEM/DER migration | 16 MiB; password out-of-band; unencrypted private key requires exceptional migration policy | Stable migration support for v4 lifecycle; no arbitrary root API |
| Migration demo audit/forensics | Pipe/JSON declared explicitly | No / no authoritative verification / evidence import only | Never trusted automatically | 16 MiB; treated as untrusted notes, not proof | Labs/archival tooling; no stable parser required after 2028-12-31 |
| Pipeline JSON/YAML and formal exports | Explicit file type | No / no / no | Never | Labs quotas; never executed by stable core | Labs only |
| Signal JSON/Base64, handshake protobuf, X.509, OTP, FHE contexts, generated applications | Explicit external/labs formats | No / no / no | Never | Handled only by owning external/labs tools | Labs or general libraries; absent from stable wheel |
| Encrypted audit lines | Fernet token per line | No / no / optional evidence export | Never treated as v4 audit | Bounded line count/size; corruption reported | One-off external migration tool, not stable runtime |

Every supported row needs committed positive, wrong-secret, truncated, corrupted,
oversized, boundary, and ambiguity vectors created from independently verified
fixtures. Raw/password formats additionally require exact KDF/default provenance.

No parser may be tried because another parser failed. Magic-bearing formats may
be identified for inventory, but decryption still requires the named adapter.
Unversioned formats MUST NOT be autodetected. Unknown CSF versions fail as
unsupported, not raw AES.

### Migration transaction

Migration MUST execute these durable states:

1. **Inventory:** hash source bytes, record declared format/size/location under
   redaction, required secret/provider availability, and collision/link risks.
2. **Dry run:** parse structure within quotas without plaintext output, resolve
   destination key/version, validate policy/deadline/capacity, and plan receipt.
3. **Backup checkpoint:** require caller-confirmed recoverable backup or explicit
   policy exception; never make/delete the backup silently.
4. **Stage:** create exclusive same-directory destination temporary file and
   durable transaction record keyed by source digest + destination key/version +
   policy id.
5. **Decrypt:** use only the declared adapter into protected staging; no
   unauthenticated plaintext becomes final.
6. **Re-encrypt:** seal immediately as v4 with required context and fresh DEK.
7. **Independent verify:** reopen the staged v4 envelope through the public
   path, compare a keyed transaction digest/length of plaintext streams without
   persisting plaintext, and inspect pinned destination version.
8. **Atomic promotion:** enforce no-overwrite/link policy, fsync staged file,
   atomic same-filesystem rename, and fsync directory.
9. **Receipt:** durably record schema `cs-migration-receipt/1`, operation/
   idempotency id, redacted source/destination ids, source and destination
   digests, declared format, policy id, opaque destination context commitment,
   key version, byte counts, timestamps, verification result, warnings, and
   audit checkpoint—no secrets.
10. **Complete:** leave source untouched. Source deletion is a separate,
    user-authorized retention workflow outside the SDK transaction.

Retries locate the transaction by idempotency key and resume only from a
verified durable state. Conflicting digests/destinations fail. Before promotion,
rollback removes owned staging and retains source/record. After promotion,
rollback restores the caller-managed backup or retains both; it never decrypts
or deletes automatically.

## API or architecture implications

Legacy adapters emit a bounded plaintext stream only to migration/open services;
providers never parse legacy. CLI selection is
`cryptosuite migrate --legacy-format FORMAT ...`.

## Security consequences

Explicit formats prevent downgrade/probing. Old unauthenticated metadata and KDF
gaps remain limitations and must appear in receipts/audit.

## Privacy consequences

Inventories and receipts can reveal filenames, formats, tenants, and key ids;
defaults store pseudonymous identifiers and, when needed, only the opaque
destination context-commitment identifier.

## Compatibility consequences

Dates are earliest support ends, not promises of v5 adapters. Removing an
adapter also requires RFC-0010 notice and published extraction guidance.

## Operational consequences

Migration requires backup, staging capacity, passwords/provider access,
idempotency storage, audit sink, and operator review of quarantined inputs.

## Failure behavior

Corruption, ambiguity, quota, policy, verification, collision, cancellation, and
I/O failures leave source and pre-existing destination unchanged and preserve a
redacted resumable record.

## Alternatives considered

Automatic probing; decrypt-only compatibility forever; offline one-shot scripts;
explicit transactional adapters.

## Rejected alternatives

Probing enables downgrade/oracles, indefinite support expands attack surface,
and ad hoc scripts lack failure atomicity and receipts.

## Implementation constraints

Legacy code is reviewed/reimplemented, not imported from v3 by path. Deadlines
use UTC and cannot be bypassed by environment variables.

## Test and validation requirements

Matrix coverage, vector provenance, parser quotas, no-fallback assertions,
crash/cancel at every state, resumability/idempotency/conflict, atomic promotion,
receipt redaction, backup/rollback, and no-source-deletion tests.

## Migration implications

This RFC is the migration contract. API-only users receive mapping to v4, labs,
or removal; data users follow the transaction above.

## Unresolved questions

Organizations may set earlier deadlines. Any request to extend a listed stable
deadline requires a new compatibility/security review and owner.

## Explicitly deferred work

Adapters, vectors, migration store, CLI implementation, labs tools, and
organization inventories are deferred.

## Acceptance criteria

- Every Phase 1 serialized format appears in the matrix.
- Stable parser entry always names one format.
- End-to-end crash/rollback tests prove source preservation and atomic output.

## Supersession rules

Adding/extending legacy support requires a compatibility RFC with threat model,
quota, vectors, owner, and absolute end date.
