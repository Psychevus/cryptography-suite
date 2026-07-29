# RFC-0007: Immutable Security Policy Model

- **Status:** Proposed for v4 implementation
- **Owner:** Security policy architecture
- **Last updated:** 2026-07-29

## Context

Policy is the explicit, immutable authority for format, provider, lifecycle,
resource, migration, file, and audit decisions.

## Phase 1 evidence

[Import/plugin evidence](../baseline/import-and-plugin-surface.md) shows cached
settings, import-time KDF environment values, mutable globals, and environment
plugin gates. [Threat model](../baseline/threat-model-current.md) identifies
ambient policy and untrusted-resource risks.

## Problem statement

Ambient variables and mutable global defaults can change encryption semantics
by import order, deployment, or process state and cannot be audited per
operation.

## Goals

Frozen validated policies, explicit composition, stable identifiers,
serializable nonsecret configuration, secure built-ins, and fail-closed
evaluation.

## Non-goals

Policy is not a remote authorization service, credential container, arbitrary
code hook, or a claim that a deployment is compliant.

## Binding decision

`Policy` is a frozen value object whose canonical JSON serialization (UTF-8,
sorted keys, no floats, versioned schema) produces
`policy_id = "cs-policy-v1:" + base64url(SHA-256(serialized_policy))`.
The identifier, not the whole policy, is stored in envelopes. Policy files MUST
contain no credentials, secrets, paths with embedded tokens, or executable
expressions.

The schema MUST control at least:

- allowed envelope major/minor versions, profiles, algorithm suites, providers,
  recipient counts, key states, and immutable-version requirement;
- required context keys, maximum context bytes, and whether selected key
  references/timestamps may be visible;
- maximum plaintext, envelope, header, entry, nesting, chunk size/count, and
  streaming staging requirements;
- password-profile enablement, KDF ids, minimum/maximum work factors, and
  resource ceilings;
- explicit legacy formats, decrypt deadlines, required migration context, and
  migration-only mode;
- rewrap destinations/count, same-key behavior, rotation/rollback/destroy
  approvals, and stale-description age;
- output overwrite, symlink/hardlink, permissions, fsync, rename,
  cross-filesystem, backup, and temporary-file rules;
- audit-required events, sink-failure mode, identifier redaction, integrity
  checkpoint requirement, and provider failure/retry budget.

Built-ins are:

| Policy | Binding intent |
| --- | --- |
| `Policy.enterprise()` | v4 provider profile only; approved provider allowlist supplied explicitly; `PRIMARY` for seal and `PRIMARY`/`DECRYPT_ONLY` for open; no password/legacy; RFC-0005 enterprise quotas; no overwrite; reject links; same-directory staging; file+directory fsync; required audit with fail-before-operation for unavailable mandatory sink |
| `Policy.development()` | v4 plus explicit local development provider; lower size/retry limits; password profile may be explicitly enabled by derived policy; no legacy by default; never labeled production |
| `Policy.migration(deadline=...)` | Cannot seal arbitrary new data; permits named legacy readers and v4 destination only; mandatory receipt/backup/verification/audit; deadline required |

Policies compose only through `base.restrict(overlay)`. Composition is
intersection/stricter-value: allowlists intersect, maximums take the minimum,
minimum security floors take the maximum, required booleans use logical OR, and
permissions may only be removed. Conflicting or empty results fail validation.
No generic “merge” that widens authority is allowed. A separately named,
audited application policy may widen a built-in only by constructing a complete
new policy and passing explicit validation; it receives a new id.

Environment variables MAY select a nonsecret policy file path at application/CLI
startup only when the application explicitly enables that mechanism. They MUST
NOT change individual security fields, format interpretation, providers, KDFs,
algorithms, or legacy permissions. Importing the package reads no environment.
Application overrides use explicit constructor/restriction calls and are logged
by policy id.

Evaluation order is hard implementation ceilings, policy schema validity,
format/profile/version, quotas, context, provider/key state, operation-specific
permission, then provider call. Missing/unknown values fail closed.

### File-operation policy

Enterprise defaults MUST:

- reject input/output identity after handle/file-identity checks;
- reject symlink destinations and destinations with hardlink count greater than
  one; do not follow links during create/promote;
- default to no overwrite and require explicit policy plus operation flag for
  replacement;
- create a same-directory exclusive temporary file with owner-only permissions,
  flush and fsync data, authenticate/verify, atomically replace, fsync the
  directory, then best-effort remove owned temporary data;
- reject cross-filesystem “atomic” promotion; explicit copy-and-verify migration
  is a separate transaction;
- preserve no unsafe source permissions by default and never delete source
  automatically.

On platforms lacking a promised primitive, the operation fails rather than
quietly weakening the guarantee.

### Audit policy

Audit events use schema `cs-audit/1` with event id, UTC time, operation id,
event type, outcome/error code, policy id, component/provider id, hashed key/
envelope identifiers, retry/transition data, and integrity-checkpoint reference.
Plaintext, context values, passwords, credentials, DEKs, raw wrapped keys,
nonces, ciphertext, full paths, and provider exception text are forbidden.

Enterprise mandatory-sink unavailability before a mutating operation blocks it.
Failure after a cryptographic provider mutation records `AUDIT_PENDING` in
durable reconciliation state and blocks completion/promotion; it MUST NOT roll
back an irreversible provider action by guess. External append-only storage and
trusted checkpoints are required for tamper-evidence claims; the SDK does not
claim its local log is tamper-proof.

## API or architecture implications

Policy models import no providers. Provider capabilities are data passed to a
pure evaluator. Every operation records the effective policy id.

## Security consequences

Monotonic composition prevents accidental widening. Explicit startup selection
eliminates import-time cryptographic policy changes.

## Privacy consequences

Canonical policy files and ids are nonsecret but may reveal organizational
controls. Audit identifier hashing uses deployment-owned keyed pseudonymization
when cross-event correlation is required.

## Compatibility consequences

Policy schema major changes are breaking; unknown required fields fail. Old
policy ids remain meaningful and their canonical documents must be retained for
the envelope support period.

## Operational consequences

Organizations must version, review, distribute, retain, and monitor policies and
audit checkpoints. Policy validation is available offline through the CLI.

## Failure behavior

Invalid/expired/unknown policies raise `POLICY_INVALID`; denied actions use
specific policy/key/legacy codes. No fallback built-in is selected after error.

## Alternatives considered

Mutable settings singleton, environment field overrides, callback-based policy,
declarative immutable policy.

## Rejected alternatives

Globals and environment are ambient; callbacks are nonportable, unauditable
code execution. Declarative immutable policy is selected.

## Implementation constraints

No floats, regex backtracking hazards, code hooks, provider objects, or secrets
in serialization. Validation must be deterministic and bounded.

## Test and validation requirements

Golden canonical policy ids; schema/unknown-field tests; composition algebra and
property tests proving no widening; environment/import tests; quota boundaries;
file link/crash/fsync/cross-filesystem tests; audit redaction and sink-failure
state tests.

## Migration implications

Migration policies name each legacy format and absolute deadline. Inventories
and receipts store policy ids so decisions remain reconstructable.

## Unresolved questions

The external policy distribution/signing system and checkpoint service are
deployment concerns; reference profiles may be specified before beta.

## Explicitly deferred work

Schema file, implementation, policy signing/distribution, and compliance
profiles are deferred.

## Acceptance criteria

- Every controlled field above is represented and deterministically validated.
- Composition cannot widen authority.
- No import-time environment changes behavior.
- File and audit failure tests meet the binding defaults.

## Supersession rules

Widening defaults or changing composition/file/audit semantics requires a
security RFC, new policy schema major when incompatible, and migration guidance.
