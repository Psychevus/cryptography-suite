# RFC-0004: Stable Public Python API

- **Status:** Proposed for v4 implementation
- **Owner:** Python API architecture
- **Last updated:** 2026-07-29

## Context

v4 needs one deliberate high-level API for bytes and bounded streams. Models are
frozen value objects; protocols are runtime-checkable and statically typed.

## Phase 1 evidence

[Public API inventory](../baseline/public-api-inventory.md) finds 111 explicit
root names plus `__version__`, broad public submodules, caller nonces/KDFs/raw
keys, and mutable backend controls.

## Problem statement

The current API makes unsafe choice and accidental compatibility part of the
contract. It cannot express provider, context, policy, inspection, or rewrap as
one coherent operation.

## Goals

Define exact root exports, method signatures, immutability, errors, cancellation,
redaction, inspection, rewrap, and versioning.

## Non-goals

The API does not expose primitives, raw DEKs, long-term private keys, async
facsimiles, or a generic provider registry.

## Binding decision

The package root MUST export exactly these 15 symbols:

```python
__all__ = [
    "AuthenticationError",
    "ContextMismatchError",
    "CryptographySuiteError",
    "EncryptionContext",
    "Envelope",
    "EnvelopeError",
    "EnvelopeMetadata",
    "ErrorCode",
    "KeyProvider",
    "KeyRef",
    "MigrationError",
    "Policy",
    "PolicyError",
    "Protector",
    "ProviderError",
]
```

`__version__` remains readable package metadata but is intentionally not in
`__all__`. No lazy compatibility exports are allowed.

The proposed signatures are normative:

```python
class Protector:
    def __init__(
        self,
        *,
        provider: KeyProvider,
        policy: Policy,
        primary_key: KeyRef,
        audit_sink: AuditSink | None = None,
    ) -> None: ...

    def seal(
        self,
        plaintext: bytes,
        *,
        context: EncryptionContext,
    ) -> Envelope: ...

    def open(
        self,
        envelope: Envelope | bytes,
        *,
        context: EncryptionContext,
    ) -> bytes: ...

    def inspect(self, envelope: Envelope | bytes) -> EnvelopeMetadata: ...

    def rewrap(
        self,
        envelope: Envelope | bytes,
        *,
        destination_key: KeyRef,
    ) -> Envelope: ...

    def seal_stream(
        self,
        source: BinaryIO,
        destination: BinaryIO,
        *,
        context: EncryptionContext,
        cancel: Callable[[], bool] | None = None,
    ) -> EnvelopeMetadata: ...

    def open_stream(
        self,
        source: BinaryIO,
        destination: BinaryIO,
        *,
        context: EncryptionContext,
        cancel: Callable[[], bool] | None = None,
    ) -> EnvelopeMetadata: ...
```

`Envelope(data: bytes)` is an immutable validated byte container;
`bytes(envelope)` returns the original canonical bytes. Construction performs
only hard-limit framing validation and no provider call. `EnvelopeMetadata` is
an immutable, redacted view containing format/profile/version, algorithm-suite
identifier, provider/key references and immutable versions, sizes/counts,
context digest (never context values), creation time if present, critical
features, and policy identifier. It contains no plaintext, DEK, nonce, wrapped
key bytes, password/KDF salt, or ciphertext samples.

`EncryptionContext` is a frozen mapping of UTF-8 string keys to UTF-8 string or
bytes values with convenience fields `purpose` and `tenant_id`. Keys are
normalized and duplicates rejected; values are size-bounded. Its deterministic
encoding is authenticated but not stored in clear. The envelope stores a
domain-separated digest; callers MUST supply exactly matching context to open.

`KeyRef(provider_id: str, key_id: str, version: str | None)` is frozen. Seal
MUST resolve and record an immutable version; an alias without a resolved
version MUST NOT be written into a recipient entry. Metadata may additionally
record a non-authoritative logical alias.

`Policy` is frozen and validated as in
[RFC-0007](RFC-0007-policy-model.md). `KeyProvider` is the explicit protocol in
[RFC-0006](RFC-0006-provider-and-key-lifecycle.md). Supporting provider/audit/
lifecycle/streaming models remain stable in their named submodules but are not
root exports.

The initial API is synchronous. Provider SDKs and file I/O may block subject to
required timeouts. A future native async API requires a separate RFC and MUST
NOT implement blocking calls on an event loop. One-shot calls have no
cooperative cancellation point; stream calls check `cancel` before provider
calls, before each chunk, and before atomic promotion. Cancellation raises a
typed error and discards operation-owned temporary output.

`inspect` MUST parse and policy-check structural metadata without unwrapping a
DEK, decrypting content, or making a network/provider call. It MUST clearly mark
authentication as “not verified”; callers cannot use it as proof of authenticity.

`rewrap` MUST parse and enforce policy, unwrap the existing DEK internally, wrap
it to a resolved destination version, update only the mutable recipient
section/authenticator, and preserve ciphertext bytes. It MUST NOT return or log
the DEK/plaintext. It verifies recipient/header integrity; unless the format can
verify the content tag without materializing plaintext, it MUST report content
authentication as “preserved, not reverified.” Same-key/version rewrap is
idempotent.

## Error taxonomy

All stable exceptions inherit `CryptographySuiteError` and expose immutable
`code: ErrorCode`, `retryable: bool`, and redacted `details: Mapping[str, JSONScalar]`.
`str(error)` is safe for logs.

| Root type | Stable code families |
| --- | --- |
| `EnvelopeError` | `FORMAT_INVALID`, `FORMAT_UNSUPPORTED`, `LIMIT_EXCEEDED`, `CRITICAL_FIELD_UNSUPPORTED`, `TRAILING_DATA` |
| `AuthenticationError` | `AUTHENTICATION_FAILED` |
| `ContextMismatchError` | `CONTEXT_MISMATCH` |
| `PolicyError` | `POLICY_INVALID`, `POLICY_DENIED`, `KEY_STATE_DENIED`, `LEGACY_DENIED` |
| `ProviderError` | `PROVIDER_UNAVAILABLE`, `PROVIDER_TIMEOUT`, `PROVIDER_RATE_LIMITED`, `PROVIDER_AUTH_FAILED`, `KEY_NOT_FOUND`, `KEY_VERSION_STALE`, `CAPABILITY_UNSUPPORTED` |
| `MigrationError` | `MIGRATION_INCOMPLETE`, `MIGRATION_VERIFY_FAILED`, `MIGRATION_CONFLICT` |
| base-only operational subclasses in `errors` | `IO_FAILED`, `OUTPUT_EXISTS`, `CANCELLED`, `INTERNAL_ERROR` |

Authentication and context mismatch are distinct programmatically but default
human messages MUST be equally non-diagnostic where an oracle is plausible.
Unknown provider messages, paths, tokens, payload fragments, key material, and
context values MUST be redacted.

## API or architecture implications

`Protector` is the sole stable orchestration object. File-path convenience lives
in `streaming` and MUST apply RFC-0009-equivalent atomic/link policy. Providers
cannot be registered globally or selected from environment/import state.

## Security consequences

Callers cannot choose nonces, tags, modes, arbitrary algorithms/KDF work
factors, raw DEKs, or provider fallback. Python memory cannot guarantee DEK
zeroization; internal mutable buffers and prompt release are best effort and
must not be advertised otherwise.

## Privacy consequences

Context values can be sensitive. They are authenticated externally and only a
digest is serialized. Inspection and exceptions are redacted by construction.

## Compatibility consequences

v3 imports are removed. Additive root exports and signature changes require the
stability process; changing `ErrorCode` meaning is breaking. Unknown enum codes
must remain representable in serialized operational output.

## Operational consequences

Applications explicitly own provider instances, primary key selection, policy,
audit sink, timeouts configured on providers, and stream lifetime.

## Failure behavior

No operation returns partial success. One-shot open returns no bytes before full
authentication. Stream open writes only to SDK-owned staging until final
authentication; on failure the caller destination is unchanged where the SDK
owns the path, or the supplied sink is documented as uncommitted/staging-only.

## Alternatives considered

Module-level `seal/open`; async-first API; separate protector classes per
provider; a larger convenience facade.

## Rejected alternatives

Module globals hide ownership, async wrappers risk blocking, provider-specific
protectors fragment semantics, and convenience exports regrow the audit surface.

## Implementation constraints

Models MUST use defensive copies and frozen fields. Bytes-like inputs other than
`bytes` MAY be accepted internally but return types are exact. No implicit text
encoding is permitted.

## Test and validation requirements

Snapshot `__all__`, signatures, typing behavior, immutability, error codes,
redaction, context mismatch, no-network inspect, same-key rewrap, cancellation
at every transition, and authenticate-before-release behavior.

## Migration implications

Mapping tables must direct v3 callers either to `Protector`, explicit
RFC-0008 migration, labs, or removal; no raw helper maps directly into root.

## Unresolved questions

Whether a later minor adds native async services is deferred with API-owner
review; it cannot alter these synchronous semantics.

## Explicitly deferred work

Implementation, async API, dataclass/library selection, and performance tuning
are deferred.

## Acceptance criteria

- Root exports and signatures match this RFC exactly.
- Every error has stable code/redaction tests.
- No stable high-level path exposes prohibited controls or secret DEKs.

## Supersession rules

Root changes require an accepted API RFC, SemVer analysis, migration guidance,
and security-owner approval.
