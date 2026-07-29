# Phase 3 public API snapshot

- **Package version:** `3.0.0`
- **Validated implementation HEAD:** `5211862d6597568e8daf912bbdab5faa4dba5e60`
- **Operational status:** declaration-only and fail-closed
- **Snapshot result:** exact match to RFC-0004

## Root facade

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

`__version__ == "3.0.0"` and is intentionally absent from `__all__`. There is
no compatibility `__getattr__`, root `seal`/`open`, primitive helper, registry,
or lazy labs export.

## Protector signatures

```text
Protector.__init__(
    self, *, provider: KeyProvider, policy: Policy, primary_key: KeyRef,
    audit_sink: AuditSink | None = None
) -> None

Protector.seal(
    self, plaintext: bytes, *, context: EncryptionContext
) -> Envelope

Protector.open(
    self, envelope: Envelope | bytes, *, context: EncryptionContext
) -> bytes

Protector.inspect(
    self, envelope: Envelope | bytes
) -> EnvelopeMetadata

Protector.rewrap(
    self, envelope: Envelope | bytes, *, destination_key: KeyRef
) -> Envelope

Protector.seal_stream(
    self, source: BinaryIO, destination: TransactionalSink, *,
    context: EncryptionContext, cancel: Callable[[], bool] | None = None
) -> EnvelopeMetadata

Protector.open_stream(
    self, source: BinaryIO, destination: TransactionalSink, *,
    context: EncryptionContext, cancel: Callable[[], bool] | None = None
) -> EnvelopeMetadata
```

All six operational methods raise an explicit `NotImplementedError` identifying
the Phase 3 boundary before a provider call, sink write, commit, filesystem
write, or cryptographic operation.

## Exception hierarchy

All stable exception types below inherit `CryptographySuiteError`:

```text
CryptographySuiteError
├── AuthenticationError
├── ContextMismatchError
├── EnvelopeError
├── MigrationError
├── PolicyError
└── ProviderError
```

Each instance exposes read-only `code`, `retryable`, and defensively copied
redacted `details`. Authentication and context-mismatch default messages are
equally nondiagnostic. Concrete exception classes reject codes outside their
RFC-0004 family. Detail values are redacted unless both the key and bounded
value are explicitly allowlisted. `ErrorCode` contains every RFC-0004 code and
represents bounded uppercase operational codes without caching unknown values
in the enum member maps.

## Public protocols

`KeyProvider` has the RFC-0006 property and exactly four methods:

```text
provider_id: str
wrap_data_key(data_key, *, key, binding, request) -> WrappedKey
unwrap_data_key(wrapped_key, *, binding, request) -> SecretBuffer
describe_key(key, *, request) -> KeyDescription
health_check(*, request) -> ProviderHealth
```

Provider identifiers use one bounded lowercase ASCII reverse-DNS validator
across every provider-neutral model. `ReadOnlySecret` exposes only `__len__`
and `readonly_view() -> memoryview`; the returned read-only view is borrowed
for the documented buffer lifetime. `SecretBuffer` adds only `close()`. No
concrete secret buffer or export API exists.

`TransactionalSink` is public only from `cryptography_suite.streaming`:

```text
max_write_size: int
write(chunk: bytes) -> None
commit() -> None
abort() -> None
```

`AuditSink.emit(event: AuditEvent) -> None` is public from the audit submodule.
`AuditEvent` has explicit optional metadata fields only: `component_id`,
`provider_id`, `key_identifier_hash`, `envelope_identifier_hash`,
`retry_attempt`, `transition`, `latency_bucket`, and
`integrity_checkpoint_ref`. It accepts no arbitrary attribute bag. No concrete
provider, fake provider, filesystem sink, audit sink, or policy evaluator is
implemented.

## Public submodule surfaces

| Submodule | `__all__` |
| --- | --- |
| `cryptography_suite.audit` | `AuditEvent`, `AuditSink` |
| `cryptography_suite.envelope` | `AuthenticationStatus`, `Envelope`, `EnvelopeMetadata` |
| `cryptography_suite.legacy` | `LegacyAdapter`, `LegacyFormat` |
| `cryptography_suite.lifecycle` | `KeyRecord`, `KeyState` |
| `cryptography_suite.providers` | `KeyCapability`, `KeyDescription`, `KeyProvider`, `KeyRef`, `ProviderHealth`, `ProviderHealthStatus`, `ProviderKeyState`, `ProviderRequest`, `ReadOnlySecret`, `SecretBuffer`, `WrappedKey` |
| `cryptography_suite.streaming` | `SinkState`, `TransactionalSink` |

`legacy` contains declarations only and is not root-imported. The package also
provides the documented root modules `context`, `errors`, `policy`, and
`protector`.

## Value-model boundary

The implemented semantics are limited to immutable defensive copies, bounded
input context storage, Unicode NFC normalization, enums, redacted error
formatting, aware-time UTC normalization, provider-identifier validation, and
nonsecret metadata declarations. Envelope recipients require immutable
`KeyRef.version` values. `Envelope` is an immutable byte container and makes no
authentication claim. `EnvelopeMetadata.authentication_status` defaults to
`not_verified`.

No context commitment, envelope parsing, encryption, decryption, key
generation, nonce generation, KDF, wrap/unwrap call, retry, policy decision,
stream processing, rewrap, migration, or legacy parsing exists.
