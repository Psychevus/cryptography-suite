# Phase 3 public API snapshot

- **Package version:** `3.0.0`
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
equally nondiagnostic. `ErrorCode` contains every RFC-0004 code and preserves
unknown nonempty serialized operational codes.

## Public protocols

`KeyProvider` has the RFC-0006 property and exactly four methods:

```text
provider_id: str
wrap_data_key(data_key, *, key, binding, request) -> WrappedKey
unwrap_data_key(wrapped_key, *, binding, request) -> SecretBuffer
describe_key(key, *, request) -> KeyDescription
health_check(*, request) -> ProviderHealth
```

`TransactionalSink` is public only from `cryptography_suite.streaming`:

```text
max_write_size: int
write(chunk: bytes) -> None
commit() -> None
abort() -> None
```

`AuditSink.emit(event: AuditEvent) -> None` is public from the audit submodule.
No concrete provider, fake provider, filesystem sink, audit sink, or policy
evaluator is implemented.

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
context storage, Unicode NFC normalization, enums, redacted error formatting,
and nonsecret metadata declarations. `Envelope` is an immutable byte container
and makes no authentication claim. `EnvelopeMetadata.authentication_status`
defaults to `not_verified`.

No context commitment, envelope parsing, encryption, decryption, key
generation, nonce generation, KDF, wrap/unwrap call, retry, policy decision,
stream processing, rewrap, migration, or legacy parsing exists.
