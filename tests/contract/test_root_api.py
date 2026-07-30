from __future__ import annotations

import inspect

import cryptography_suite as suite
from cryptography_suite import Protector

EXPECTED_ROOT = [
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

EXPECTED_SIGNATURES = {
    "__init__": (
        "(self, *, provider: 'KeyProvider', policy: 'Policy', "
        "primary_key: 'KeyRef', audit_sink: 'AuditSink | None' = None) -> 'None'"
    ),
    "seal": (
        "(self, plaintext: 'bytes', *, context: 'EncryptionContext') -> 'Envelope'"
    ),
    "open": (
        "(self, envelope: 'Envelope | bytes', *, "
        "context: 'EncryptionContext') -> 'bytes'"
    ),
    "inspect": "(self, envelope: 'Envelope | bytes') -> 'EnvelopeMetadata'",
    "rewrap": (
        "(self, envelope: 'Envelope | bytes', *, "
        "destination_key: 'KeyRef') -> 'Envelope'"
    ),
    "seal_stream": (
        "(self, source: 'BinaryIO', destination: 'TransactionalSink', *, "
        "context: 'EncryptionContext', cancel: 'Callable[[], bool] | None' = "
        "None) -> 'EnvelopeMetadata'"
    ),
    "open_stream": (
        "(self, source: 'BinaryIO', destination: 'TransactionalSink', *, "
        "context: 'EncryptionContext', cancel: 'Callable[[], bool] | None' = "
        "None) -> 'EnvelopeMetadata'"
    ),
}


def test_root_all_is_exact() -> None:
    assert suite.__all__ == EXPECTED_ROOT
    assert len(suite.__all__) == 15
    assert suite.__version__ == "3.0.0"
    assert "__version__" not in suite.__all__


def test_no_compatibility_export_hook() -> None:
    assert "__getattr__" not in vars(suite)
    assert "seal" not in vars(suite)
    assert "open" not in vars(suite)


def test_protector_signatures_match_rfc_0004() -> None:
    actual = {
        name: str(inspect.signature(getattr(Protector, name)))
        for name in EXPECTED_SIGNATURES
    }
    assert actual == EXPECTED_SIGNATURES
