from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from cryptography_suite import (
    AuthenticationError,
    ContextMismatchError,
    CryptographySuiteError,
    EncryptionContext,
    Envelope,
    EnvelopeMetadata,
    ErrorCode,
    KeyRef,
    Policy,
)
from cryptography_suite.envelope import AuthenticationStatus


def test_encryption_context_is_immutable_and_defensively_copied() -> None:
    source: dict[str, str | bytes] = {
        "purpose": "billing",
        "opaque": b"value",
    }
    context = EncryptionContext(source)
    source["purpose"] = "changed"

    assert context.purpose == "billing"
    assert context["opaque"] == b"value"
    with pytest.raises(TypeError):
        context._values["new"] = "value"  # type: ignore[index]


def test_encryption_context_rejects_normalized_duplicate() -> None:
    with pytest.raises(ValueError):
        EncryptionContext({"e\u0301": "one", "\u00e9": "two"})


def test_envelope_is_only_an_immutable_container() -> None:
    envelope = Envelope(b"not-an-authenticated-envelope")
    assert bytes(envelope) == b"not-an-authenticated-envelope"
    with pytest.raises(FrozenInstanceError):
        envelope.data = b"changed"  # type: ignore[misc]


def test_metadata_defaults_to_not_verified_and_copies_sequences() -> None:
    recipients = [KeyRef("example.provider", "key", "1")]
    features = ["feature"]
    metadata = EnvelopeMetadata(
        format_name="unimplemented-v4",
        profile="declaration",
        major_version=4,
        minor_version=0,
        algorithm_suite="unassigned",
        recipients=tuple(recipients),
        plaintext_size=None,
        ciphertext_size=0,
        chunk_count=0,
        context_commitment_id=None,
        created_at=datetime.now(timezone.utc),
        critical_features=tuple(features),
        policy_id="uncomputed",
    )
    recipients.clear()
    features.clear()

    assert metadata.authentication_status is AuthenticationStatus.NOT_VERIFIED
    assert len(metadata.recipients) == 1
    assert metadata.critical_features == ("feature",)


def test_metadata_rejects_unresolved_recipient_versions() -> None:
    with pytest.raises(ValueError, match="immutable key versions"):
        EnvelopeMetadata(
            format_name="unimplemented-v4",
            profile="declaration",
            major_version=4,
            minor_version=0,
            algorithm_suite="unassigned",
            recipients=(KeyRef("example.provider", "alias"),),
            plaintext_size=None,
            ciphertext_size=0,
            chunk_count=0,
            context_commitment_id=None,
            created_at=None,
            critical_features=(),
            policy_id="uncomputed",
        )


def test_metadata_normalizes_aware_time_and_rejects_naive_time() -> None:
    local_time = datetime(
        2026,
        1,
        2,
        12,
        tzinfo=timezone(timedelta(hours=3, minutes=30)),
    )
    metadata = EnvelopeMetadata(
        format_name="unimplemented-v4",
        profile="declaration",
        major_version=4,
        minor_version=0,
        algorithm_suite="unassigned",
        recipients=(KeyRef("example.provider", "key", "1"),),
        plaintext_size=None,
        ciphertext_size=0,
        chunk_count=0,
        context_commitment_id=None,
        created_at=local_time,
        critical_features=(),
        policy_id="uncomputed",
    )
    assert metadata.created_at == datetime(
        2026,
        1,
        2,
        8,
        30,
        tzinfo=timezone.utc,
    )
    assert metadata.created_at.tzinfo is timezone.utc

    with pytest.raises(ValueError, match="timezone-aware"):
        EnvelopeMetadata(
            format_name="unimplemented-v4",
            profile="declaration",
            major_version=4,
            minor_version=0,
            algorithm_suite="unassigned",
            recipients=(KeyRef("example.provider", "key", "1"),),
            plaintext_size=None,
            ciphertext_size=0,
            chunk_count=0,
            context_commitment_id=None,
            created_at=datetime(2026, 1, 2),
            critical_features=(),
            policy_id="uncomputed",
        )


def test_errors_are_typed_immutable_and_redacted() -> None:
    error = CryptographySuiteError(
        ErrorCode.INTERNAL_ERROR,
        details={"plaintext": "sensitive-value", "attempt": 2},
    )

    assert error.code is ErrorCode.INTERNAL_ERROR
    assert error.retryable is False
    assert error.details == {
        "plaintext": "<redacted>",
        "attempt": "<redacted>",
    }
    assert "sensitive-value" not in str(error)
    with pytest.raises(TypeError):
        error.details["new"] = "value"  # type: ignore[index]
    with pytest.raises(AttributeError):
        error.code = ErrorCode.CANCELLED  # type: ignore[misc]


def test_authentication_and_context_messages_are_equally_nondiagnostic() -> None:
    assert str(AuthenticationError()) == str(ContextMismatchError())


def test_unknown_error_code_remains_representable() -> None:
    code = ErrorCode("FUTURE_OPERATIONAL_CODE")
    assert code.value == "FUTURE_OPERATIONAL_CODE"


def test_policy_is_a_non_operational_frozen_identifier() -> None:
    policy = Policy("application-assigned-id")
    with pytest.raises(FrozenInstanceError):
        policy.profile = "changed"  # type: ignore[misc]
    with pytest.raises(NotImplementedError):
        Policy.enterprise(approved_providers=["example.provider"])
