from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from types import MappingProxyType

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
from cryptography_suite.audit import AuditEvent
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


def test_audit_event_attributes_are_portable_immutable_and_copied() -> None:
    occurred_at = datetime.now(timezone.utc)
    first = AuditEvent(
        schema_version="cs-audit/1",
        event_id="event-1",
        occurred_at=occurred_at,
        operation_id="operation-1",
        event_type="declaration",
        outcome="not-implemented",
        policy_id="policy-1",
    )
    second = AuditEvent(
        schema_version="cs-audit/1",
        event_id="event-2",
        occurred_at=occurred_at,
        operation_id="operation-2",
        event_type="declaration",
        outcome="not-implemented",
        policy_id="policy-2",
    )

    assert first.attributes == {}
    assert second.attributes == {}
    assert isinstance(first.attributes, MappingProxyType)
    assert isinstance(second.attributes, MappingProxyType)
    assert first.attributes is not second.attributes

    supplied: dict[str, str | int] = {
        "component": "unit",
        "attempt": 1,
    }
    explicit = AuditEvent(
        schema_version="cs-audit/1",
        event_id="event-3",
        occurred_at=occurred_at,
        operation_id="operation-3",
        event_type="declaration",
        outcome="not-implemented",
        policy_id="policy-3",
        attributes=supplied,
    )
    supplied["component"] = "changed"
    supplied["attempt"] = 2

    assert explicit.attributes == {
        "component": "unit",
        "attempt": 1,
    }
    assert isinstance(explicit.attributes, MappingProxyType)


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
