from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from cryptography_suite.audit import AuditEvent
from cryptography_suite.errors import ErrorCode


def _audit_event(*, occurred_at: datetime | None = None) -> AuditEvent:
    return AuditEvent(
        schema_version="cs-audit/1",
        event_id="event-1",
        occurred_at=occurred_at or datetime.now(timezone.utc),
        operation_id="operation-1",
        event_type="provider.call",
        outcome="failed",
        policy_id="policy-1",
    )


def test_audit_event_accepts_only_explicit_allowlisted_metadata() -> None:
    digest = "sha256:" + ("a" * 64)
    event = AuditEvent(
        schema_version="cs-audit/1",
        event_id="event-1",
        occurred_at=datetime.now(timezone.utc),
        operation_id="operation-1",
        event_type="provider.call",
        outcome="failed",
        policy_id="policy-1",
        error_code=ErrorCode.PROVIDER_TIMEOUT,
        component_id="protector",
        provider_id="example.provider",
        key_identifier_hash=digest,
        envelope_identifier_hash=digest,
        retry_attempt=2,
        transition="started",
        latency_bucket="10-99ms",
        integrity_checkpoint_ref="checkpoint:one",
    )

    assert event.provider_id == "example.provider"
    assert event.key_identifier_hash == digest
    assert event.retry_attempt == 2
    frozen_field = "outcome"
    with pytest.raises(FrozenInstanceError):
        setattr(event, frozen_field, "changed")

    parameters = set(inspect.signature(AuditEvent).parameters)
    forbidden = {
        "attributes",
        "ciphertext",
        "context",
        "credential",
        "data_key",
        "exception",
        "nonce",
        "password",
        "path",
        "payload",
        "plaintext",
        "wrapped_key",
    }
    assert parameters.isdisjoint(forbidden)


def test_audit_event_rejects_arbitrary_attribute_bag() -> None:
    pytest.raises(
        TypeError,
        AuditEvent,
        schema_version="cs-audit/1",
        event_id="event-1",
        occurred_at=datetime.now(timezone.utc),
        operation_id="operation-1",
        event_type="provider.call",
        outcome="failed",
        policy_id="policy-1",
        attributes={"plaintext": "secret"},
    )


def test_audit_event_validates_identifiers_and_ranges() -> None:
    event = _audit_event()
    digest = "sha256:" + ("b" * 64)
    assert replace(event, key_identifier_hash=digest).key_identifier_hash == digest

    invalid_changes: tuple[Callable[[], AuditEvent], ...] = (
        lambda: replace(event, component_id="../component"),
        lambda: replace(event, provider_id="../provider"),
        lambda: replace(event, key_identifier_hash="raw-key-id"),
        lambda: replace(event, envelope_identifier_hash="sha256:ABC"),
        lambda: replace(event, retry_attempt=-1),
        lambda: replace(event, retry_attempt=101),
        lambda: replace(event, retry_attempt=True),
        lambda: replace(event, transition="path/to/state"),
        lambda: replace(event, latency_bucket=" "),
        lambda: replace(event, integrity_checkpoint_ref="C:\\checkpoint"),
    )
    for invalid_change in invalid_changes:
        with pytest.raises((TypeError, ValueError)):
            invalid_change()


def test_audit_event_rejects_naive_and_normalizes_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _audit_event(occurred_at=datetime(2026, 1, 2, 12))

    non_utc = datetime(
        2026,
        1,
        2,
        12,
        tzinfo=timezone(timedelta(hours=2)),
    )
    event = _audit_event(occurred_at=non_utc)
    assert event.occurred_at == datetime(
        2026,
        1,
        2,
        10,
        tzinfo=timezone.utc,
    )
    assert event.occurred_at.tzinfo is timezone.utc


def test_audit_event_accepts_only_error_code_members() -> None:
    event = _audit_event()
    unknown = ErrorCode("FUTURE_PROVIDER_FAILURE")

    assert event.error_code is None
    assert replace(event, error_code=ErrorCode.PROVIDER_TIMEOUT).error_code is (
        ErrorCode.PROVIDER_TIMEOUT
    )
    assert replace(event, error_code=unknown).error_code is unknown

    for invalid in (
        "PROVIDER_TIMEOUT",
        7,
        {"code": "PROVIDER_TIMEOUT"},
    ):
        captured = pytest.raises(
            TypeError,
            AuditEvent,
            schema_version="cs-audit/1",
            event_id="event-1",
            occurred_at=datetime.now(timezone.utc),
            operation_id="operation-1",
            event_type="provider.call",
            outcome="failed",
            policy_id="policy-1",
            error_code=invalid,
        )
        assert str(captured.value) == "error_code must be ErrorCode or None"


def test_audit_event_rejects_exception_without_retaining_secret_text() -> None:
    event = _audit_event()
    secret = "provider-credential-secret"
    provider_error = RuntimeError(secret)

    captured = pytest.raises(
        TypeError,
        AuditEvent,
        schema_version="cs-audit/1",
        event_id="event-1",
        occurred_at=datetime.now(timezone.utc),
        operation_id="operation-1",
        event_type="provider.call",
        outcome="failed",
        policy_id="policy-1",
        error_code=provider_error,
    )

    assert str(captured.value) == "error_code must be ErrorCode or None"
    assert secret not in str(captured.value)
    assert event.error_code is None
