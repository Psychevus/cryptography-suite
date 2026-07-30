"""Secret-free audit event and sink declarations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Protocol, runtime_checkable

from ..errors import ErrorCode

_AUDIT_TOKEN_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_AUDIT_VALUE_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HASHED_IDENTIFIER_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_PROVIDER_ID_LENGTH: Final = 253
_MAX_PROVIDER_LABEL_LENGTH: Final = 63
_PROVIDER_LABEL_RE: Final = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _normalize_utc_datetime(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_provider_id(provider_id: str) -> None:
    if not isinstance(provider_id, str):
        raise TypeError("provider_id must be a string")
    if not 1 <= len(provider_id) <= _MAX_PROVIDER_ID_LENGTH:
        raise ValueError("provider_id exceeds the bounded reverse-DNS length")
    labels = provider_id.split(".")
    if len(labels) < 2 or any(
        not 1 <= len(label) <= _MAX_PROVIDER_LABEL_LENGTH
        or _PROVIDER_LABEL_RE.fullmatch(label) is None
        for label in labels
    ):
        raise ValueError("provider_id must use bounded lowercase reverse-DNS syntax")


def _validate_audit_token(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if _AUDIT_TOKEN_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a bounded non-path token")


def _validate_hashed_identifier(value: str, field_name: str) -> None:
    if _HASHED_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 identifier")


def _validate_audit_value_token(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if _AUDIT_VALUE_TOKEN_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a bounded non-path token")


@dataclass(frozen=True)
class AuditEvent:
    schema_version: str
    event_id: str
    occurred_at: datetime
    operation_id: str
    event_type: str
    outcome: str
    policy_id: str
    error_code: ErrorCode | None = None
    component_id: str | None = None
    provider_id: str | None = None
    key_identifier_hash: str | None = None
    envelope_identifier_hash: str | None = None
    retry_attempt: int | None = None
    transition: str | None = None
    latency_bucket: str | None = None
    integrity_checkpoint_ref: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != "cs-audit/1":
            raise ValueError("unsupported audit schema")
        if self.error_code is not None and not isinstance(self.error_code, ErrorCode):
            raise TypeError("error_code must be ErrorCode or None")
        object.__setattr__(
            self,
            "occurred_at",
            _normalize_utc_datetime(self.occurred_at, "occurred_at"),
        )
        for field_name in (
            "event_id",
            "operation_id",
            "event_type",
            "outcome",
            "policy_id",
        ):
            _validate_audit_token(getattr(self, field_name), field_name)
        if self.component_id is not None:
            _validate_audit_token(self.component_id, "component_id")
        for field_name, value in (
            ("transition", self.transition),
            ("latency_bucket", self.latency_bucket),
            ("integrity_checkpoint_ref", self.integrity_checkpoint_ref),
        ):
            if value is not None:
                _validate_audit_value_token(value, field_name)
        if self.provider_id is not None:
            _validate_provider_id(self.provider_id)
        for field_name in (
            "key_identifier_hash",
            "envelope_identifier_hash",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _validate_hashed_identifier(value, field_name)
        if self.retry_attempt is not None and (
            type(self.retry_attempt) is not int or not 0 <= self.retry_attempt <= 100
        ):
            raise ValueError("retry_attempt must be an integer from 0 through 100")


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


__all__ = ["AuditEvent", "AuditSink"]
