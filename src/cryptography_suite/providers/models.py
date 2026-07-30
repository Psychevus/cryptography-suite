"""Immutable provider-neutral value models."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Final

_MAX_PROVIDER_ID_LENGTH: Final = 253
_MAX_PROVIDER_LABEL_LENGTH: Final = 63
_PROVIDER_LABEL_RE: Final = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")


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


def _normalize_utc_datetime(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class KeyRef:
    provider_id: str
    key_id: str
    version: str | None = None

    def __post_init__(self) -> None:
        _validate_provider_id(self.provider_id)
        if not self.key_id:
            raise ValueError("key_id must be non-empty")
        if self.version == "":
            raise ValueError("version must be non-empty when present")


@dataclass(frozen=True)
class ProviderRequest:
    deadline: datetime | None
    cancel: Callable[[], bool] | None
    operation_id: str
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        if self.deadline is not None:
            object.__setattr__(
                self,
                "deadline",
                _normalize_utc_datetime(self.deadline, "deadline"),
            )
        if not self.operation_id:
            raise ValueError("operation_id must be non-empty")


@dataclass(frozen=True)
class WrappedKey:
    provider_id: str
    key_id: str
    version: str
    wrapping_algorithm: str
    opaque_bytes: bytes
    metadata: Mapping[str, str]

    def __post_init__(self) -> None:
        _validate_provider_id(self.provider_id)
        object.__setattr__(self, "opaque_bytes", bytes(self.opaque_bytes))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if not all(
            (
                self.key_id,
                self.version,
                self.wrapping_algorithm,
            )
        ):
            raise ValueError("wrapped-key identifiers must be non-empty")


class KeyCapability(str, Enum):
    WRAP = "wrap"
    UNWRAP = "unwrap"


class ProviderKeyState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    DESTROYED = "destroyed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class KeyDescription:
    key: KeyRef
    capabilities: frozenset[KeyCapability]
    state: ProviderKeyState
    observed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(
            self,
            "observed_at",
            _normalize_utc_datetime(self.observed_at, "observed_at"),
        )
        if self.key.version is None:
            raise ValueError("described keys require an immutable version")


class ProviderHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderHealth:
    provider_id: str
    status: ProviderHealthStatus
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_provider_id(self.provider_id)
        object.__setattr__(
            self,
            "observed_at",
            _normalize_utc_datetime(self.observed_at, "observed_at"),
        )


__all__ = [
    "KeyCapability",
    "KeyDescription",
    "KeyRef",
    "ProviderHealth",
    "ProviderHealthStatus",
    "ProviderKeyState",
    "ProviderRequest",
    "WrappedKey",
]
