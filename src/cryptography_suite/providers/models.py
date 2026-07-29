"""Immutable provider-neutral value models."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType


@dataclass(frozen=True)
class KeyRef:
    provider_id: str
    key_id: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not self.provider_id or self.provider_id != self.provider_id.lower():
            raise ValueError("provider_id must be a lowercase non-empty identifier")
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
        object.__setattr__(self, "opaque_bytes", bytes(self.opaque_bytes))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if not all(
            (
                self.provider_id,
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
