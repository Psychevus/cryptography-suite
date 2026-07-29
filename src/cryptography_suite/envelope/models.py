"""Immutable, non-authenticating envelope value models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..providers.models import KeyRef

_MAX_ENVELOPE_BYTES = 1024**4


class AuthenticationStatus(str, Enum):
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    PRESERVED_NOT_REVERIFIED = "preserved_not_reverified"


@dataclass(frozen=True, init=False)
class Envelope:
    """An immutable byte container that makes no authentication claim."""

    data: bytes

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("envelope data must be bytes")
        if len(data) > _MAX_ENVELOPE_BYTES:
            raise ValueError("envelope exceeds the hard size limit")
        object.__setattr__(self, "data", bytes(data))

    def __bytes__(self) -> bytes:
        return self.data


@dataclass(frozen=True)
class EnvelopeMetadata:
    """A redacted structural view; authentication is explicit."""

    format_name: str
    profile: str
    major_version: int
    minor_version: int
    algorithm_suite: str
    recipients: tuple[KeyRef, ...]
    plaintext_size: int | None
    ciphertext_size: int
    chunk_count: int
    context_commitment_id: str | None
    created_at: datetime | None
    critical_features: tuple[str, ...]
    policy_id: str
    authentication_status: AuthenticationStatus = AuthenticationStatus.NOT_VERIFIED

    def __post_init__(self) -> None:
        object.__setattr__(self, "recipients", tuple(self.recipients))
        object.__setattr__(self, "critical_features", tuple(self.critical_features))
        for value in (
            self.major_version,
            self.minor_version,
            self.ciphertext_size,
            self.chunk_count,
        ):
            if value < 0:
                raise ValueError("metadata counts and versions must be non-negative")
        if self.plaintext_size is not None and self.plaintext_size < 0:
            raise ValueError("plaintext_size must be non-negative when present")


__all__ = ["AuthenticationStatus", "Envelope", "EnvelopeMetadata"]
