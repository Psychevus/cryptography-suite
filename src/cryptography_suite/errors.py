"""Stable, redacted v4 error declarations."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Final, TypeAlias

JSONScalar: TypeAlias = str | int | bool | None
_MAX_UNKNOWN_ERROR_CODE_LENGTH: Final = 64
_UNKNOWN_ERROR_CODE_RE: Final = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")


class ErrorCode(str, Enum):
    """Stable machine-readable v4 error codes.

    Unknown serialized codes remain representable so operational readers can
    preserve a code introduced by a newer compatible producer.
    """

    FORMAT_INVALID = "FORMAT_INVALID"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    CRITICAL_FIELD_UNSUPPORTED = "CRITICAL_FIELD_UNSUPPORTED"
    TRAILING_DATA = "TRAILING_DATA"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    POLICY_INVALID = "POLICY_INVALID"
    POLICY_DENIED = "POLICY_DENIED"
    KEY_STATE_DENIED = "KEY_STATE_DENIED"
    LEGACY_DENIED = "LEGACY_DENIED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_AUTH_FAILED = "PROVIDER_AUTH_FAILED"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_VERSION_STALE = "KEY_VERSION_STALE"
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    MIGRATION_INCOMPLETE = "MIGRATION_INCOMPLETE"
    MIGRATION_VERIFY_FAILED = "MIGRATION_VERIFY_FAILED"
    MIGRATION_CONFLICT = "MIGRATION_CONFLICT"
    IO_FAILED = "IO_FAILED"
    OUTPUT_EXISTS = "OUTPUT_EXISTS"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"

    @classmethod
    def _missing_(cls, value: object) -> ErrorCode | None:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= _MAX_UNKNOWN_ERROR_CODE_LENGTH
            or _UNKNOWN_ERROR_CODE_RE.fullmatch(value) is None
        ):
            return None
        member = str.__new__(cls, value)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        return member


_SAFE_MESSAGES: Final[Mapping[ErrorCode, str]] = MappingProxyType(
    {
        ErrorCode.FORMAT_INVALID: "The envelope format is invalid.",
        ErrorCode.FORMAT_UNSUPPORTED: "The envelope format is not supported.",
        ErrorCode.LIMIT_EXCEEDED: "A configured resource limit was exceeded.",
        ErrorCode.CRITICAL_FIELD_UNSUPPORTED: (
            "The envelope requires an unsupported critical feature."
        ),
        ErrorCode.TRAILING_DATA: "Unexpected trailing envelope data was found.",
        ErrorCode.AUTHENTICATION_FAILED: "The protected data could not be opened.",
        ErrorCode.CONTEXT_MISMATCH: "The protected data could not be opened.",
        ErrorCode.POLICY_INVALID: "The policy is invalid.",
        ErrorCode.POLICY_DENIED: "The policy denied the operation.",
        ErrorCode.KEY_STATE_DENIED: "The key state does not permit the operation.",
        ErrorCode.LEGACY_DENIED: "Legacy processing is not permitted.",
        ErrorCode.PROVIDER_UNAVAILABLE: "The key provider is unavailable.",
        ErrorCode.PROVIDER_TIMEOUT: "The key provider request timed out.",
        ErrorCode.PROVIDER_RATE_LIMITED: "The key provider rate-limited the request.",
        ErrorCode.PROVIDER_AUTH_FAILED: "The key provider rejected authentication.",
        ErrorCode.KEY_NOT_FOUND: "The requested key was not found.",
        ErrorCode.KEY_VERSION_STALE: "The requested key version is stale.",
        ErrorCode.CAPABILITY_UNSUPPORTED: "The requested capability is unsupported.",
        ErrorCode.MIGRATION_INCOMPLETE: "The migration did not complete.",
        ErrorCode.MIGRATION_VERIFY_FAILED: "Migration verification failed.",
        ErrorCode.MIGRATION_CONFLICT: "The migration conflicts with existing state.",
        ErrorCode.IO_FAILED: "An input or output operation failed.",
        ErrorCode.OUTPUT_EXISTS: "The output already exists.",
        ErrorCode.CANCELLED: "The operation was cancelled.",
        ErrorCode.INTERNAL_ERROR: "The operation failed safely.",
    }
)

_ENVELOPE_CODES: Final = frozenset(
    {
        ErrorCode.FORMAT_INVALID,
        ErrorCode.FORMAT_UNSUPPORTED,
        ErrorCode.LIMIT_EXCEEDED,
        ErrorCode.CRITICAL_FIELD_UNSUPPORTED,
        ErrorCode.TRAILING_DATA,
    }
)
_AUTHENTICATION_CODES: Final = frozenset({ErrorCode.AUTHENTICATION_FAILED})
_CONTEXT_CODES: Final = frozenset({ErrorCode.CONTEXT_MISMATCH})
_POLICY_CODES: Final = frozenset(
    {
        ErrorCode.POLICY_INVALID,
        ErrorCode.POLICY_DENIED,
        ErrorCode.KEY_STATE_DENIED,
        ErrorCode.LEGACY_DENIED,
    }
)
_PROVIDER_CODES: Final = frozenset(
    {
        ErrorCode.PROVIDER_UNAVAILABLE,
        ErrorCode.PROVIDER_TIMEOUT,
        ErrorCode.PROVIDER_RATE_LIMITED,
        ErrorCode.PROVIDER_AUTH_FAILED,
        ErrorCode.KEY_NOT_FOUND,
        ErrorCode.KEY_VERSION_STALE,
        ErrorCode.CAPABILITY_UNSUPPORTED,
    }
)
_MIGRATION_CODES: Final = frozenset(
    {
        ErrorCode.MIGRATION_INCOMPLETE,
        ErrorCode.MIGRATION_VERIFY_FAILED,
        ErrorCode.MIGRATION_CONFLICT,
    }
)


def _safe_detail_value(key: str, value: JSONScalar) -> JSONScalar:
    if key == "retry_attempt" and type(value) is int and 0 <= value <= 100:
        return value
    if key == "http_status_code" and type(value) is int and 100 <= value <= 599:
        return value
    return "<redacted>"


def _redact_details(
    details: Mapping[str, JSONScalar] | None,
) -> Mapping[str, JSONScalar]:
    if details is None:
        return MappingProxyType({})

    redacted: dict[str, JSONScalar] = {}
    for raw_key, value in details.items():
        key = str(raw_key)
        redacted[key] = _safe_detail_value(key, value)
    return MappingProxyType(redacted)


def _validate_code_family(
    code: ErrorCode,
    allowed: frozenset[ErrorCode],
    exception_name: str,
) -> None:
    if code not in allowed:
        raise ValueError(f"{exception_name} does not accept error code {code.value}")


class CryptographySuiteError(Exception):
    """Base class for stable errors with immutable, redacted fields."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        self._code = ErrorCode(code)
        self._retryable = bool(retryable)
        self._details = _redact_details(details)
        super().__init__(_SAFE_MESSAGES.get(self._code, "The operation failed safely."))

    @property
    def code(self) -> ErrorCode:
        return self._code

    @property
    def retryable(self) -> bool:
        return self._retryable

    @property
    def details(self) -> Mapping[str, JSONScalar]:
        return self._details


class EnvelopeError(CryptographySuiteError):
    """Envelope structure, format, or resource-limit failure."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.FORMAT_INVALID,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _ENVELOPE_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


class AuthenticationError(CryptographySuiteError):
    """Protected data authentication failure."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.AUTHENTICATION_FAILED,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _AUTHENTICATION_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


class ContextMismatchError(CryptographySuiteError):
    """Caller context did not match without identifying the mismatched value."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.CONTEXT_MISMATCH,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _CONTEXT_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


class PolicyError(CryptographySuiteError):
    """Policy validation or authorization failure."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.POLICY_INVALID,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _POLICY_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


class ProviderError(CryptographySuiteError):
    """Normalized provider failure."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.PROVIDER_UNAVAILABLE,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _PROVIDER_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


class MigrationError(CryptographySuiteError):
    """Explicit migration transaction failure."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.MIGRATION_INCOMPLETE,
        *,
        retryable: bool = False,
        details: Mapping[str, JSONScalar] | None = None,
    ) -> None:
        _validate_code_family(code, _MIGRATION_CODES, type(self).__name__)
        super().__init__(code, retryable=retryable, details=details)


__all__ = [
    "AuthenticationError",
    "ContextMismatchError",
    "CryptographySuiteError",
    "EnvelopeError",
    "ErrorCode",
    "MigrationError",
    "PolicyError",
    "ProviderError",
]
