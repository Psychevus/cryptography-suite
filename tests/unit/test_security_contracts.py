from __future__ import annotations

from collections.abc import Iterator, Mapping

import pytest

from cryptography_suite import (
    AuthenticationError,
    ContextMismatchError,
    CryptographySuiteError,
    EncryptionContext,
    EnvelopeError,
    ErrorCode,
    MigrationError,
    PolicyError,
    ProviderError,
)


class CountingMapping(Mapping[str, str]):
    def __init__(self, size: int) -> None:
        self.size = size
        self.value_reads = 0

    def __getitem__(self, key: str) -> str:
        self.value_reads += 1
        return f"value-{key}"

    def __iter__(self) -> Iterator[str]:
        return (f"key-{index}" for index in range(self.size))

    def __len__(self) -> int:
        return self.size


def test_unknown_error_codes_are_bounded_and_never_cached() -> None:
    member_count = len(ErrorCode._member_map_)
    value_count = len(ErrorCode._value2member_map_)

    for index in range(1_000):
        value = f"FUTURE_OPERATIONAL_{index}"
        assert ErrorCode(value).value == value

    assert len(ErrorCode._member_map_) == member_count
    assert len(ErrorCode._value2member_map_) == value_count

    for malformed in (
        "",
        "lowercase",
        "BAD-CODE",
        "BAD CODE",
        "_BAD",
        "BAD_",
        "BAD__CODE",
        "A" * 65,
    ):
        with pytest.raises(ValueError):
            ErrorCode(malformed)


def test_error_details_redact_secrets_and_allow_only_safe_bounded_fields() -> None:
    supplied: dict[str, str | int] = {
        "pin": 1234,
        "otp": 654321,
        "account_number": 998877665544,
        "path": "/private/customer/file",
        "token": "secret-token",
        "context_value": "tenant-secret",
        "provider_payload": "raw-provider-response",
        "exception_text": "credential rejected: hunter2",
        "retry_attempt": 2,
        "http_status_code": 429,
        "unsafe_retry_attempt": 500,
    }
    error = CryptographySuiteError(ErrorCode.INTERNAL_ERROR, details=supplied)

    assert error.details == {
        "pin": "<redacted>",
        "otp": "<redacted>",
        "account_number": "<redacted>",
        "path": "<redacted>",
        "token": "<redacted>",
        "context_value": "<redacted>",
        "provider_payload": "<redacted>",
        "exception_text": "<redacted>",
        "retry_attempt": 2,
        "http_status_code": 429,
        "unsafe_retry_attempt": "<redacted>",
    }
    rendered = f"{error!s} {error!r} {error.details!r}"
    for secret in (
        "1234",
        "654321",
        "998877665544",
        "/private/customer/file",
        "secret-token",
        "tenant-secret",
        "raw-provider-response",
        "hunter2",
        "500",
    ):
        assert secret not in rendered


def test_concrete_exceptions_enforce_rfc_0004_code_families() -> None:
    valid = (
        EnvelopeError(ErrorCode.LIMIT_EXCEEDED),
        AuthenticationError(ErrorCode.AUTHENTICATION_FAILED),
        ContextMismatchError(ErrorCode.CONTEXT_MISMATCH),
        PolicyError(ErrorCode.POLICY_DENIED),
        ProviderError(ErrorCode.PROVIDER_TIMEOUT),
        MigrationError(ErrorCode.MIGRATION_CONFLICT),
    )
    assert [error.code for error in valid] == [
        ErrorCode.LIMIT_EXCEEDED,
        ErrorCode.AUTHENTICATION_FAILED,
        ErrorCode.CONTEXT_MISMATCH,
        ErrorCode.POLICY_DENIED,
        ErrorCode.PROVIDER_TIMEOUT,
        ErrorCode.MIGRATION_CONFLICT,
    ]

    invalid: tuple[
        tuple[type[CryptographySuiteError], ErrorCode],
        ...,
    ] = (
        (EnvelopeError, ErrorCode.PROVIDER_TIMEOUT),
        (AuthenticationError, ErrorCode.CONTEXT_MISMATCH),
        (ContextMismatchError, ErrorCode.AUTHENTICATION_FAILED),
        (PolicyError, ErrorCode.FORMAT_INVALID),
        (ProviderError, ErrorCode.MIGRATION_CONFLICT),
        (MigrationError, ErrorCode.IO_FAILED),
        (ProviderError, ErrorCode("FUTURE_PROVIDER_CODE")),
    )
    for exception_type, code in invalid:
        with pytest.raises(ValueError):
            exception_type(code)

    unknown = ErrorCode("FUTURE_OPERATIONAL_CODE")
    assert CryptographySuiteError(unknown).code.value == "FUTURE_OPERATIONAL_CODE"


def test_context_stops_at_entry_bound_without_copying_large_mapping() -> None:
    source = CountingMapping(10_000)

    with pytest.raises(ValueError, match="input entry limit"):
        EncryptionContext(source)

    assert source.value_reads == 129
    assert source.value_reads < len(source)


def test_context_checks_storage_bound_before_retaining_oversized_value() -> None:
    with pytest.raises(ValueError, match="input storage limit"):
        EncryptionContext({"purpose": "x" * (1024 * 1024)})
