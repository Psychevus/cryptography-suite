from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pytest

from cryptography_suite.providers import (
    KeyDescription,
    KeyProvider,
    KeyRef,
    ProviderHealth,
    ProviderHealthStatus,
    ProviderRequest,
    ReadOnlySecret,
    SecretBuffer,
    WrappedKey,
)


class BorrowedSecret:
    def __init__(self, value: bytes) -> None:
        self._value = bytearray(value)
        self.closed = False

    def __len__(self) -> int:
        return len(self._value)

    def readonly_view(self) -> memoryview:
        if self.closed:
            raise RuntimeError("secret buffer is closed")
        return memoryview(self._value).toreadonly()

    def close(self) -> None:
        self.closed = True
        self._value.clear()


class StructuralProviderSpy:
    @property
    def provider_id(self) -> str:
        return "example.provider"

    def wrap_data_key(
        self,
        data_key: ReadOnlySecret,
        *,
        key: KeyRef,
        binding: bytes,
        request: ProviderRequest,
    ) -> WrappedKey:
        del data_key, key, binding, request
        raise AssertionError("structural provider spy must not be called")

    def unwrap_data_key(
        self,
        wrapped_key: WrappedKey,
        *,
        binding: bytes,
        request: ProviderRequest,
    ) -> SecretBuffer:
        del wrapped_key, binding, request
        raise AssertionError("structural provider spy must not be called")

    def describe_key(
        self,
        key: KeyRef,
        *,
        request: ProviderRequest,
    ) -> KeyDescription:
        del key, request
        raise AssertionError("structural provider spy must not be called")

    def health_check(
        self,
        *,
        request: ProviderRequest,
    ) -> ProviderHealth:
        del request
        raise AssertionError("structural provider spy must not be called")


def test_secret_protocol_exposes_only_borrowed_readonly_access() -> None:
    secret = BorrowedSecret(b"secret")

    assert isinstance(secret, ReadOnlySecret)
    assert isinstance(secret, SecretBuffer)
    assert len(secret) == 6
    view = secret.readonly_view()
    assert view.readonly is True
    assert bytes(view) == b"secret"
    with pytest.raises(TypeError):
        view[0] = 0

    view.release()
    secret.close()
    assert secret.closed is True
    with pytest.raises(RuntimeError):
        secret.readonly_view()


def test_secret_and_provider_protocol_signatures_are_exact() -> None:
    assert str(inspect.signature(ReadOnlySecret.readonly_view)) == (
        "(self) -> 'memoryview'"
    )
    assert "borrowed" in (ReadOnlySecret.readonly_view.__doc__ or "").lower()
    operations = {
        name
        for name, value in vars(KeyProvider).items()
        if callable(value) and not name.startswith("_")
    }
    assert operations == {
        "describe_key",
        "health_check",
        "unwrap_data_key",
        "wrap_data_key",
    }
    assert isinstance(StructuralProviderSpy(), KeyProvider)


def test_provider_identifier_uses_bounded_reverse_dns_grammar() -> None:
    maximum = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
    for provider_id in ("a.b", "example.provider", "kms.us-east-1.example", maximum):
        assert KeyRef(provider_id, "key", "1").provider_id == provider_id

    invalid = (
        "../local",
        "a/b",
        ".",
        "Example.Provider",
        "example..provider",
        "-example.provider",
        "example-.provider",
        "example.provider-",
        "example\\provider",
        "example:provider",
        "example provider",
        "exampłe.provider",
        "single",
        "a" * 254,
    )
    for provider_id in invalid:
        with pytest.raises(ValueError):
            KeyRef(provider_id, "key", "1")


def test_provider_identifier_validation_is_shared_by_provider_models() -> None:
    observed_at = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        WrappedKey(
            provider_id="../local",
            key_id="key",
            version="1",
            wrapping_algorithm="unassigned",
            opaque_bytes=b"",
            metadata={},
        )
    with pytest.raises(ValueError):
        ProviderHealth(
            provider_id="example..provider",
            status=ProviderHealthStatus.UNKNOWN,
            observed_at=observed_at,
        )
