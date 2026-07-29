"""The four-method provider protocol, without implementations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    KeyDescription,
    KeyRef,
    ProviderHealth,
    ProviderRequest,
    WrappedKey,
)


@runtime_checkable
class ReadOnlySecret(Protocol):
    def __len__(self) -> int: ...


@runtime_checkable
class SecretBuffer(Protocol):
    def __len__(self) -> int: ...

    def close(self) -> None: ...


@runtime_checkable
class KeyProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    def wrap_data_key(
        self,
        data_key: ReadOnlySecret,
        *,
        key: KeyRef,
        binding: bytes,
        request: ProviderRequest,
    ) -> WrappedKey: ...

    def unwrap_data_key(
        self,
        wrapped_key: WrappedKey,
        *,
        binding: bytes,
        request: ProviderRequest,
    ) -> SecretBuffer: ...

    def describe_key(
        self,
        key: KeyRef,
        *,
        request: ProviderRequest,
    ) -> KeyDescription: ...

    def health_check(
        self,
        *,
        request: ProviderRequest,
    ) -> ProviderHealth: ...


__all__ = ["KeyProvider", "ReadOnlySecret", "SecretBuffer"]
