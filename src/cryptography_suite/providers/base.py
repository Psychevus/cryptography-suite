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
    """Borrowed secret access valid only for the owning buffer's lifetime."""

    def __len__(self) -> int: ...

    def readonly_view(self) -> memoryview:
        """Return a borrowed read-only view that must not outlive the buffer."""
        ...


@runtime_checkable
class SecretBuffer(ReadOnlySecret, Protocol):
    """Closable secret storage without serialization or raw export methods."""

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
