"""Immutable external encryption-context value model."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

ContextValue: TypeAlias = str | bytes

_MAX_CONTEXT_BYTES = 1024 * 1024


@dataclass(frozen=True, init=False)
class EncryptionContext(Mapping[str, ContextValue]):
    """A bounded, immutable context mapping.

    This Phase 3 model performs no commitment, hashing, or encoding. Context
    commitment construction remains explicitly unimplemented.
    """

    _values: Mapping[str, ContextValue]

    def __init__(
        self,
        values: Mapping[str, ContextValue] | None = None,
        *,
        purpose: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        source = {} if values is None else dict(values)
        if purpose is not None:
            if "purpose" in source:
                raise ValueError("purpose must be supplied only once")
            source["purpose"] = purpose
        if tenant_id is not None:
            if "tenant_id" in source:
                raise ValueError("tenant_id must be supplied only once")
            source["tenant_id"] = tenant_id

        normalized: dict[str, ContextValue] = {}
        total_bytes = 0
        for raw_key, raw_value in source.items():
            if not isinstance(raw_key, str):
                raise TypeError("context keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if not key:
                raise ValueError("context keys must not be empty")
            if key in normalized:
                raise ValueError("normalized context keys must be unique")

            key_bytes = key.encode("utf-8")
            if isinstance(raw_value, str):
                normalized_text = unicodedata.normalize("NFC", raw_value)
                value: ContextValue = normalized_text
                value_bytes = normalized_text.encode("utf-8")
            elif isinstance(raw_value, bytes):
                value = bytes(raw_value)
                value_bytes = value
            else:
                raise TypeError("context values must be strings or bytes")

            total_bytes += len(key_bytes) + len(value_bytes)
            if total_bytes > _MAX_CONTEXT_BYTES:
                raise ValueError("context exceeds the hard size limit")
            normalized[key] = value

        object.__setattr__(self, "_values", MappingProxyType(normalized))

    @property
    def purpose(self) -> str | None:
        value = self._values.get("purpose")
        return value if isinstance(value, str) else None

    @property
    def tenant_id(self) -> str | None:
        value = self._values.get("tenant_id")
        return value if isinstance(value, str) else None

    def __getitem__(self, key: str) -> ContextValue:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


__all__ = ["ContextValue", "EncryptionContext"]
