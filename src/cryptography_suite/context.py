"""Immutable external encryption-context value model."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

ContextValue: TypeAlias = str | bytes

_MAX_CONTEXT_INPUT_ENTRIES = 128
_MAX_CONTEXT_INPUT_STORAGE_BYTES = 1024 * 1024


@dataclass(frozen=True, init=False)
class EncryptionContext(Mapping[str, ContextValue]):
    """A bounded, immutable context mapping.

    Phase 3 bounds retained input storage only. This is not a canonical encoded
    size guarantee and performs no commitment, hashing, or encoding.
    """

    _values: Mapping[str, ContextValue]

    def __init__(
        self,
        values: Mapping[str, ContextValue] | None = None,
        *,
        purpose: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        normalized: dict[str, ContextValue] = {}
        total_bytes = 0
        entry_count = 0

        def retain(
            raw_key: str,
            raw_value: ContextValue,
            *,
            duplicate_message: str | None = None,
        ) -> None:
            nonlocal entry_count, total_bytes
            entry_count += 1
            if entry_count > _MAX_CONTEXT_INPUT_ENTRIES:
                raise ValueError("context exceeds the hard input entry limit")
            if not isinstance(raw_key, str):
                raise TypeError("context keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if not key:
                raise ValueError("context keys must not be empty")
            if key in normalized:
                raise ValueError(
                    duplicate_message or "normalized context keys must be unique"
                )

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

            retained_bytes = len(key_bytes) + len(value_bytes)
            if retained_bytes > _MAX_CONTEXT_INPUT_STORAGE_BYTES - total_bytes:
                raise ValueError("context exceeds the hard input storage limit")
            total_bytes += retained_bytes
            normalized[key] = value

        if values is not None:
            for raw_key, raw_value in values.items():
                retain(raw_key, raw_value)
        if purpose is not None:
            retain(
                "purpose",
                purpose,
                duplicate_message="purpose must be supplied only once",
            )
        if tenant_id is not None:
            retain(
                "tenant_id",
                tenant_id,
                duplicate_message="tenant_id must be supplied only once",
            )

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
