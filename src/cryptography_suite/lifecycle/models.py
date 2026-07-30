"""Immutable lifecycle state declarations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..providers import KeyRef


class KeyState(str, Enum):
    PENDING = "PENDING"
    PRIMARY = "PRIMARY"
    DECRYPT_ONLY = "DECRYPT_ONLY"
    DISABLED = "DISABLED"
    DESTROYED = "DESTROYED"


@dataclass(frozen=True)
class KeyRecord:
    logical_key_id: str
    key: KeyRef
    state: KeyState
    generation: int

    def __post_init__(self) -> None:
        if not self.logical_key_id:
            raise ValueError("logical_key_id must be non-empty")
        if self.key.version is None:
            raise ValueError("lifecycle records require an immutable key version")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")


__all__ = ["KeyRecord", "KeyState"]
