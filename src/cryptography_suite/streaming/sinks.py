"""Transactional output protocol declaration."""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable


class SinkState(str, Enum):
    OPEN = "open"
    COMMITTED = "committed"
    ABORTED = "aborted"


@runtime_checkable
class TransactionalSink(Protocol):
    @property
    def max_write_size(self) -> int: ...

    def write(self, chunk: bytes) -> None: ...

    def commit(self) -> None: ...

    def abort(self) -> None: ...


__all__ = ["SinkState", "TransactionalSink"]
