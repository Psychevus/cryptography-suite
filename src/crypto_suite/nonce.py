from __future__ import annotations

import threading
from hmac import compare_digest
from typing import Iterator, Protocol, Optional


class KeyRotationRequired(RuntimeError):
    """Signal that cryptographic keys should be rotated."""


class NonceReuseError(RuntimeError):
    """Raised when a nonce is reused."""


class StateStore(Protocol):
    """Minimal protocol for storing seen nonces."""

    def __iter__(self) -> Iterator[bytes]:
        ...

    def add(self, item: bytes) -> None:
        ...


class NonceManager:
    """Manage monotonically increasing 96-bit nonces."""

    _counter: int
    _limit: int
    _storage: StateStore
    _lock: threading.Lock

    def __init__(
        self,
        *,
        start: int = 0,
        limit: int = 2**32,
        storage: Optional[StateStore] = None,
    ) -> None:
        if start < 0:
            raise ValueError("start must be non-negative")
        if limit <= start:
            raise ValueError("limit must be greater than start")
        self._counter = start
        self._limit = limit
        self._storage = storage if storage is not None else set()
        self._lock = threading.Lock()

    def next(self) -> bytes:
        """Return the next unique 96-bit nonce."""
        with self._lock:
            if self._counter >= self._limit:
                raise KeyRotationRequired("nonce limit reached")
            value = self._counter
            self._counter += 1
            nonce = value.to_bytes(12, "big")
            self._remember_locked(nonce)
            return nonce

    def remember(self, nonce: bytes) -> None:
        """Record an externally provided nonce."""
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        with self._lock:
            self._remember_locked(nonce)

    def _remember_locked(self, nonce: bytes) -> None:
        for existing in self._storage:
            if compare_digest(existing, nonce):
                raise NonceReuseError("nonce reuse detected")
        self._storage.add(nonce)
