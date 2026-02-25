"""Nonce management utilities."""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Literal

from .exceptions import KeyRotationRequired, NonceReuseError

NONCE_SIZE = 12

__all__ = ["NonceManager"]


class NonceManager:
    """Manage monotonically increasing nonces and detect reuse.

    Parameters
    ----------
    start:
        Initial counter value.
    limit:
        Maximum number of nonces allowed before requiring key rotation.
    mode:
        ``"strict"`` keeps every observed nonce for the lifetime of the
        manager. ``"lru"`` keeps only a bounded replay cache.
    cache_size:
        Maximum number of nonces retained in ``"lru"`` mode.

    Notes
    -----
    The default ``limit`` of :math:`2^{32}` matches the AES-GCM message
    cap and ensures callers rotate keys before exceeding the safe
    number of encryptions. The default ``"lru"`` mode provides bounded
    memory usage for long-running services.
    """

    def __init__(
        self,
        *,
        start: int = 0,
        limit: int = 2**32,
        mode: Literal["lru", "strict"] = "lru",
        cache_size: int = 100_000,
    ) -> None:
        if start < 0:
            raise ValueError("start must be non-negative")
        if limit <= start:
            raise ValueError("limit must be greater than start")
        if mode not in {"lru", "strict"}:
            raise ValueError("mode must be 'lru' or 'strict'")
        if cache_size <= 0:
            raise ValueError("cache_size must be positive")
        self._counter = start
        self._limit = limit
        self._mode: Literal["lru", "strict"] = mode
        self._cache_size = cache_size
        self._seen: set[bytes] | OrderedDict[bytes, None]
        if mode == "strict":
            self._seen = set()
        else:
            self._seen = OrderedDict()
        self._lock = threading.Lock()

    def next(self) -> bytes:
        """Return the next 12-byte big-endian counter value."""
        with self._lock:
            if self._counter >= self._limit:
                raise KeyRotationRequired("nonce limit reached")
            value = self._counter
            self._counter += 1
        return value.to_bytes(NONCE_SIZE, "big")

    def remember(self, nonce: bytes) -> None:
        """Record ``nonce`` and ensure it has not been used before."""
        if len(nonce) != NONCE_SIZE:
            raise ValueError("nonce must be 12 bytes")
        with self._lock:
            if self._mode == "strict":
                seen = self._seen
                assert isinstance(seen, set)
                if nonce in seen:
                    raise NonceReuseError("nonce reuse detected")
                seen.add(nonce)
                return

            seen = self._seen
            assert isinstance(seen, OrderedDict)
            if nonce in seen:
                raise NonceReuseError("nonce reuse detected")
            seen[nonce] = None
            if len(seen) > self._cache_size:
                seen.popitem(last=False)
