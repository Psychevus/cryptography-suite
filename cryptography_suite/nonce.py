"""Nonce management utilities."""
from __future__ import annotations

import threading

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

    Notes
    -----
    The default ``limit`` of :math:`2^{32}` matches the AES-GCM message
    cap and ensures callers rotate keys before exceeding the safe
    number of encryptions.
    """

    def __init__(self, *, start: int = 0, limit: int = 2**32) -> None:
        if start < 0:
            raise ValueError("start must be non-negative")
        if limit <= start:
            raise ValueError("limit must be greater than start")
        self._counter = start
        self._limit = limit
        self._seen: set[bytes] = set()
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
            if nonce in self._seen:
                raise NonceReuseError("nonce reuse detected")
            self._seen.add(nonce)
