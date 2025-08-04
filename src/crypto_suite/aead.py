from __future__ import annotations

import threading
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .nonce import KeyRotationRequired, NonceManager

BYTE_LIMIT = 2**54  # 2**24 GiB
NONCE_SIZE = 12


class AesGcm:
    """AES-GCM wrapper with nonce management and usage limits."""

    def __init__(self, key: bytes, *, byte_limit: int = BYTE_LIMIT) -> None:
        if len(key) not in {16, 24, 32}:
            raise ValueError("key must be 128, 192 or 256 bits")
        self._aesgcm = AESGCM(key)
        self._byte_limit = byte_limit
        self._bytes_processed = 0
        self._lock = threading.Lock()

    def encrypt(
        self,
        plaintext: bytes,
        *,
        associated_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        nonce_manager: Optional[NonceManager] = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt ``plaintext`` and return ``(nonce, ciphertext)``."""
        if nonce_manager is not None:
            nonce = nonce_manager.next()
        if nonce is None:
            raise ValueError("nonce or nonce_manager required")
        with self._lock:
            if self._bytes_processed + len(plaintext) > self._byte_limit:
                raise KeyRotationRequired("byte limit reached")
            self._bytes_processed += len(plaintext)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
        nonce_manager: Optional[NonceManager] = None,
    ) -> bytes:
        """Decrypt ``ciphertext`` using ``nonce``."""
        if nonce_manager is not None:
            nonce_manager.remember(nonce)
        with self._lock:
            if self._bytes_processed + len(ciphertext) > self._byte_limit:
                raise KeyRotationRequired("byte limit reached")
            self._bytes_processed += len(ciphertext)
        return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
