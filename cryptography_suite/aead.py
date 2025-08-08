"""Authenticated encryption primitives."""

from __future__ import annotations

import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .constants import CHACHA20_KEY_SIZE, NONCE_SIZE
from .exceptions import KeyRotationRequired
from .nonce import NonceManager

# Default AEAD algorithm used by high level helpers. This value can be
# monkey-patched at runtime (e.g. via ``--experimental gcm-sst`` CLI flag)
# to switch to alternate constructions.
DEFAULT = "GCM"

__all__ = ["chacha20_encrypt_aead", "chacha20_decrypt_aead", "AESGCMContext"]


def chacha20_encrypt_aead(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Encrypt ``plaintext`` using ChaCha20-Poly1305.

    The ``key`` must be 32 bytes and the ``nonce`` 12 bytes.
    """
    if len(key) != CHACHA20_KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")
    cipher = ChaCha20Poly1305(key)
    ad = associated_data or b""
    return cipher.encrypt(nonce, plaintext, ad)


def chacha20_decrypt_aead(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data encrypted with :func:`chacha20_encrypt_aead`."""
    if len(key) != CHACHA20_KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")
    cipher = ChaCha20Poly1305(key)
    ad = associated_data or b""
    return cipher.decrypt(nonce, ciphertext, ad)


BYTE_LIMIT = 2**54  # 2**24 GiB


class AESGCMContext:
    """AES-GCM wrapper with nonce management and usage limits."""

    def __init__(self, key: bytes, *, byte_limit: int = BYTE_LIMIT) -> None:
        if len(key) not in {16, 24, 32}:
            raise ValueError("key must be 128, 192 or 256 bits")
        self._aesgcm = AESGCM(key)
        self._byte_limit = byte_limit
        self._bytes_processed = 0
        # count of messages processed with this key
        self._msg_counter: int = 0
        self._lock = threading.Lock()

    @property
    def bytes_processed(self) -> int:
        return self._bytes_processed

    def encrypt(
        self,
        *,
        nm: NonceManager,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        """Encrypt ``plaintext`` and return ``(nonce, ciphertext)``."""
        nonce = nm.next()
        nm.remember(nonce)
        with self._lock:
            if self._bytes_processed + len(plaintext) > self._byte_limit:
                raise KeyRotationRequired("byte limit reached")
            self._bytes_processed += len(plaintext)
            self._msg_counter += 1
            if self._msg_counter > 2**32:
                raise KeyRotationRequired("2^32 message cap reached")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(
        self,
        *,
        nm: NonceManager,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """Decrypt ``ciphertext`` using ``nonce``."""
        nm.remember(nonce)
        with self._lock:
            if self._bytes_processed + len(ciphertext) > self._byte_limit:
                raise KeyRotationRequired("byte limit reached")
            self._bytes_processed += len(ciphertext)
        return self._aesgcm.decrypt(nonce, ciphertext, aad)
