"""Authenticated encryption primitives."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constants import CHACHA20_KEY_SIZE, NONCE_SIZE

__all__ = ["chacha20_encrypt_aead", "chacha20_decrypt_aead"]


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
