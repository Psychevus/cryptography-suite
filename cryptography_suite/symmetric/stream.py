from __future__ import annotations

from Crypto.Cipher import Salsa20, ChaCha20

from ..errors import EncryptionError, DecryptionError

from .kdf import CHACHA20_KEY_SIZE


SALSA20_NONCE_SIZE = 8
CHACHA20_NONCE_SIZE = 8  # also accepts 12 or 24 bytes for XChaCha20


def salsa20_encrypt(message: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt ``message`` using Salsa20.

    The ``key`` must be 32 bytes and ``nonce`` must be 8 bytes.
    Encryption is deterministic for a given key and nonce.
    """
    if not message:
        raise EncryptionError("Message cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise EncryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != SALSA20_NONCE_SIZE:
        raise EncryptionError("Nonce must be 8 bytes.")

    cipher = Salsa20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.encrypt(bytes(message))


def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt data encrypted with :func:`salsa20_encrypt`."""
    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise DecryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != SALSA20_NONCE_SIZE:
        raise DecryptionError("Nonce must be 8 bytes.")

    cipher = Salsa20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.decrypt(ciphertext)


def chacha20_stream_encrypt(message: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt ``message`` using ChaCha20 without Poly1305."""
    if not message:
        raise EncryptionError("Message cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise EncryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) not in {8, 12, 24}:
        raise EncryptionError("Nonce must be 8, 12, or 24 bytes long.")

    cipher = ChaCha20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.encrypt(bytes(message))


def chacha20_stream_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt data encrypted with :func:`chacha20_stream_encrypt`."""
    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise DecryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) not in {8, 12, 24}:
        raise DecryptionError("Nonce must be 8, 12, or 24 bytes long.")

    cipher = ChaCha20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.decrypt(ciphertext)


__all__ = [
    "salsa20_encrypt",
    "salsa20_decrypt",
    "chacha20_stream_encrypt",
    "chacha20_stream_decrypt",
]
