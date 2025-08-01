from __future__ import annotations

"""Salsa20 stream cipher helpers using PyCryptodome.

PyCryptodome is only used for these deprecated helpers. The project
intends to migrate to :mod:`cryptography` if Salsa20 support becomes
available. Do **not** use these functions in production code.
"""

from Crypto.Cipher import Salsa20

from ..errors import EncryptionError, DecryptionError
from ..utils import deprecated
from ..constants import CHACHA20_KEY_SIZE

SALSA20_NONCE_SIZE = 8


@deprecated("Salsa20 is deprecated and not recommended for production.")
def salsa20_encrypt(message: bytes, key: bytes, nonce: bytes) -> bytes:
    """INSECURE: Encrypt ``message`` using Salsa20.

    .. warning:: This cipher provides no authentication and is **not recommended**
       for production use.

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


@deprecated("Salsa20 is deprecated and not recommended for production.")
def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """INSECURE: Decrypt data encrypted with :func:`salsa20_encrypt`."""
    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise DecryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != SALSA20_NONCE_SIZE:
        raise DecryptionError("Nonce must be 8 bytes.")

    cipher = Salsa20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.decrypt(ciphertext)


__all__ = ["salsa20_encrypt", "salsa20_decrypt"]
