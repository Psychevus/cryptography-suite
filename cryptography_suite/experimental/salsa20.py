from __future__ import annotations

DEPRECATED_MSG = (
    "This function is deprecated and will be removed in v4.0.0. For reference/education only. DO NOT USE IN PRODUCTION."
)

raise RuntimeError(DEPRECATED_MSG)

# Reference implementation retained for educational purposes only.
from Crypto.Cipher import Salsa20

from ..errors import EncryptionError, DecryptionError
from ..constants import CHACHA20_KEY_SIZE

SALSA20_NONCE_SIZE = 8


def salsa20_encrypt(message: bytes, key: bytes, nonce: bytes) -> bytes:
    if not message:
        raise EncryptionError("Message cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise EncryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != SALSA20_NONCE_SIZE:
        raise EncryptionError("Nonce must be 8 bytes.")
    cipher = Salsa20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.encrypt(bytes(message))


def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise DecryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != SALSA20_NONCE_SIZE:
        raise DecryptionError("Nonce must be 8 bytes.")
    cipher = Salsa20.new(key=bytes(key), nonce=bytes(nonce))
    return cipher.decrypt(ciphertext)
