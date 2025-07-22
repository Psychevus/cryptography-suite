from __future__ import annotations

import base64
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..errors import EncryptionError, DecryptionError

from .kdf import (
    CHACHA20_KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    derive_key_argon2,
)


def chacha20_encrypt(plaintext: str, password: str) -> str:
    """Encrypt using ChaCha20-Poly1305 with an Argon2-derived key."""
    if not plaintext:
        raise EncryptionError("Plaintext cannot be empty.")
    if not password:
        raise EncryptionError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    key = derive_key_argon2(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)
    nonce = urandom(NONCE_SIZE)

    ciphertext = chacha.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()


def chacha20_decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt data encrypted with ChaCha20-Poly1305."""
    if not encrypted_data:
        raise DecryptionError("Encrypted data cannot be empty.")
    if not password:
        raise DecryptionError("Password cannot be empty.")

    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
    except Exception as exc:
        raise DecryptionError(f"Invalid encrypted data: {exc}") from exc
    if len(encrypted_data_bytes) < SALT_SIZE + NONCE_SIZE:
        raise DecryptionError("Invalid encrypted data.")

    salt = encrypted_data_bytes[:SALT_SIZE]
    nonce = encrypted_data_bytes[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + NONCE_SIZE :]

    key = derive_key_argon2(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:
        raise DecryptionError(f"Decryption failed: {exc}")


__all__ = ["chacha20_encrypt", "chacha20_decrypt"]
