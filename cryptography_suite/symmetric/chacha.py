from __future__ import annotations

import base64
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .kdf import (
    CHACHA20_KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    derive_key_argon2,
)


def chacha20_encrypt(plaintext: str, password: str) -> str:
    """Encrypt using ChaCha20-Poly1305 with an Argon2-derived key."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    key = derive_key_argon2(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)
    nonce = urandom(NONCE_SIZE)

    ciphertext = chacha.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()


def chacha20_decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt data encrypted with ChaCha20-Poly1305."""
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    encrypted_data_bytes = base64.b64decode(encrypted_data)
    if len(encrypted_data_bytes) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted data.")

    salt = encrypted_data_bytes[:SALT_SIZE]
    nonce = encrypted_data_bytes[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + NONCE_SIZE :]

    key = derive_key_argon2(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}")


__all__ = ["chacha20_encrypt", "chacha20_decrypt"]
