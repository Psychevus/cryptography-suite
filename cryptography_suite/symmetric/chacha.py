from __future__ import annotations

import base64
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:  # pragma: no cover - optional algorithm
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
except Exception:  # pragma: no cover - old cryptography versions
    XChaCha20Poly1305 = None
from ..errors import EncryptionError, DecryptionError, MissingDependencyError
from ..debug import verbose_print

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
    verbose_print(f"Derived key: {key.hex()}")
    chacha = ChaCha20Poly1305(key)
    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: ChaCha20-Poly1305")

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
    verbose_print(f"Derived key: {key.hex()}")
    chacha = ChaCha20Poly1305(key)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: ChaCha20-Poly1305")
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:
        raise DecryptionError(f"Decryption failed: {exc}")


def xchacha_encrypt(message: bytes, key: bytes, nonce: bytes) -> dict:
    """Encrypt ``message`` using XChaCha20-Poly1305."""

    if XChaCha20Poly1305 is None:
        raise MissingDependencyError("XChaCha20Poly1305 not available")

    if not message:
        raise EncryptionError("Message cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise EncryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 24:
        raise EncryptionError("Nonce must be 24 bytes.")

    cipher = XChaCha20Poly1305(bytes(key))
    verbose_print(f"Derived key: {bytes(key).hex()}")
    verbose_print(f"Nonce: {bytes(nonce).hex()}")
    verbose_print("Mode: XChaCha20-Poly1305")
    ciphertext = cipher.encrypt(bytes(nonce), bytes(message), None)
    return {"nonce": bytes(nonce), "ciphertext": ciphertext}


def xchacha_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt data encrypted with :func:`xchacha_encrypt`."""

    if XChaCha20Poly1305 is None:
        raise MissingDependencyError("XChaCha20Poly1305 not available")

    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != CHACHA20_KEY_SIZE:
        raise DecryptionError("Key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 24:
        raise DecryptionError("Nonce must be 24 bytes.")

    cipher = XChaCha20Poly1305(bytes(key))
    verbose_print(f"Derived key: {bytes(key).hex()}")
    verbose_print(f"Nonce: {bytes(nonce).hex()}")
    verbose_print("Mode: XChaCha20-Poly1305")
    try:
        return cipher.decrypt(bytes(nonce), ciphertext, None)
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise DecryptionError(f"Decryption failed: {exc}")


__all__ = [
    "chacha20_encrypt",
    "chacha20_decrypt",
    "xchacha_encrypt",
    "xchacha_decrypt",
]
