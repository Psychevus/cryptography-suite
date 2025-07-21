from __future__ import annotations

import base64
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import (
    NONCE_SIZE,
    SALT_SIZE,
    derive_key_argon2,
    derive_key_pbkdf2,
    derive_key_scrypt,
)


def aes_encrypt(plaintext: str, password: str, kdf: str = "scrypt") -> str:
    """Encrypt plaintext using AES-GCM with a password-derived key."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()


def aes_decrypt(encrypted_data: str, password: str, kdf: str = "scrypt") -> str:
    """Decrypt AES-GCM encrypted data using a password-derived key."""
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

    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise ValueError(f"Decryption failed: {exc}")


def encrypt_file(
    input_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = "scrypt",
) -> None:
    """Encrypt a file using AES-GCM with a password-derived key."""
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)

    try:
        with open(input_file_path, "rb") as f:
            data = f.read()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        with open(output_file_path, "wb") as f:
            f.write(salt + nonce + ciphertext)
    except Exception as exc:
        raise IOError(f"File encryption failed: {exc}")


def decrypt_file(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = "scrypt",
) -> None:
    """Decrypt a file encrypted with AES-GCM using a password-derived key."""
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()
    except Exception as exc:
        raise IOError(f"Failed to read encrypted file: {exc}")

    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted file.")

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE :]

    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(nonce, ciphertext, None)
        with open(output_file_path, "wb") as f:
            f.write(data)
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise ValueError(
            "File decryption failed: Invalid password or corrupted file."
        ) from exc


# Convenience wrappers -------------------------------------------------------

def scrypt_encrypt(plaintext: str, password: str) -> str:
    return aes_encrypt(plaintext, password, kdf="scrypt")


def scrypt_decrypt(encrypted_data: str, password: str) -> str:
    return aes_decrypt(encrypted_data, password, kdf="scrypt")


def pbkdf2_encrypt(plaintext: str, password: str) -> str:
    return aes_encrypt(plaintext, password, kdf="pbkdf2")


def pbkdf2_decrypt(encrypted_data: str, password: str) -> str:
    return aes_decrypt(encrypted_data, password, kdf="pbkdf2")


def argon2_encrypt(plaintext: str, password: str) -> str:
    return aes_encrypt(plaintext, password, kdf="argon2")


def argon2_decrypt(encrypted_data: str, password: str) -> str:
    return aes_decrypt(encrypted_data, password, kdf="argon2")


__all__ = [
    "aes_encrypt",
    "aes_decrypt",
    "encrypt_file",
    "decrypt_file",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
]
