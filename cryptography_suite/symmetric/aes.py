from __future__ import annotations

"""AES helpers built on :mod:`pyca/cryptography`.

``AESGCM`` from ``pyca/cryptography`` is the authoritative backend for AES
operations in this project. Other AES libraries (e.g. PyCryptodome) should not
be used in production code.
"""

import base64
import os
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import cast
from ..errors import (
    EncryptionError,
    DecryptionError,
    MissingDependencyError,
    KeyDerivationError,
)
from ..utils import deprecated
from ..debug import verbose_print

from ..constants import NONCE_SIZE, SALT_SIZE
from .kdf import select_kdf, DEFAULT_KDF

# Constants for streaming file encryption
CHUNK_SIZE = 4096
TAG_SIZE = 16  # AES-GCM authentication tag size


@deprecated("aes_encrypt is deprecated; use the AESGCMEncrypt pipeline module")
def aes_encrypt(
    plaintext: str,
    password: str,
    kdf: str = DEFAULT_KDF,
    *,
    raw_output: bool = False,
) -> str | bytes:
    """Encrypt ``plaintext`` using AES-GCM with a password-derived key.

    This one-shot helper will be removed in a future release. Prefer
    ``AESGCMEncrypt`` from :mod:`cryptography_suite.pipeline`.

    Argon2id is used by default when available. Pass ``kdf='scrypt'`` or
    ``kdf='pbkdf2'`` for compatibility with older data or when Argon2 support
    is missing.
    """
    if not plaintext:
        raise EncryptionError("Plaintext cannot be empty.")
    if not password:
        raise EncryptionError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    try:
        key = select_kdf(password, salt, kdf)
    except KeyDerivationError as exc:
        raise EncryptionError(str(exc)) from exc

    verbose_print(f"Derived key: {key.hex()}")

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    data = salt + nonce + ciphertext
    if raw_output:
        return data
    return base64.b64encode(data).decode()


@deprecated("aes_decrypt is deprecated; use the AESGCMDecrypt pipeline module")
def aes_decrypt(
    encrypted_data: bytes | str,
    password: str,
    kdf: str = DEFAULT_KDF,
) -> str:
    """Decrypt AES-GCM encrypted data using a password-derived key.

    This one-shot helper will be removed in a future release. Prefer
    ``AESGCMDecrypt`` from :mod:`cryptography_suite.pipeline`.

    Argon2id is used by default when available. Pass ``kdf='scrypt'`` or
    ``kdf='pbkdf2'`` for compatibility with data encrypted using those KDFs or
    when Argon2 support is missing.
    """
    if not encrypted_data:
        raise DecryptionError("Encrypted data cannot be empty.")
    if not password:
        raise DecryptionError("Password cannot be empty.")

    if isinstance(encrypted_data, str):
        try:
            encrypted_data_bytes = base64.b64decode(encrypted_data)
        except Exception as exc:
            raise DecryptionError(f"Invalid encrypted data: {exc}") from exc
    else:
        encrypted_data_bytes = encrypted_data
    if len(encrypted_data_bytes) < SALT_SIZE + NONCE_SIZE:
        raise DecryptionError("Invalid encrypted data.")

    salt = encrypted_data_bytes[:SALT_SIZE]
    nonce = encrypted_data_bytes[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + NONCE_SIZE :]

    try:
        key = select_kdf(password, salt, kdf)
    except KeyDerivationError as exc:
        raise DecryptionError(str(exc)) from exc

    verbose_print(f"Derived key: {key.hex()}")
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise DecryptionError(f"Decryption failed: {exc}")


def encrypt_file(
    input_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
) -> None:
    """Encrypt a file using AES-GCM with a password-derived key.

    Argon2id is used by default when available. Specify ``kdf='scrypt'`` or
    ``kdf='pbkdf2'`` to maintain compatibility with existing files or when
    Argon2 support is missing.

    The file is processed in chunks to avoid loading the entire file into
    memory. The output file begins with the salt and nonce and ends with the
    authentication tag.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    try:
        key = select_kdf(password, salt, kdf)
    except KeyDerivationError as exc:
        raise EncryptionError(str(exc)) from exc

    verbose_print(f"Derived key: {key.hex()}")

    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")
    aesgcm = AESGCM(key)

    try:
        with open(input_file_path, "rb") as f_in, open(output_file_path, "wb") as f_out:
            data = f_in.read()
            ct = aesgcm.encrypt(nonce, data, None)
            f_out.write(salt + nonce + ct)
    except Exception as exc:
        # Remove potentially partial output on error
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise IOError(f"File encryption failed: {exc}")


def decrypt_file(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
) -> None:
    """Decrypt a file encrypted with AES-GCM using a password-derived key.

    Argon2id is used by default when available. Specify ``kdf='scrypt'`` or
    ``kdf='pbkdf2'`` if the file was encrypted using one of those KDFs or when
    Argon2 support is missing.

    Data is streamed in chunks, verifying the authentication tag at the end.
    The output file is removed if decryption fails.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")

    try:
        file_size = os.path.getsize(encrypted_file_path)
        with open(encrypted_file_path, "rb") as f_in:
            if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise DecryptionError("Invalid encrypted file.")

            salt = f_in.read(SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            ciphertext_len = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE

            try:
                key = select_kdf(password, salt, kdf)
            except KeyDerivationError as exc:
                raise DecryptionError(str(exc)) from exc

            verbose_print(f"Derived key: {key.hex()}")
            verbose_print(f"Nonce: {nonce.hex()}")
            verbose_print("Mode: AES-GCM")

            aesgcm = AESGCM(key)

            try:
                with open(output_file_path, "wb") as f_out:
                    ciphertext = f_in.read(ciphertext_len + TAG_SIZE)
                    data = aesgcm.decrypt(nonce, ciphertext, None)
                    f_out.write(data)
            except Exception as exc:  # pragma: no cover - high-level error handling
                if os.path.exists(output_file_path):
                    os.remove(output_file_path)
                raise DecryptionError(
                    "File decryption failed: Invalid password or corrupted file."
                ) from exc
    except DecryptionError:
        raise
    except Exception as exc:
        raise IOError(f"Failed to read encrypted file: {exc}") from exc


async def encrypt_file_async(
    input_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
) -> None:
    """Asynchronously encrypt a file using AES-GCM with a password-derived key.

    Requires the optional :mod:`aiofiles` package. The logic mirrors
    :func:`encrypt_file` but performs non-blocking I/O.
    """

    if not password:
        raise EncryptionError("Password cannot be empty.")

    try:  # pragma: no cover - optional dependency
        import aiofiles
    except Exception as exc:  # pragma: no cover - fallback when aiofiles missing
        raise MissingDependencyError(
            "aiofiles is required for async operations"
        ) from exc

    salt = urandom(SALT_SIZE)
    try:
        key = select_kdf(password, salt, kdf)
    except KeyDerivationError as exc:
        raise EncryptionError(str(exc)) from exc

    verbose_print(f"Derived key: {key.hex()}")

    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")
    aesgcm = AESGCM(key)

    try:
        async with (
            aiofiles.open(input_file_path, "rb") as f_in,
            aiofiles.open(output_file_path, "wb") as f_out,
        ):
            data = await f_in.read()
            ct = aesgcm.encrypt(nonce, data, None)
            await f_out.write(salt + nonce + ct)
    except Exception as exc:  # pragma: no cover - high-level error handling
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise IOError(f"File encryption failed: {exc}")


async def decrypt_file_async(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
) -> None:
    """Asynchronously decrypt a file encrypted with AES-GCM using a password-derived key."""

    if not password:
        raise EncryptionError("Password cannot be empty.")

    try:  # pragma: no cover - optional dependency
        import aiofiles
    except Exception as exc:  # pragma: no cover - fallback when aiofiles missing
        raise MissingDependencyError(
            "aiofiles is required for async operations"
        ) from exc

    try:
        file_size = os.path.getsize(encrypted_file_path)
        async with aiofiles.open(encrypted_file_path, "rb") as f_in:
            if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise DecryptionError("Invalid encrypted file.")

            salt = await f_in.read(SALT_SIZE)
            nonce = await f_in.read(NONCE_SIZE)
            ciphertext_len = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE

            try:
                key = select_kdf(password, salt, kdf)
            except KeyDerivationError as exc:
                raise DecryptionError(str(exc)) from exc

            verbose_print(f"Derived key: {key.hex()}")
            verbose_print(f"Nonce: {nonce.hex()}")
            verbose_print("Mode: AES-GCM")

            aesgcm = AESGCM(key)

            try:
                async with aiofiles.open(output_file_path, "wb") as f_out:
                    ciphertext = await f_in.read(ciphertext_len + TAG_SIZE)
                    data = aesgcm.decrypt(nonce, ciphertext, None)
                    await f_out.write(data)
            except Exception as exc:  # pragma: no cover - high-level error handling
                if os.path.exists(output_file_path):
                    os.remove(output_file_path)
                raise DecryptionError(
                    "File decryption failed: Invalid password or corrupted file."
                ) from exc
    except DecryptionError:
        raise
    except Exception as exc:
        raise IOError(f"Failed to read encrypted file: {exc}") from exc


# Convenience wrappers -------------------------------------------------------


def scrypt_encrypt(plaintext: str, password: str) -> str:
    return cast(str, aes_encrypt(plaintext, password, kdf="scrypt"))


def scrypt_decrypt(encrypted_data: str, password: str) -> str:
    return cast(str, aes_decrypt(encrypted_data, password, kdf="scrypt"))


def pbkdf2_encrypt(plaintext: str, password: str) -> str:
    return cast(str, aes_encrypt(plaintext, password, kdf="pbkdf2"))


def pbkdf2_decrypt(encrypted_data: str, password: str) -> str:
    return cast(str, aes_decrypt(encrypted_data, password, kdf="pbkdf2"))


def argon2_encrypt(plaintext: str, password: str) -> str:
    return cast(str, aes_encrypt(plaintext, password, kdf="argon2"))


def argon2_decrypt(encrypted_data: str, password: str) -> str:
    return cast(str, aes_decrypt(encrypted_data, password, kdf="argon2"))


__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_async",
    "decrypt_file_async",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
]
