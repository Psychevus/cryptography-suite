from __future__ import annotations

import base64
import os
from os import urandom

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..errors import EncryptionError, DecryptionError
from ..debug import verbose_print

from .kdf import (
    NONCE_SIZE,
    SALT_SIZE,
    derive_key_argon2,
    derive_key_pbkdf2,
    derive_key_scrypt,
)

# Constants for streaming file encryption
CHUNK_SIZE = 4096
TAG_SIZE = 16  # AES-GCM authentication tag size


def aes_encrypt(
    plaintext: str,
    password: str,
    kdf: str = "argon2",
    *,
    raw_output: bool = False,
) -> str | bytes:
    """Encrypt plaintext using AES-GCM with a password-derived key.

    Argon2id is used by default. Pass ``kdf='scrypt'`` or ``kdf='pbkdf2'`` for
    compatibility with older data.
    """
    if not plaintext:
        raise EncryptionError("Plaintext cannot be empty.")
    if not password:
        raise EncryptionError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise EncryptionError("Unsupported KDF specified.")

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


def aes_decrypt(
    encrypted_data: bytes | str,
    password: str,
    kdf: str = "argon2",
) -> str:
    """Decrypt AES-GCM encrypted data using a password-derived key.

    Argon2id is used by default. Pass ``kdf='scrypt'`` or ``kdf='pbkdf2'`` for
    compatibility with data encrypted using those KDFs.
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

    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise DecryptionError("Unsupported KDF specified.")

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
    kdf: str = "argon2",
) -> None:
    """Encrypt a file using AES-GCM with a password-derived key.

    Argon2id is used by default. Specify ``kdf='scrypt'`` or ``kdf='pbkdf2'`` to
    maintain compatibility with existing files.

    The file is processed in chunks to avoid loading the entire file into
    memory. The output file begins with the salt and nonce and ends with the
    authentication tag.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise EncryptionError("Unsupported KDF specified.")

    verbose_print(f"Derived key: {key.hex()}")

    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    try:
        with open(input_file_path, "rb") as f_in, open(output_file_path, "wb") as f_out:
            f_out.write(salt + nonce)
            while chunk := f_in.read(CHUNK_SIZE):
                f_out.write(encryptor.update(chunk))
            encryptor.finalize()
            f_out.write(encryptor.tag)
    except Exception as exc:
        # Remove potentially partial output on error
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise IOError(f"File encryption failed: {exc}")


def decrypt_file(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = "argon2",
) -> None:
    """Decrypt a file encrypted with AES-GCM using a password-derived key.

    Argon2id is used by default. Specify ``kdf='scrypt'`` or ``kdf='pbkdf2'`` if
    the file was encrypted using one of those KDFs.

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

            if kdf == "scrypt":
                key = derive_key_scrypt(password, salt)
            elif kdf == "pbkdf2":
                key = derive_key_pbkdf2(password, salt)
            elif kdf == "argon2":
                key = derive_key_argon2(password, salt)
            else:
                raise DecryptionError("Unsupported KDF specified.")

            verbose_print(f"Derived key: {key.hex()}")
            verbose_print(f"Nonce: {nonce.hex()}")
            verbose_print("Mode: AES-GCM")

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            decryptor = cipher.decryptor()

            try:
                with open(output_file_path, "wb") as f_out:
                    processed = 0
                    while processed < ciphertext_len:
                        to_read = min(CHUNK_SIZE, ciphertext_len - processed)
                        chunk = f_in.read(to_read)
                        processed += len(chunk)
                        f_out.write(decryptor.update(chunk))

                    tag = f_in.read(TAG_SIZE)
                    decryptor.finalize_with_tag(tag)
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
    kdf: str = "argon2",
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
        raise MissingDependencyError("aiofiles is required for async operations") from exc

    salt = urandom(SALT_SIZE)
    if kdf == "scrypt":
        key = derive_key_scrypt(password, salt)
    elif kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt)
    elif kdf == "argon2":
        key = derive_key_argon2(password, salt)
    else:
        raise EncryptionError("Unsupported KDF specified.")

    verbose_print(f"Derived key: {key.hex()}")

    nonce = urandom(NONCE_SIZE)
    verbose_print(f"Nonce: {nonce.hex()}")
    verbose_print("Mode: AES-GCM")
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    try:
        async with aiofiles.open(input_file_path, "rb") as f_in, aiofiles.open(
            output_file_path, "wb"
        ) as f_out:
            await f_out.write(salt + nonce)
            while True:
                chunk = await f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                await f_out.write(encryptor.update(chunk))
            encryptor.finalize()
            await f_out.write(encryptor.tag)
    except Exception as exc:  # pragma: no cover - high-level error handling
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise IOError(f"File encryption failed: {exc}")


async def decrypt_file_async(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = "argon2",
) -> None:
    """Asynchronously decrypt a file encrypted with AES-GCM using a password-derived key."""

    if not password:
        raise EncryptionError("Password cannot be empty.")

    try:  # pragma: no cover - optional dependency
        import aiofiles
    except Exception as exc:  # pragma: no cover - fallback when aiofiles missing
        raise MissingDependencyError("aiofiles is required for async operations") from exc

    try:
        file_size = os.path.getsize(encrypted_file_path)
        async with aiofiles.open(encrypted_file_path, "rb") as f_in:
            if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise DecryptionError("Invalid encrypted file.")

            salt = await f_in.read(SALT_SIZE)
            nonce = await f_in.read(NONCE_SIZE)
            ciphertext_len = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE

            if kdf == "scrypt":
                key = derive_key_scrypt(password, salt)
            elif kdf == "pbkdf2":
                key = derive_key_pbkdf2(password, salt)
            elif kdf == "argon2":
                key = derive_key_argon2(password, salt)
            else:
                raise DecryptionError("Unsupported KDF specified.")

            verbose_print(f"Derived key: {key.hex()}")
            verbose_print(f"Nonce: {nonce.hex()}")
            verbose_print("Mode: AES-GCM")

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            decryptor = cipher.decryptor()

            try:
                async with aiofiles.open(output_file_path, "wb") as f_out:
                    processed = 0
                    while processed < ciphertext_len:
                        to_read = min(CHUNK_SIZE, ciphertext_len - processed)
                        chunk = await f_in.read(to_read)
                        processed += len(chunk)
                        await f_out.write(decryptor.update(chunk))

                    tag = await f_in.read(TAG_SIZE)
                    decryptor.finalize_with_tag(tag)
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
    "encrypt_file_async",
    "decrypt_file_async",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
]
