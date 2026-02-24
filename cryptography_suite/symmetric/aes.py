from __future__ import annotations

"""AES helpers built on :mod:`pyca/cryptography`.

``AESGCM`` from ``pyca/cryptography`` is the authoritative backend for AES
operations in this project. Other AES libraries (e.g. PyCryptodome) should not
be used in production code.
"""

import base64
import binascii
import logging
import os
import struct
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import cast
from ..errors import (
    EncryptionError,
    DecryptionError,
    MissingDependencyError,
    KeyDerivationError,
)
from ..utils import deprecated
from ..debug import VERBOSE, verbose_print

from ..constants import NONCE_SIZE, SALT_SIZE
from .kdf import select_kdf, DEFAULT_KDF


logger = logging.getLogger(__name__)

# Constants for streaming file encryption
CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16  # AES-GCM authentication tag size
FORMAT_MAGIC = b"CSF!"
FORMAT_VERSION = 1
HEADER_FIXED_SIZE = 12
_KDF_TO_ID = {"scrypt": 1, "pbkdf2": 2, "argon2": 3}
_ID_TO_KDF = {v: k for k, v in _KDF_TO_ID.items()}


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
    if VERBOSE:
        if logger.level > logging.DEBUG:
            raise RuntimeError("Verbose mode requires DEBUG level")
        logger.debug("ciphertext=%s", binascii.hexlify(ciphertext)[:32])
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
    memory. The output is a versioned format:
    magic, version, KDF id, salt/nonce lengths, chunk size, salt, nonce,
    ciphertext, and trailing authentication tag.
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
    kdf_id = _KDF_TO_ID.get(kdf)
    if kdf_id is None:
        raise EncryptionError("Unsupported KDF specified.")

    try:
        with open(input_file_path, "rb") as f_in, open(output_file_path, "wb") as f_out:
            header = (
                FORMAT_MAGIC
                + bytes([FORMAT_VERSION, kdf_id, len(salt), len(nonce)])
                + struct.pack(">I", CHUNK_SIZE)
                + salt
                + nonce
            )
            f_out.write(header)

            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
            if VERBOSE:
                if logger.level > logging.DEBUG:
                    raise RuntimeError("Verbose mode requires DEBUG level")
                logger.debug("tag=%s", binascii.hexlify(encryptor.tag))
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
    Supports both the current versioned format and the legacy
    ``salt || nonce || ciphertext_and_tag`` format.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")
    if kdf not in _KDF_TO_ID:
        raise DecryptionError("Unsupported KDF specified.")

    try:
        file_size = os.path.getsize(encrypted_file_path)
        with open(encrypted_file_path, "rb") as f_in:
            if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise DecryptionError("Invalid encrypted file.")

            magic = f_in.read(len(FORMAT_MAGIC))
            is_versioned = magic == FORMAT_MAGIC

            if is_versioned:
                rest = f_in.read(HEADER_FIXED_SIZE - len(FORMAT_MAGIC))
                if len(rest) != HEADER_FIXED_SIZE - len(FORMAT_MAGIC):
                    raise DecryptionError("Invalid encrypted file.")
                version, kdf_id, salt_len, nonce_len, chunk_size = struct.unpack(">BBBBI", rest
                )
                if version != FORMAT_VERSION:
                    raise DecryptionError("Unsupported encrypted file version.")
                format_kdf = _ID_TO_KDF.get(kdf_id)
                if format_kdf is None:
                    raise DecryptionError("Invalid encrypted file.")
                salt = f_in.read(salt_len)
                nonce = f_in.read(nonce_len)
                if len(salt) != salt_len or len(nonce) != nonce_len:
                    raise DecryptionError("Invalid encrypted file.")
                stream_chunk_size = max(1024, chunk_size)
            else:
                f_in.seek(0)
                salt = f_in.read(SALT_SIZE)
                nonce = f_in.read(NONCE_SIZE)
                format_kdf = kdf
                stream_chunk_size = CHUNK_SIZE

            ciphertext_start = f_in.tell()
            ciphertext_len = file_size - ciphertext_start - TAG_SIZE
            if ciphertext_len < 0:
                raise DecryptionError("Invalid encrypted file.")

            try:
                key = select_kdf(password, salt, format_kdf)
            except KeyDerivationError as exc:
                raise DecryptionError(str(exc)) from exc

            verbose_print(f"Derived key: {key.hex()}")
            verbose_print(f"Nonce: {nonce.hex()}")
            verbose_print("Mode: AES-GCM")

            try:
                with open(output_file_path, "wb") as f_out:
                    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
                    remaining = ciphertext_len
                    while remaining > 0:
                        read_len = min(stream_chunk_size, remaining)
                        chunk = f_in.read(read_len)
                        if not chunk:
                            raise DecryptionError("Invalid encrypted file.")
                        remaining -= len(chunk)
                        f_out.write(decryptor.update(chunk))

                    tag = f_in.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise DecryptionError("Invalid encrypted file.")
                    f_out.write(decryptor.finalize_with_tag(tag))
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
            if VERBOSE:
                if logger.level > logging.DEBUG:
                    raise RuntimeError("Verbose mode requires DEBUG level")
                logger.debug("ciphertext=%s", binascii.hexlify(ct)[:32])
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
