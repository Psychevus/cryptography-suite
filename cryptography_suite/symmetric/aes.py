"""AES helpers built on :mod:`pyca/cryptography`.

``AESGCM`` from ``pyca/cryptography`` is the authoritative backend for AES
operations in this project. Other AES libraries (e.g. PyCryptodome) should not
be used in production code.
"""

from __future__ import annotations

import base64
import os
import struct
import tempfile
from dataclasses import dataclass
from os import urandom
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..constants import NONCE_SIZE, SALT_SIZE
from ..debug import verbose_print
from ..errors import (
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    MissingDependencyError,
)
from ..utils import deprecated
from .kdf import DEFAULT_KDF, select_kdf

# Constants for streaming file encryption
CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16  # AES-GCM authentication tag size
FORMAT_MAGIC = b"CSF!"
FORMAT_VERSION = 2
LEGACY_FORMAT_VERSION = 1
HEADER_FIXED_SIZE = 12
_KDF_TO_ID = {"scrypt": 1, "pbkdf2": 2, "argon2": 3}
_ID_TO_KDF = {v: k for k, v in _KDF_TO_ID.items()}


@dataclass(frozen=True)
class _ParsedFileHeader:
    version: int | None
    format_kdf: str
    salt: bytes
    nonce: bytes
    chunk_size: int
    ciphertext_start: int
    aad: bytes | None


def _build_file_header(kdf_id: int, salt: bytes, nonce: bytes) -> bytes:
    return (
        FORMAT_MAGIC
        + bytes([FORMAT_VERSION, kdf_id, len(salt), len(nonce)])
        + struct.pack(">I", CHUNK_SIZE)
        + salt
        + nonce
    )


def _reject_implicit_legacy() -> None:
    raise DecryptionError(
        "Legacy encrypted file format requires allow_legacy_format=True."
    )


def _validate_versioned_header_fields(
    *,
    version: int,
    kdf_id: int,
    salt_len: int,
    nonce_len: int,
    chunk_size: int,
    file_size: int,
    allow_legacy_format: bool,
) -> tuple[str, int]:
    if version not in (LEGACY_FORMAT_VERSION, FORMAT_VERSION):
        raise DecryptionError("Unsupported encrypted file version.")
    if version == LEGACY_FORMAT_VERSION and not allow_legacy_format:
        _reject_implicit_legacy()
    format_kdf = _ID_TO_KDF.get(kdf_id)
    if format_kdf is None:
        raise DecryptionError("Invalid encrypted file.")
    if salt_len != SALT_SIZE or nonce_len != NONCE_SIZE:
        raise DecryptionError("Invalid encrypted file.")
    if chunk_size != CHUNK_SIZE:
        raise DecryptionError("Invalid encrypted file.")
    header_len = HEADER_FIXED_SIZE + salt_len + nonce_len
    if file_size < header_len + TAG_SIZE:
        raise DecryptionError("Invalid encrypted file.")
    return format_kdf, header_len


def _parse_file_header(
    f_in: Any,
    file_size: int,
    *,
    kdf: str,
    allow_legacy_format: bool,
) -> _ParsedFileHeader:
    if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Invalid encrypted file.")

    magic = f_in.read(len(FORMAT_MAGIC))
    if magic != FORMAT_MAGIC:
        if not allow_legacy_format:
            _reject_implicit_legacy()
        f_in.seek(0)
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(NONCE_SIZE)
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
            raise DecryptionError("Invalid encrypted file.")
        return _ParsedFileHeader(
            version=None,
            format_kdf=kdf,
            salt=salt,
            nonce=nonce,
            chunk_size=CHUNK_SIZE,
            ciphertext_start=SALT_SIZE + NONCE_SIZE,
            aad=None,
        )

    rest = f_in.read(HEADER_FIXED_SIZE - len(FORMAT_MAGIC))
    if len(rest) != HEADER_FIXED_SIZE - len(FORMAT_MAGIC):
        raise DecryptionError("Invalid encrypted file.")
    version, kdf_id, salt_len, nonce_len, chunk_size = struct.unpack(">BBBBI", rest)
    format_kdf, header_len = _validate_versioned_header_fields(
        version=version,
        kdf_id=kdf_id,
        salt_len=salt_len,
        nonce_len=nonce_len,
        chunk_size=chunk_size,
        file_size=file_size,
        allow_legacy_format=allow_legacy_format,
    )
    salt = f_in.read(salt_len)
    nonce = f_in.read(nonce_len)
    if len(salt) != salt_len or len(nonce) != nonce_len:
        raise DecryptionError("Invalid encrypted file.")
    header = magic + rest + salt + nonce
    if len(header) != header_len:
        raise DecryptionError("Invalid encrypted file.")
    return _ParsedFileHeader(
        version=version,
        format_kdf=format_kdf,
        salt=salt,
        nonce=nonce,
        chunk_size=chunk_size,
        ciphertext_start=header_len,
        aad=header if version == FORMAT_VERSION else None,
    )


async def _parse_file_header_async(
    f_in: Any,
    file_size: int,
    *,
    kdf: str,
    allow_legacy_format: bool,
) -> _ParsedFileHeader:
    if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Invalid encrypted file.")

    magic = await f_in.read(len(FORMAT_MAGIC))
    if magic != FORMAT_MAGIC:
        if not allow_legacy_format:
            _reject_implicit_legacy()
        await f_in.seek(0)
        salt = await f_in.read(SALT_SIZE)
        nonce = await f_in.read(NONCE_SIZE)
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
            raise DecryptionError("Invalid encrypted file.")
        return _ParsedFileHeader(
            version=None,
            format_kdf=kdf,
            salt=salt,
            nonce=nonce,
            chunk_size=CHUNK_SIZE,
            ciphertext_start=SALT_SIZE + NONCE_SIZE,
            aad=None,
        )

    rest = await f_in.read(HEADER_FIXED_SIZE - len(FORMAT_MAGIC))
    if len(rest) != HEADER_FIXED_SIZE - len(FORMAT_MAGIC):
        raise DecryptionError("Invalid encrypted file.")
    version, kdf_id, salt_len, nonce_len, chunk_size = struct.unpack(">BBBBI", rest)
    format_kdf, header_len = _validate_versioned_header_fields(
        version=version,
        kdf_id=kdf_id,
        salt_len=salt_len,
        nonce_len=nonce_len,
        chunk_size=chunk_size,
        file_size=file_size,
        allow_legacy_format=allow_legacy_format,
    )
    salt = await f_in.read(salt_len)
    nonce = await f_in.read(nonce_len)
    if len(salt) != salt_len or len(nonce) != nonce_len:
        raise DecryptionError("Invalid encrypted file.")
    header = magic + rest + salt + nonce
    if len(header) != header_len:
        raise DecryptionError("Invalid encrypted file.")
    return _ParsedFileHeader(
        version=version,
        format_kdf=format_kdf,
        salt=salt,
        nonce=nonce,
        chunk_size=chunk_size,
        ciphertext_start=header_len,
        aad=header if version == FORMAT_VERSION else None,
    )


def _new_temp_output_path(output_file_path: str) -> str:
    output_path = Path(output_file_path)
    output_dir = output_path.resolve().parent
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=str(output_dir),
    )
    os.close(fd)
    return temp_path


def _cleanup_temp_file(temp_path: str | None) -> None:
    if temp_path and os.path.exists(temp_path):
        os.remove(temp_path)


def _import_aiofiles() -> Any:
    try:  # pragma: no cover - optional dependency
        import aiofiles  # type: ignore[import-untyped]

        return aiofiles
    except Exception as exc:  # pragma: no cover - fallback when aiofiles missing
        raise MissingDependencyError(
            "aiofiles is required for async operations"
        ) from exc


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

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)
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

    verbose_print("Mode: AES-GCM")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise DecryptionError(f"Decryption failed: {exc}") from exc


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

    nonce = urandom(NONCE_SIZE)
    verbose_print("Mode: AES-GCM")
    kdf_id = _KDF_TO_ID.get(kdf)
    if kdf_id is None:
        raise EncryptionError("Unsupported KDF specified.")

    try:
        with open(input_file_path, "rb") as f_in, open(output_file_path, "wb") as f_out:
            header = _build_file_header(kdf_id, salt, nonce)
            f_out.write(header)

            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(header)
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
    except Exception as exc:
        # Remove potentially partial output on error
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise OSError(f"File encryption failed: {exc}") from exc


def decrypt_file(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
    *,
    allow_legacy_format: bool = False,
) -> None:
    """Decrypt a file encrypted with AES-GCM using a password-derived key.

    Argon2id is used by default when available. Specify ``kdf='scrypt'`` or
    ``kdf='pbkdf2'`` if the file was encrypted using one of those KDFs or when
    Argon2 support is missing.

    Data is streamed into a same-directory temporary file and atomically moved
    into place only after the authentication tag verifies. Legacy v1 and raw
    ``salt || nonce || ciphertext_and_tag`` files require
    ``allow_legacy_format=True``.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")
    if kdf not in _KDF_TO_ID:
        raise DecryptionError("Unsupported KDF specified.")

    try:
        file_size = os.path.getsize(encrypted_file_path)
        with open(encrypted_file_path, "rb") as f_in:
            header = _parse_file_header(
                f_in,
                file_size,
                kdf=kdf,
                allow_legacy_format=allow_legacy_format,
            )
            ciphertext_len = file_size - header.ciphertext_start - TAG_SIZE
            if ciphertext_len < 0:
                raise DecryptionError("Invalid encrypted file.")

            try:
                key = select_kdf(password, header.salt, header.format_kdf)
            except KeyDerivationError as exc:
                raise DecryptionError(str(exc)) from exc

            verbose_print("Mode: AES-GCM")

            temp_path: str | None = None
            try:
                temp_path = _new_temp_output_path(output_file_path)
                with open(temp_path, "wb") as f_out:
                    decryptor = Cipher(
                        algorithms.AES(key), modes.GCM(header.nonce)
                    ).decryptor()
                    if header.aad is not None:
                        decryptor.authenticate_additional_data(header.aad)
                    remaining = ciphertext_len
                    while remaining > 0:
                        read_len = min(header.chunk_size, remaining)
                        chunk = f_in.read(read_len)
                        if not chunk:
                            raise DecryptionError("Invalid encrypted file.")
                        remaining -= len(chunk)
                        f_out.write(decryptor.update(chunk))

                    tag = f_in.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise DecryptionError("Invalid encrypted file.")
                    f_out.write(decryptor.finalize_with_tag(tag))
                os.replace(temp_path, output_file_path)
                temp_path = None
            except Exception as exc:  # pragma: no cover - high-level error handling
                _cleanup_temp_file(temp_path)
                raise DecryptionError(
                    "File decryption failed: Invalid password or corrupted file."
                ) from exc
    except DecryptionError:
        raise
    except Exception as exc:
        raise OSError(f"Failed to read encrypted file: {exc}") from exc


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

    aiofiles = _import_aiofiles()

    salt = urandom(SALT_SIZE)
    try:
        key = select_kdf(password, salt, kdf)
    except KeyDerivationError as exc:
        raise EncryptionError(str(exc)) from exc

    nonce = urandom(NONCE_SIZE)
    verbose_print("Mode: AES-GCM")
    kdf_id = _KDF_TO_ID.get(kdf)
    if kdf_id is None:
        raise EncryptionError("Unsupported KDF specified.")

    try:
        async with (
            aiofiles.open(input_file_path, "rb") as f_in,
            aiofiles.open(output_file_path, "wb") as f_out,
        ):
            header = _build_file_header(kdf_id, salt, nonce)
            await f_out.write(header)

            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(header)
            while True:
                chunk = await f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                await f_out.write(encryptor.update(chunk))

            await f_out.write(encryptor.finalize())
            await f_out.write(encryptor.tag)
    except Exception as exc:  # pragma: no cover - high-level error handling
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        raise OSError(f"File encryption failed: {exc}") from exc


async def decrypt_file_async(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = DEFAULT_KDF,
    *,
    allow_legacy_format: bool = False,
) -> None:
    """Asynchronously decrypt a file encrypted with AES-GCM.

    Uses a password-derived key.
    """

    if not password:
        raise EncryptionError("Password cannot be empty.")
    if kdf not in _KDF_TO_ID:
        raise DecryptionError("Unsupported KDF specified.")

    aiofiles = _import_aiofiles()

    try:
        file_size = os.path.getsize(encrypted_file_path)
        async with aiofiles.open(encrypted_file_path, "rb") as f_in:
            header = await _parse_file_header_async(
                f_in,
                file_size,
                kdf=kdf,
                allow_legacy_format=allow_legacy_format,
            )
            ciphertext_len = file_size - header.ciphertext_start - TAG_SIZE
            if ciphertext_len < 0:
                raise DecryptionError("Invalid encrypted file.")

            try:
                key = select_kdf(password, header.salt, header.format_kdf)
            except KeyDerivationError as exc:
                raise DecryptionError(str(exc)) from exc

            verbose_print("Mode: AES-GCM")

            temp_path: str | None = None
            try:
                temp_path = _new_temp_output_path(output_file_path)
                async with aiofiles.open(temp_path, "wb") as f_out:
                    decryptor = Cipher(
                        algorithms.AES(key), modes.GCM(header.nonce)
                    ).decryptor()
                    if header.aad is not None:
                        decryptor.authenticate_additional_data(header.aad)
                    remaining = ciphertext_len
                    while remaining > 0:
                        read_len = min(header.chunk_size, remaining)
                        chunk = await f_in.read(read_len)
                        if not chunk:
                            raise DecryptionError("Invalid encrypted file.")
                        remaining -= len(chunk)
                        await f_out.write(decryptor.update(chunk))

                    tag = await f_in.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise DecryptionError("Invalid encrypted file.")
                    await f_out.write(decryptor.finalize_with_tag(tag))
                os.replace(temp_path, output_file_path)
                temp_path = None
            except Exception as exc:  # pragma: no cover - high-level error handling
                _cleanup_temp_file(temp_path)
                raise DecryptionError(
                    "File decryption failed: Invalid password or corrupted file."
                ) from exc
    except DecryptionError:
        raise
    except Exception as exc:
        raise OSError(f"Failed to read encrypted file: {exc}") from exc


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
