from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography_suite.constants import NONCE_SIZE, SALT_SIZE
from cryptography_suite.errors import DecryptionError
from cryptography_suite.symmetric.aes import (
    CHUNK_SIZE,
    FORMAT_MAGIC,
    decrypt_file_async,
    encrypt_file_async,
)
from cryptography_suite.symmetric.kdf import select_kdf


class _AsyncFileProxy:
    def __init__(self, handle: Any, read_sizes: list[int]) -> None:
        self._handle = handle
        self._read_sizes = read_sizes

    async def __aenter__(self) -> _AsyncFileProxy:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        self._handle.close()
        return None

    async def read(self, n: int = -1) -> bytes:
        self._read_sizes.append(n)
        return self._handle.read(n)

    async def write(self, data: bytes) -> int:
        return self._handle.write(data)

    async def seek(self, offset: int, whence: int = 0) -> int:
        return self._handle.seek(offset, whence)

    async def tell(self) -> int:
        return self._handle.tell()


class _AiofilesStub:
    def __init__(self, read_sizes: list[int]) -> None:
        self._read_sizes = read_sizes

    def open(self, path: str, mode: str):
        handle = open(path, mode)
        return _AsyncFileProxy(handle, self._read_sizes)


def test_encrypt_decrypt_async_streams_large_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plain = tmp_path / "large.bin"
    enc = tmp_path / "large.enc"
    out = tmp_path / "large.out"

    # Generate > 10MB without materializing the payload in memory.
    block = b"ABCD" * 1024
    with plain.open("wb") as f:
        for _ in range(3000):
            f.write(block)

    read_sizes: list[int] = []
    monkeypatch.setattr(
        "cryptography_suite.symmetric.aes._import_aiofiles",
        lambda: _AiofilesStub(read_sizes),
    )

    async def run() -> None:
        await encrypt_file_async(str(plain), str(enc), "pw", kdf="scrypt")
        await decrypt_file_async(str(enc), str(out), "pw", kdf="scrypt")

    asyncio.run(run())

    assert out.read_bytes() == plain.read_bytes()
    assert enc.read_bytes()[:4] == FORMAT_MAGIC
    assert all(size != -1 for size in read_sizes)
    assert max(size for size in read_sizes if size > 0) <= CHUNK_SIZE
    assert read_sizes.count(CHUNK_SIZE) > 1


def test_decrypt_async_detects_corrupted_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"X" * 2048)

    monkeypatch.setattr(
        "cryptography_suite.symmetric.aes._import_aiofiles",
        lambda: _AiofilesStub([]),
    )

    async def encrypt() -> None:
        await encrypt_file_async(str(plain), str(enc), "pw")

    asyncio.run(encrypt())

    tampered = bytearray(enc.read_bytes())
    tampered[-1] ^= 0xAA
    enc.write_bytes(bytes(tampered))

    async def decrypt_bad() -> None:
        await decrypt_file_async(str(enc), str(out), "pw")

    with pytest.raises(DecryptionError, match="Invalid password or corrupted file"):
        asyncio.run(decrypt_bad())


def test_decrypt_async_supports_legacy_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plain = b"legacy async bytes"
    salt = bytes([0x55]) * SALT_SIZE
    nonce = bytes([0x66]) * NONCE_SIZE
    key = select_kdf("pw", salt, "scrypt")
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)

    legacy = tmp_path / "legacy.enc"
    out = tmp_path / "legacy.out"
    legacy.write_bytes(salt + nonce + ciphertext)

    monkeypatch.setattr(
        "cryptography_suite.symmetric.aes._import_aiofiles",
        lambda: _AiofilesStub([]),
    )

    async def run() -> None:
        await decrypt_file_async(str(legacy), str(out), "pw", kdf="scrypt")

    asyncio.run(run())

    assert out.read_bytes() == plain
