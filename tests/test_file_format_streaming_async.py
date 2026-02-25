from __future__ import annotations

import asyncio
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography_suite.constants import NONCE_SIZE, SALT_SIZE
from cryptography_suite.errors import DecryptionError
from cryptography_suite.symmetric.aes import (
    CHUNK_SIZE,
    decrypt_file_async,
    encrypt_file_async,
)
from cryptography_suite.symmetric.kdf import select_kdf


def _require_aiofiles() -> Any:
    return pytest.importorskip("aiofiles")


def test_async_roundtrip_streams_large_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    aiofiles = _require_aiofiles()

    plain = tmp_path / "large.bin"
    enc = tmp_path / "large.enc"
    out = tmp_path / "large.out"

    block = b"ABCD" * 4096
    target_size = 11 * 1024 * 1024
    written = 0
    with plain.open("wb") as handle:
        while written < target_size:
            remaining = target_size - written
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            written += len(chunk)

    plain_read_sizes: list[int] = []
    enc_read_sizes: list[int] = []

    class ReaderProxy:
        def __init__(self, wrapped: Any, sizes: list[int]) -> None:
            self._wrapped = wrapped
            self._sizes = sizes

        async def read(self, n: int = -1) -> bytes:
            self._sizes.append(n)
            return await self._wrapped.read(n)

        def __getattr__(self, item: str) -> Any:
            return getattr(self._wrapped, item)

    class OpenProxy:
        def __init__(self, wrapped: Any, file: str, mode: str) -> None:
            self._wrapped = wrapped
            self._file = str(file)
            self._mode = mode

        async def __aenter__(self) -> Any:
            handle = await self._wrapped.__aenter__()
            if self._file == str(plain) and "rb" in self._mode:
                return ReaderProxy(handle, plain_read_sizes)
            if self._file == str(enc) and "rb" in self._mode:
                return ReaderProxy(handle, enc_read_sizes)
            return handle

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
            return await self._wrapped.__aexit__(exc_type, exc, tb)

    def wrapped_open(file: str, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        return OpenProxy(aiofiles.open(file, mode, *args, **kwargs), file, mode)

    fake_aiofiles = types.SimpleNamespace(open=wrapped_open)
    monkeypatch.setattr("cryptography_suite.symmetric.aes._import_aiofiles", lambda: fake_aiofiles)

    asyncio.run(encrypt_file_async(str(plain), str(enc), "pw"))
    asyncio.run(decrypt_file_async(str(enc), str(out), "pw"))

    assert out.read_bytes() == plain.read_bytes()
    assert plain_read_sizes
    assert enc_read_sizes
    assert -1 not in plain_read_sizes
    assert -1 not in enc_read_sizes
    assert max(plain_read_sizes) <= CHUNK_SIZE
    assert max(enc_read_sizes) <= CHUNK_SIZE


def test_async_decrypt_corrupt_tag_raises(tmp_path: Path) -> None:
    _require_aiofiles()

    plain = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"A" * 5000)

    asyncio.run(encrypt_file_async(str(plain), str(enc), "pw"))
    tampered = bytearray(enc.read_bytes())
    tampered[-1] ^= 0xFF
    enc.write_bytes(bytes(tampered))

    with pytest.raises(DecryptionError, match="Invalid password or corrupted file"):
        asyncio.run(decrypt_file_async(str(enc), str(out), "pw"))


def test_async_legacy_format_decrypt_still_supported(tmp_path: Path) -> None:
    _require_aiofiles()

    plain = b"legacy bytes"
    salt = bytes([0x33]) * SALT_SIZE
    nonce = bytes([0x44]) * NONCE_SIZE
    key = select_kdf("pw", salt, "scrypt")
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)

    legacy = tmp_path / "legacy.enc"
    out = tmp_path / "legacy.out"
    legacy.write_bytes(salt + nonce + ciphertext)

    asyncio.run(decrypt_file_async(str(legacy), str(out), "pw", kdf="scrypt"))
    assert out.read_bytes() == plain
