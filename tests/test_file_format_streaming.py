from __future__ import annotations

from pathlib import Path
from typing import IO, Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography_suite.constants import NONCE_SIZE, SALT_SIZE
from cryptography_suite.errors import DecryptionError
from cryptography_suite.symmetric.aes import (
    CHUNK_SIZE,
    FORMAT_MAGIC,
    FORMAT_VERSION,
    decrypt_file,
    encrypt_file,
)
from cryptography_suite.symmetric.kdf import select_kdf


def test_small_file_roundtrip_and_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    vals = [b"\\x11" * SALT_SIZE, b"\\x22" * NONCE_SIZE]

    def fake_urandom(size: int) -> bytes:
        return vals.pop(0)

    monkeypatch.setattr("cryptography_suite.symmetric.aes.urandom", fake_urandom)

    plain = tmp_path / "plain.txt"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"hello streaming format")

    encrypt_file(str(plain), str(enc), "pw", kdf="scrypt")
    data = enc.read_bytes()

    assert data[:4] == FORMAT_MAGIC
    assert data[4] == FORMAT_VERSION
    assert data[5] == 1  # scrypt id

    decrypt_file(str(enc), str(out), "pw")
    assert out.read_bytes() == b"hello streaming format"


def test_corruption_detected(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"A" * 5000)

    encrypt_file(str(plain), str(enc), "pw")
    tampered = bytearray(enc.read_bytes())
    tampered[-20] ^= 0xFF
    enc.write_bytes(bytes(tampered))

    with pytest.raises(DecryptionError, match="Invalid password or corrupted file"):
        decrypt_file(str(enc), str(out), "pw")


def test_wrong_password_detected(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"B" * 200)

    encrypt_file(str(plain), str(enc), "pw")

    with pytest.raises(DecryptionError, match="Invalid password or corrupted file"):
        decrypt_file(str(enc), str(out), "wrong")


def test_encrypt_streams_in_chunks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plain = tmp_path / "big.bin"
    enc = tmp_path / "big.enc"
    plain.write_bytes(b"Z" * (CHUNK_SIZE * 3 + 123))

    read_sizes: list[int] = []

    class ReaderProxy:
        def __init__(self, wrapped: IO[bytes]) -> None:
            self._wrapped = wrapped

        def read(self, n: int = -1) -> bytes:
            read_sizes.append(n)
            return self._wrapped.read(n)

        def __getattr__(self, item: str) -> Any:
            return getattr(self._wrapped, item)

        def __enter__(self) -> ReaderProxy:
            self._wrapped.__enter__()
            return self

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
            return self._wrapped.__exit__(exc_type, exc, tb)

    import builtins

    real_open = builtins.open

    def wrapped_open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if str(file) == str(plain) and "rb" in mode:
            return ReaderProxy(handle)
        return handle

    monkeypatch.setattr("builtins.open", wrapped_open)

    encrypt_file(str(plain), str(enc), "pw")

    assert read_sizes.count(CHUNK_SIZE) >= 3


def test_legacy_format_decrypt_still_supported(tmp_path: Path) -> None:
    plain = b"legacy bytes"
    salt = bytes([0x33]) * SALT_SIZE
    nonce = bytes([0x44]) * NONCE_SIZE
    key = select_kdf("pw", salt, "scrypt")
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)

    legacy = tmp_path / "legacy.enc"
    out = tmp_path / "legacy.out"
    legacy.write_bytes(salt + nonce + ciphertext)

    decrypt_file(str(legacy), str(out), "pw", kdf="scrypt")
    assert out.read_bytes() == plain


def test_versioned_header_rejects_truncated_salt_and_nonce(tmp_path: Path) -> None:
    enc = tmp_path / "bad.enc"
    out = tmp_path / "bad.out"
    # Header announces salt/nonce lengths that are not present in payload.
    bad_header = (
        FORMAT_MAGIC
        + bytes([FORMAT_VERSION, 1, SALT_SIZE, NONCE_SIZE])
        + (CHUNK_SIZE).to_bytes(4, "big")
        + b"\x00" * (SALT_SIZE - 1)
    )
    enc.write_bytes(bad_header + b"\x00" * 16)

    with pytest.raises(DecryptionError, match="Invalid encrypted file"):
        decrypt_file(str(enc), str(out), "pw")


def test_decrypt_enforces_minimum_stream_chunk_size(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "tiny-chunk.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"Q" * 5000)

    encrypt_file(str(plain), str(enc), "pw", kdf="scrypt")

    data = bytearray(enc.read_bytes())
    # Overwrite chunk-size field in versioned header with value below 1024.
    data[8:12] = (1).to_bytes(4, "big")
    enc.write_bytes(bytes(data))

    import builtins

    read_sizes: list[int] = []
    real_open = builtins.open

    class ReaderProxy:
        def __init__(self, wrapped: IO[bytes]) -> None:
            self._wrapped = wrapped

        def read(self, n: int = -1) -> bytes:
            read_sizes.append(n)
            return self._wrapped.read(n)

        def __getattr__(self, item: str) -> Any:
            return getattr(self._wrapped, item)

        def __enter__(self) -> ReaderProxy:
            self._wrapped.__enter__()
            return self

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
            return self._wrapped.__exit__(exc_type, exc, tb)

    def wrapped_open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if str(file) == str(enc) and "rb" in mode:
            return ReaderProxy(handle)
        return handle

    monkeypatch.setattr("builtins.open", wrapped_open)

    decrypt_file(str(enc), str(out), "pw", kdf="scrypt")
    assert out.read_bytes() == plain.read_bytes()
    assert 1024 in read_sizes
