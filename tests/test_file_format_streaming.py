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
    HEADER_FIXED_SIZE,
    decrypt_file,
    encrypt_file,
)
from cryptography_suite.symmetric.kdf import select_kdf


def test_small_file_roundtrip_and_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    vals = [b"\x11" * SALT_SIZE, b"\x22" * NONCE_SIZE]

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


def _assert_failure_preserves_existing_output(enc: Path, out: Path) -> None:
    out.write_bytes(b"existing output must survive")

    with pytest.raises(DecryptionError):
        decrypt_file(str(enc), str(out), "pw", kdf="scrypt")

    assert out.read_bytes() == b"existing output must survive"
    assert not list(out.parent.glob(f".{out.name}.*.tmp"))


@pytest.mark.parametrize(
    "case",
    [
        "modified_header",
        "modified_kdf_id",
        "modified_salt",
        "modified_nonce",
        "modified_ciphertext",
        "modified_tag",
        "truncated_file",
        "malformed_header_lengths",
        "invalid_version",
    ],
)
def test_tampered_v2_file_rejected_without_touching_existing_output(
    tmp_path: Path,
    case: str,
) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / f"{case}.enc"
    out = tmp_path / f"{case}.out"
    plain.write_bytes(b"authenticated plaintext" * 16)

    encrypt_file(str(plain), str(enc), "pw", kdf="scrypt")
    data = bytearray(enc.read_bytes())
    ciphertext_start = HEADER_FIXED_SIZE + SALT_SIZE + NONCE_SIZE

    if case == "modified_header":
        data[8:12] = (CHUNK_SIZE // 2).to_bytes(4, "big")
    elif case == "modified_kdf_id":
        data[5] = 2
    elif case == "modified_salt":
        data[HEADER_FIXED_SIZE] ^= 0x01
    elif case == "modified_nonce":
        data[HEADER_FIXED_SIZE + SALT_SIZE] ^= 0x01
    elif case == "modified_ciphertext":
        data[ciphertext_start] ^= 0x01
    elif case == "modified_tag":
        data[-1] ^= 0x01
    elif case == "truncated_file":
        data = data[:-1]
    elif case == "malformed_header_lengths":
        data[6] = SALT_SIZE + 1
    elif case == "invalid_version":
        data[4] = 99
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(case)

    enc.write_bytes(bytes(data))
    _assert_failure_preserves_existing_output(enc, out)


def test_failed_decrypt_does_not_create_requested_output_or_leave_temp(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "plain.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"wrong-password leaves no output")

    encrypt_file(str(plain), str(enc), "pw", kdf="scrypt")

    with pytest.raises(DecryptionError, match="Invalid password or corrupted file"):
        decrypt_file(str(enc), str(out), "wrong", kdf="scrypt")

    assert not out.exists()
    assert not list(tmp_path.glob(f".{out.name}.*.tmp"))


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

    decrypt_file(str(legacy), str(out), "pw", kdf="scrypt", allow_legacy_format=True)
    assert out.read_bytes() == plain


def test_versioned_v1_requires_explicit_legacy_flag(tmp_path: Path) -> None:
    plain = b"versioned v1 bytes"
    salt = bytes([0x77]) * SALT_SIZE
    nonce = bytes([0x88]) * NONCE_SIZE
    key = select_kdf("pw", salt, "scrypt")
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)
    header = (
        FORMAT_MAGIC
        + bytes([1, 1, SALT_SIZE, NONCE_SIZE])
        + (CHUNK_SIZE).to_bytes(4, "big")
        + salt
        + nonce
    )

    enc = tmp_path / "v1.enc"
    out = tmp_path / "v1.out"
    enc.write_bytes(header + ciphertext)

    with pytest.raises(DecryptionError, match="allow_legacy_format=True"):
        decrypt_file(str(enc), str(out), "pw", kdf="scrypt")

    decrypt_file(str(enc), str(out), "pw", kdf="scrypt", allow_legacy_format=True)
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


def test_decrypt_rejects_malformed_stream_chunk_size(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "tiny-chunk.enc"
    out = tmp_path / "plain.out"
    plain.write_bytes(b"Q" * 5000)

    encrypt_file(str(plain), str(enc), "pw", kdf="scrypt")

    data = bytearray(enc.read_bytes())
    # Overwrite chunk-size field in versioned header with value below 1024.
    data[8:12] = (1).to_bytes(4, "big")
    enc.write_bytes(bytes(data))

    with pytest.raises(DecryptionError, match="Invalid encrypted file"):
        decrypt_file(str(enc), str(out), "pw", kdf="scrypt")
    assert not out.exists()
