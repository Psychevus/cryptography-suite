import timeit

import pytest
from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography_suite.nonce import KeyRotationRequired, NonceManager, NonceReuseError
from cryptography_suite.aead import AESGCMContext


@given(st.binary(min_size=12, max_size=12))
def test_nonce_reuse_detection(nonce: bytes) -> None:
    nm = NonceManager()
    nm.remember(nonce)
    with pytest.raises(NonceReuseError):
        nm.remember(nonce)


def test_encrypt_after_limit_raises_key_rotation() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key, byte_limit=16)
    nm = NonceManager()
    ctx.encrypt(nm=nm, plaintext=b"a" * 8)
    with pytest.raises(KeyRotationRequired):
        ctx.encrypt(nm=nm, plaintext=b"b" * 9)


def test_encrypt_rejects_reused_nonce_with_nonce_manager() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key)
    nm = NonceManager()
    nonce, ct = ctx.encrypt(nm=nm, plaintext=b"msg")
    with pytest.raises(NonceReuseError):
        ctx.decrypt(nm=nm, nonce=nonce, ciphertext=ct)


def test_nonce_manager_overhead() -> None:
    nm = NonceManager()
    duration = timeit.timeit(
        "nonce = nm.next(); nm.remember(nonce)", globals={"nm": nm}, number=1000
    )
    assert duration < 0.2


@given(st.integers(min_value=1, max_value=10))
def test_nonce_limit_triggers_rotation(limit: int) -> None:
    nm = NonceManager(limit=limit)
    for _ in range(limit):
        nm.next()
    with pytest.raises(KeyRotationRequired):
        nm.next()


def test_nonce_manager_invalid_parameters() -> None:
    with pytest.raises(ValueError):
        NonceManager(start=-1)
    with pytest.raises(ValueError):
        NonceManager(start=5, limit=5)


def test_nonce_manager_rejects_bad_length() -> None:
    nm = NonceManager()
    with pytest.raises(ValueError):
        nm.remember(b"short")
