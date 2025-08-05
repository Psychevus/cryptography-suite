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
    ctx.encrypt(b"a" * 8, nm=nm)
    with pytest.raises(KeyRotationRequired):
        ctx.encrypt(b"b" * 9, nm=nm)


def test_encrypt_rejects_reused_nonce_with_nonce_manager() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key)
    nm = NonceManager()
    nonce, _ = ctx.encrypt(b"msg", nm=nm)
    with pytest.raises(NonceReuseError):
        ctx.encrypt(b"again", nonce=nonce, nm=nm)


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
