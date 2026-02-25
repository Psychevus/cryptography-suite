import timeit

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography_suite.aead import AESGCMContext
from cryptography_suite.nonce import KeyRotationRequired, NonceManager, NonceReuseError


def test_nonce_reuse_detection() -> None:
    for nonce in (bytes([0]) * 12, bytes(range(12)), b"n" * 12):
        nm = NonceManager(mode="strict")
        nm.remember(nonce)
        with pytest.raises(NonceReuseError):
            nm.remember(nonce)


def test_nonce_reuse_detection_lru_window() -> None:
    nm = NonceManager(mode="lru", cache_size=2)
    nonce_a = (1).to_bytes(12, "big")
    nonce_b = (2).to_bytes(12, "big")
    nonce_c = (3).to_bytes(12, "big")

    nm.remember(nonce_a)
    nm.remember(nonce_b)
    with pytest.raises(NonceReuseError):
        nm.remember(nonce_a)

    nm.remember(nonce_c)  # evicts nonce_a
    nm.remember(nonce_a)  # no longer in bounded replay cache


def test_encrypt_after_limit_raises_key_rotation() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key, byte_limit=16)
    nm = NonceManager()
    ctx.encrypt(nm=nm, plaintext=b"a" * 8)
    with pytest.raises(KeyRotationRequired):
        ctx.encrypt(nm=nm, plaintext=b"b" * 9)


def test_decrypt_tracking_rejects_reused_nonce() -> None:
    key = AESGCM.generate_key(bit_length=128)
    enc_ctx = AESGCMContext(key, nonce_tracking="encrypt")
    dec_ctx = AESGCMContext(key, nonce_tracking="decrypt")
    nm_enc = NonceManager(mode="strict")
    nonce, ct = enc_ctx.encrypt(nm=nm_enc, plaintext=b"msg")
    nm_dec = NonceManager(mode="strict")
    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct) == b"msg"
    with pytest.raises(NonceReuseError):
        dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)


def test_nonce_manager_overhead() -> None:
    nm = NonceManager()
    duration = timeit.timeit(
        "nonce = nm.next(); nm.remember(nonce)", globals={"nm": nm}, number=1000
    )
    assert duration < 0.2


def test_nonce_limit_triggers_rotation() -> None:
    for limit in range(1, 11):
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
    with pytest.raises(ValueError):
        NonceManager(mode="unknown")
    with pytest.raises(ValueError):
        NonceManager(cache_size=0)


def test_nonce_manager_rejects_bad_length() -> None:
    nm = NonceManager()
    with pytest.raises(ValueError):
        nm.remember(b"short")


def test_nonce_manager_enforces_exact_nonce_size() -> None:
    nm = NonceManager()
    for bad_len in (0, 11, 13, 24):
        with pytest.raises(ValueError):
            nm.remember(b"x" * bad_len)


def test_nonce_manager_start_value_is_encoded_big_endian() -> None:
    nm = NonceManager(start=255, limit=300)
    assert nm.next() == (255).to_bytes(12, "big")


def test_nonce_manager_limit_must_exceed_start() -> None:
    with pytest.raises(ValueError):
        NonceManager(start=9, limit=8)
