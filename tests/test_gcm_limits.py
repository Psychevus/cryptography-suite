import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given
from hypothesis import strategies as st

from cryptography_suite.aead import (
    AESGCMContext,
    chacha20_decrypt_aead,
    chacha20_encrypt_aead,
)
from cryptography_suite.nonce import (
    KeyRotationRequired,
    NonceManager,
    NonceReuseError,
)


@given(st.binary())
def test_reuse_nonce_raises(pt: bytes) -> None:
    key = AESGCM.generate_key(bit_length=128)
    enc_ctx = AESGCMContext(key, nonce_tracking="encrypt")
    dec_ctx = AESGCMContext(key, nonce_tracking="decrypt")
    nm_enc = NonceManager(mode="strict")
    nonce, ct = enc_ctx.encrypt(nm=nm_enc, plaintext=pt)
    nm_dec = NonceManager(mode="strict")
    dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)
    with pytest.raises(NonceReuseError):
        dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)


@given(st.binary(min_size=0, max_size=32))
def test_message_cap_enforced(pt: bytes) -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key)
    nm = NonceManager(limit=2**33)
    ctx._msg_counter = 2**32
    with pytest.raises(KeyRotationRequired):
        ctx.encrypt(nm=nm, plaintext=pt)


@given(st.binary(min_size=1, max_size=16))
def test_message_cap_independent_of_byte_limit(pt: bytes) -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key, byte_limit=1024)
    nm = NonceManager(limit=2**33)
    ctx._msg_counter = 2**32
    with pytest.raises(KeyRotationRequired):
        ctx.encrypt(nm=nm, plaintext=pt)
    # verify byte accounting still below limit
    assert ctx.bytes_processed == len(pt)


def test_chacha20_aead_roundtrip() -> None:
    key = b"\x01" * 32
    nonce = b"\x02" * 12
    pt = b"hello"
    ct = chacha20_encrypt_aead(pt, key, nonce)
    assert chacha20_decrypt_aead(ct, key, nonce) == pt


def test_chacha20_aead_validation() -> None:
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    with pytest.raises(ValueError):
        chacha20_encrypt_aead(b"", key[:-1], nonce)
    with pytest.raises(ValueError):
        chacha20_encrypt_aead(b"", key, nonce[:-1])
    with pytest.raises(ValueError):
        chacha20_decrypt_aead(b"", key[:-1], nonce)
    with pytest.raises(ValueError):
        chacha20_decrypt_aead(b"", key, nonce[:-1])


def test_aesgcmcontext_rejects_bad_key() -> None:
    with pytest.raises(ValueError):
        AESGCMContext(b"short")


def test_aesgcmcontext_decrypt_roundtrip() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key)
    nm_enc = NonceManager()
    nonce, ct = ctx.encrypt(nm=nm_enc, plaintext=b"msg")
    nm_dec = NonceManager()
    pt = ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)
    assert pt == b"msg"


def test_aesgcmcontext_decrypt_byte_limit() -> None:
    key = AESGCM.generate_key(bit_length=128)
    ctx = AESGCMContext(key, byte_limit=1)
    nm_enc = NonceManager()
    nonce, ct = ctx.encrypt(nm=nm_enc, plaintext=b"a")
    nm_dec = NonceManager()
    with pytest.raises(KeyRotationRequired):
        ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)


def test_aesgcmcontext_rejects_bad_nonce_tracking_mode() -> None:
    key = AESGCM.generate_key(bit_length=128)
    with pytest.raises(ValueError):
        AESGCMContext(key, nonce_tracking="invalid")


def test_decrypt_replay_detection_bounded_by_lru_window() -> None:
    key = AESGCM.generate_key(bit_length=128)
    enc_ctx = AESGCMContext(key, nonce_tracking="encrypt")
    dec_ctx = AESGCMContext(key, nonce_tracking="decrypt")

    nm_enc = NonceManager(mode="strict")
    nonce_1, ct_1 = enc_ctx.encrypt(nm=nm_enc, plaintext=b"one")
    nonce_2, ct_2 = enc_ctx.encrypt(nm=nm_enc, plaintext=b"two")
    nonce_3, ct_3 = enc_ctx.encrypt(nm=nm_enc, plaintext=b"three")

    nm_dec = NonceManager(mode="lru", cache_size=2)
    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce_1, ciphertext=ct_1) == b"one"
    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce_2, ciphertext=ct_2) == b"two"
    with pytest.raises(NonceReuseError):
        dec_ctx.decrypt(nm=nm_dec, nonce=nonce_1, ciphertext=ct_1)

    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce_3, ciphertext=ct_3) == b"three"
    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce_1, ciphertext=ct_1) == b"one"


def test_decrypt_replay_detection_strict_mode_always_rejects_reuse() -> None:
    key = AESGCM.generate_key(bit_length=128)
    enc_ctx = AESGCMContext(key, nonce_tracking="encrypt")
    dec_ctx = AESGCMContext(key, nonce_tracking="decrypt")

    nm_enc = NonceManager(mode="strict")
    nonce, ct = enc_ctx.encrypt(nm=nm_enc, plaintext=b"msg")

    nm_dec = NonceManager(mode="strict")
    assert dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct) == b"msg"
    with pytest.raises(NonceReuseError):
        dec_ctx.decrypt(nm=nm_dec, nonce=nonce, ciphertext=ct)
