import os
import pytest

salsa = pytest.importorskip("cryptography_suite.optional.salsa20")
from cryptography_suite.errors import EncryptionError, DecryptionError


def test_salsa20_encrypt_decrypt():
    key = os.urandom(32)
    nonce = os.urandom(8)
    msg = b"secret"
    ct = salsa.salsa20_encrypt(msg, key, nonce)
    pt = salsa.salsa20_decrypt(ct, key, nonce)
    assert pt == msg


def test_salsa20_deterministic():
    key = os.urandom(32)
    nonce = os.urandom(8)
    msg = b"msg"
    ct1 = salsa.salsa20_encrypt(msg, key, nonce)
    ct2 = salsa.salsa20_encrypt(msg, key, nonce)
    assert ct1 == ct2


def test_salsa20_invalid_lengths():
    with pytest.raises(EncryptionError):
        salsa.salsa20_encrypt(b"x", b"short", b"12345678")
    with pytest.raises(EncryptionError):
        salsa.salsa20_encrypt(b"x", os.urandom(32), b"short")
    with pytest.raises(DecryptionError):
        salsa.salsa20_decrypt(b"", os.urandom(32), os.urandom(8))
