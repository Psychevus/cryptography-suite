import base64
import pytest
from hypothesis import given, strategies as st
from cryptography_suite.asymmetric import generate_x25519_keypair, ec_encrypt, ec_decrypt
from cryptography_suite.errors import CryptographySuiteError

PRIVATE_KEY, PUBLIC_KEY = generate_x25519_keypair()

@given(message=st.binary(min_size=1, max_size=256))
def test_ecies_roundtrip(message: bytes) -> None:
    ciphertext = ec_encrypt(message, PUBLIC_KEY)
    plaintext = ec_decrypt(ciphertext, PRIVATE_KEY)
    assert plaintext == message

@given(message=st.binary(min_size=1, max_size=256))
def test_ecies_tamper_raises(message: bytes) -> None:
    ciphertext = ec_encrypt(message, PUBLIC_KEY)
    data = bytearray(base64.b64decode(ciphertext))
    if data:
        data[0] ^= 0xFF
    tampered = base64.b64encode(bytes(data)).decode()
    with pytest.raises(CryptographySuiteError):
        ec_decrypt(tampered, PRIVATE_KEY)

def test_ecies_invalid_keys() -> None:
    with pytest.raises(TypeError):
        ec_encrypt(b"data", object())
    with pytest.raises(TypeError):
        ec_decrypt(b"data", object())
