import base64
import pytest
from hypothesis import given, strategies as st
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt
from cryptography_suite.errors import CryptographySuiteError

PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair(key_size=2048)

@given(message=st.binary(min_size=1, max_size=256))
def test_rsa_roundtrip(message: bytes) -> None:
    ciphertext = RSAEncrypt(public_key=PUBLIC_KEY).run(message)
    plaintext = RSADecrypt(private_key=PRIVATE_KEY).run(ciphertext)
    assert plaintext == message

@given(message=st.binary(min_size=1, max_size=256))
def test_rsa_tamper_raises(message: bytes) -> None:
    ciphertext = RSAEncrypt(public_key=PUBLIC_KEY).run(message)
    data = bytearray(base64.b64decode(ciphertext))
    if data:
        data[0] ^= 0xFF
    tampered = base64.b64encode(bytes(data)).decode()
    with pytest.raises(CryptographySuiteError):
        RSADecrypt(private_key=PRIVATE_KEY).run(tampered)

def test_rsa_invalid_keys() -> None:
    with pytest.raises(TypeError):
        RSAEncrypt(public_key=object()).run(b"data")
    with pytest.raises(TypeError):
        RSADecrypt(private_key=object()).run(b"cipher")
