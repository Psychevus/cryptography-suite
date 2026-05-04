import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptography_suite.asymmetric import generate_rsa_keypair, generate_x25519_keypair
from cryptography_suite.pipeline import (
    ECIESX25519Decrypt,
    ECIESX25519Encrypt,
    HybridDecrypt,
    HybridEncrypt,
    MLKEMDecrypt,
    MLKEMEncrypt,
    Pipeline,
)
from cryptography_suite.pqc import PQCRYPTO_AVAILABLE, generate_ml_kem_keypair

PRIVATE_X25519, PUBLIC_X25519 = generate_x25519_keypair()
RSA_PRIV, RSA_PUB = generate_rsa_keypair(key_size=2048)

if PQCRYPTO_AVAILABLE:
    KYBER_PUB, KYBER_PRIV = generate_ml_kem_keypair()
else:  # pragma: no cover - environment without pqcrypto
    KYBER_PUB = KYBER_PRIV = b""


@given(message=st.binary(min_size=1, max_size=256))
def test_ecies_pipeline_roundtrip(message: bytes) -> None:
    pipe = (
        Pipeline()
        >> ECIESX25519Encrypt(public_key=PUBLIC_X25519)
        >> ECIESX25519Decrypt(private_key=PRIVATE_X25519)
    )
    assert pipe.run(message) == message


@given(message=st.binary(min_size=1, max_size=256))
def test_hybrid_pipeline_roundtrip(message: bytes) -> None:
    pipe = (
        Pipeline()
        >> HybridEncrypt(public_key=RSA_PUB)
        >> HybridDecrypt(private_key=RSA_PRIV)
    )
    assert pipe.run(message) == message


@pytest.mark.skipif(not PQCRYPTO_AVAILABLE, reason="pqcrypto not installed")
@given(message=st.binary(min_size=1, max_size=256))
def test_kyber_pipeline_roundtrip(message: bytes) -> None:
    pipe = (
        Pipeline()
        >> MLKEMEncrypt(public_key=KYBER_PUB)
        >> MLKEMDecrypt(private_key=KYBER_PRIV)
    )
    assert pipe.run(message) == message
