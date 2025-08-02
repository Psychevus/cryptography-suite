import os
import pytest

from cryptography_suite.keystores import load_plugins, get_keystore

pkcs11 = pytest.importorskip("pkcs11")

LIB = os.getenv("PKCS11_LIBRARY")
LABEL = os.getenv("PKCS11_TOKEN_LABEL")
PIN = os.getenv("PKCS11_PIN", "1234")

if not LIB or not LABEL:
    pytest.skip("PKCS#11 library not configured", allow_module_level=True)

load_plugins()
PKCS11KS = get_keystore("pkcs11")


@pytest.fixture(scope="session")
def ks():
    ks = PKCS11KS(LIB, LABEL, PIN)
    # seed an RSA key if none exist
    with ks._session() as session:  # type: ignore[attr-defined]
        if not ks.list_keys():
            session.generate_keypair(pkcs11.KeyType.RSA, 2048, label="rsa")
    return ks


def test_list_keys(ks):
    keys = ks.list_keys()
    assert keys
    assert all(isinstance(k, str) for k in keys)


def test_sign_decrypt_roundtrip(ks):
    data = b"hello"
    with ks._session() as session:  # type: ignore[attr-defined]
        key = ks._get_key(session, "rsa")  # type: ignore[attr-defined]
        ciphertext = key.public_key.encrypt(data, mechanism=pkcs11.Mechanism.RSA_PKCS)
    assert ks.decrypt("rsa", ciphertext) == data
    sig = ks.sign("rsa", data)
    assert isinstance(sig, bytes) and sig
