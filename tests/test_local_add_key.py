import warnings
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

from cryptography_suite.keystores.local import LocalKeyStore


def test_add_import_and_sign(tmp_path):
    ks = LocalKeyStore(directory=str(tmp_path))
    msg = b"hello"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_id = ks.add_key(rsa_key, "rsa", password="pwd")
    assert rsa_id in ks.list_keys()
    sig = ks.sign(rsa_id, msg)
    rsa_key.public_key().verify(
        sig,
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ec_id = ks.import_key(pem, "ec")
    assert ec_id in ks.list_keys()
    sig2 = ks.sign(ec_id, msg)
    ec_key.public_key().verify(sig2, msg, ec.ECDSA(hashes.SHA256()))
