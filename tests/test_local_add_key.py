import json
import warnings

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from cryptography_suite.errors import StrictKeyPolicyError
from cryptography_suite.keystores.local import LocalKeyStore


def test_add_import_and_sign(tmp_path):
    ks = LocalKeyStore(directory=str(tmp_path))
    msg = b"hello"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_id = ks.add_key(rsa_key, "rsa", password="pwd")
    assert rsa_id in ks.list_keys()
    sig = ks.sign(rsa_id, msg, password="pwd")
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
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("ignore")
        ec_id = ks.import_key(pem, "ec", allow_unencrypted=True)
    assert ec_id in ks.list_keys()
    sig2 = ks.sign(ec_id, msg)
    ec_key.public_key().verify(sig2, msg, ec.ECDSA(hashes.SHA256()))
    assert caught == []


def test_unencrypted_add_and_import_require_explicit_unsafe(tmp_path):
    ks = LocalKeyStore(directory=str(tmp_path))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with pytest.raises(StrictKeyPolicyError, match="disabled by default"):
        ks.add_key(key, "rsa")
    with pytest.raises(StrictKeyPolicyError, match="disabled by default"):
        ks.import_key(pem, "rsa")


def test_encrypted_import_preserves_metadata(tmp_path):
    ks = LocalKeyStore(directory=str(tmp_path))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pwd"),
    )

    key_id = ks.import_key(pem, {"id": "encrypted", "type": "rsa"})
    _, meta = ks.export_key(key_id)

    assert meta["encrypted"] is True
    assert (tmp_path / f"{key_id}.pem").read_bytes() == pem


def test_legacy_password_metadata_is_ignored(tmp_path):
    ks = LocalKeyStore(directory=str(tmp_path))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    key_id = ks.add_key(key, "rsa", password="pwd")
    meta_path = tmp_path / f"{key_id}.json"
    meta = json.loads(meta_path.read_text())
    assert "password" not in json.dumps(meta)

    meta["password"] = "legacy"
    meta_path.write_text(json.dumps(meta))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(ValueError, match="Password required"):
            ks._load_key(key_id)
    assert any(
        "Ignoring legacy persisted password metadata" in str(w.message) for w in caught
    )

    loaded, algo = ks._load_key(key_id, password="pwd")
    assert algo == "rsa"
    assert isinstance(loaded, rsa.RSAPrivateKey)
