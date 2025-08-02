import json
import warnings

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_suite.keystores.local import LocalKeyStore
from cryptography_suite.errors import StrictKeyPolicyError

def _unencrypted_rsa_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _write_key(tmp_path, pem):
    key_path = tmp_path / "k.pem"
    key_path.write_bytes(pem)
    (tmp_path / "k.json").write_text(json.dumps({"type": "rsa"}))


def test_strict_keys_error(monkeypatch, tmp_path):
    pem = _unencrypted_rsa_pem()
    _write_key(tmp_path, pem)
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "1")
    ks = LocalKeyStore(str(tmp_path))
    with pytest.raises(StrictKeyPolicyError):
        ks.sign("k", b"data")
    with pytest.raises(StrictKeyPolicyError):
        ks.import_key(pem, {"id": "new", "type": "rsa"})


def test_strict_keys_warn(monkeypatch, tmp_path):
    pem = _unencrypted_rsa_pem()
    _write_key(tmp_path, pem)
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "warn")
    ks = LocalKeyStore(str(tmp_path))
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        ks.sign("k", b"data")
        ks.import_key(pem, {"id": "new", "type": "rsa"})
    assert len(w) >= 2


def test_strict_keys_unset(monkeypatch, tmp_path):
    pem = _unencrypted_rsa_pem()
    _write_key(tmp_path, pem)
    monkeypatch.delenv("CRYPTOSUITE_STRICT_KEYS", raising=False)
    ks = LocalKeyStore(str(tmp_path))
    assert ks.sign("k", b"data")
    ks.import_key(pem, {"id": "new", "type": "rsa"})
