import importlib
import json
import warnings

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_suite.keystores.local import LocalKeyStore
from cryptography_suite.errors import StrictKeyPolicyError, SecurityError
from cryptography_suite.utils import KeyVault
import cryptography_suite.config as config


@pytest.fixture(autouse=True)
def reset_config(monkeypatch):
    yield
    monkeypatch.delenv("CRYPTOSUITE_STRICT_KEYS", raising=False)
    importlib.reload(config)

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
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "error")
    importlib.reload(config)
    ks = LocalKeyStore(str(tmp_path))
    with pytest.raises(StrictKeyPolicyError):
        ks.sign("k", b"data")
    with pytest.raises(StrictKeyPolicyError):
        ks.import_key(pem, {"id": "new", "type": "rsa"})


def test_strict_keys_warn(monkeypatch, tmp_path):
    pem = _unencrypted_rsa_pem()
    _write_key(tmp_path, pem)
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "warn")
    importlib.reload(config)
    ks = LocalKeyStore(str(tmp_path))
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        ks.sign("k", b"data")
        ks.import_key(pem, {"id": "new", "type": "rsa"})
    assert len(w) >= 2


def test_strict_keys_disabled(monkeypatch, tmp_path):
    pem = _unencrypted_rsa_pem()
    _write_key(tmp_path, pem)
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "0")
    importlib.reload(config)
    ks = LocalKeyStore(str(tmp_path))
    assert ks.sign("k", b"data")
    ks.import_key(pem, {"id": "new", "type": "rsa"})


def test_keyvault_write_pem_warn(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "warn")
    importlib.reload(config)
    kv = KeyVault(b"secret")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        kv._write_pem(tmp_path / "k.pem", encrypted=False)
    assert len(w) == 1


def test_keyvault_write_pem_error(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "error")
    importlib.reload(config)
    kv = KeyVault(b"secret")
    with pytest.raises(SecurityError):
        kv._write_pem(tmp_path / "k.pem", encrypted=False)


def test_keyvault_write_pem_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "0")
    importlib.reload(config)
    kv = KeyVault(b"secret")
    kv._write_pem(tmp_path / "k.pem", encrypted=False)
