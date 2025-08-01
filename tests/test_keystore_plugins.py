import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa

from cryptography_suite.keystores import load_plugins, list_keystores, get_keystore
from cryptography_suite.cli import keystore_cli
from cryptography_suite.audit import InMemoryAuditLogger, set_audit_logger
from cryptography_suite.asymmetric import rsa_encrypt


def test_keystore_loader():
    load_plugins()
    names = list_keystores()
    assert "local" in names
    assert "aws-kms" in names
    cls = get_keystore("local")
    ks = cls()
    assert ks.test_connection()


def test_keystore_cli_list(capsys):
    load_plugins()
    keystore_cli(["list"])
    out = capsys.readouterr().out
    assert "local (testing)" in out
    assert "mock_hsm (testing)" in out
    assert "aws-kms (production)" in out


def test_mock_hsm_audit():
    load_plugins()
    log = InMemoryAuditLogger()
    set_audit_logger(log)
    ks = get_keystore("mock_hsm")()
    ks.sign("test", b"data")
    ks.decrypt("test", b"data")
    set_audit_logger(None)
    assert log.logs[0]["operation"] == "sign"
    assert log.logs[1]["operation"] == "decrypt"


def test_local_keystore_key_types(tmp_path: Path):
    load_plugins()
    ed = ed25519.Ed25519PrivateKey.generate()
    ec_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def write(p: Path, key):
        p.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    write(tmp_path / "ed.pem", ed)
    write(tmp_path / "ec.pem", ec_key)
    write(tmp_path / "rsa.pem", rsa_key)

    ks = get_keystore("local")(directory=str(tmp_path))
    assert isinstance(ks.sign("ed", b"msg"), bytes)
    assert isinstance(ks.sign("ec", b"msg"), bytes)

    ciphertext = rsa_encrypt(b"secret", rsa_key.public_key(), raw_output=True)
    assert ks.decrypt("rsa", ciphertext) == b"secret"


def test_aws_kms_plugin_operations(monkeypatch):
    fake_client = MagicMock()
    fake_client.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "k1"}]}
    ]
    fake_client.list_keys.return_value = {"Keys": []}
    fake_client.sign.return_value = {"Signature": b"sig"}
    fake_client.decrypt.return_value = {"Plaintext": b"plain"}

    boto3_mod = types.SimpleNamespace(client=lambda *args, **kwargs: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore(region_name="us-west-2")
    assert ks.list_keys() == ["k1"]
    assert ks.test_connection()
    assert ks.sign("k1", b"d") == b"sig"
    assert ks.decrypt("k1", b"x") == b"plain"


def test_external_plugin_loading(tmp_path: Path):
    plugin_code = """
from cryptography_suite.keystores import register_keystore

@register_keystore('ext')
class ExtKS:
    name = 'ext'
    status = 'testing'

    def list_keys(self):
        return []

    def test_connection(self):
        return True

    def sign(self, key_id, data):
        return b''

    def decrypt(self, key_id, data):
        return b''

    def unwrap(self, key_id, wrapped_key):
        return b''
"""
    (tmp_path / "ext.py").write_text(plugin_code)
    load_plugins(directory=str(tmp_path))
    assert "ext" in list_keystores()
