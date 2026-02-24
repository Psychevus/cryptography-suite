import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from cryptography_suite.asymmetric import rsa_encrypt
from cryptography_suite.audit import InMemoryAuditLogger, set_audit_logger
from cryptography_suite.cli import keystore_cli
from cryptography_suite.keystores import get_keystore, list_keystores, load_plugins


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
    assert "aws-kms (limited)" in out


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
    fake_client.get_public_key.return_value = {
        "KeySpec": "RSA_2048",
        "SigningAlgorithms": ["RSASSA_PSS_SHA_256"],
    }

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


def test_plugin_failure_isolated(tmp_path: Path, capsys):
    broken_dir = tmp_path / "keystores"
    broken_dir.mkdir()
    (broken_dir / "broken.py").write_text("raise RuntimeError('boom')")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        os.environ["CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS"] = "1"
        with pytest.raises(SystemExit) as exc:
            keystore_cli(["list"])
        assert exc.value.code != 0
        out = capsys.readouterr().out
        assert "broken (broken)" in out
    finally:
        os.environ.pop("CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS", None)
        os.chdir(cwd)


def test_load_plugins_does_not_import_cwd_plugins_without_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    local_dir = tmp_path / "keystores"
    local_dir.mkdir()
    (local_dir / "evil_plugin.py").write_text(
        """
from pathlib import Path
Path('pwned.txt').write_text('owned')
"""
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS", raising=False)

    load_plugins()

    assert not (tmp_path / "pwned.txt").exists()


def test_load_plugins_imports_cwd_plugins_with_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    local_dir = tmp_path / "keystores"
    local_dir.mkdir()
    (local_dir / "opt_in_plugin.py").write_text(
        """
from pathlib import Path
from cryptography_suite.keystores import register_keystore

Path('opted_in.txt').write_text('loaded')

@register_keystore('opt-in')
class OptInKS:
    name = 'opt-in'
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
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS", "1")

    load_plugins()

    assert (tmp_path / "opted_in.txt").exists()
    assert "opt-in" in list_keystores()
