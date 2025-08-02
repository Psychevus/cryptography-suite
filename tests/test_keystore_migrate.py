import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography_suite.keystores import get_keystore, load_plugins
from cryptography_suite.errors import UnsupportedAlgorithm


def test_roundtrip_local_mock(tmp_path: Path):
    load_plugins()
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "k1.pem").write_bytes(pem)
    src = get_keystore("local")(directory=str(src_dir))
    dst = get_keystore("mock_hsm")()
    raw, meta = src.export_key("k1")
    new_id = dst.import_key(raw, meta)
    raw2, meta2 = dst.export_key(new_id)
    dst_dir = tmp_path / "dst"
    dst_dir.mkdir()
    local2 = get_keystore("local")(directory=str(dst_dir))
    new_id2 = local2.import_key(raw2, meta2)
    raw3, meta3 = local2.export_key(new_id2)
    assert raw == raw3
    assert meta["type"] == meta3["type"]


def test_aws_kms_import(monkeypatch):
    load_plugins()
    fake_client = types.SimpleNamespace(import_key=MagicMock())
    boto3_mod = types.SimpleNamespace(client=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)
    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore()
    ks.import_key(b"raw", {"type": "rsa", "id": "kid"})
    fake_client.import_key.assert_called_once()
    with pytest.raises(UnsupportedAlgorithm):
        ks.import_key(b"raw", {"type": "unknown"})
