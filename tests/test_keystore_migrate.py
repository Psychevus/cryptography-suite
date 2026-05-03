import sys
import types
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography_suite.errors import StrictKeyPolicyError
from cryptography_suite.keystores import get_keystore, load_plugins
from cryptography_suite.keystores.local import LocalKeyStore


def test_roundtrip_local_mock(tmp_path: Path):
    load_plugins()
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pwd"),
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "k1.pem").write_bytes(pem)
    (src_dir / "k1.json").write_text(
        '{"type": "ed25519", "encrypted": true, "name": "k1"}'
    )
    src_cls = cast(type[LocalKeyStore], get_keystore("local"))
    src = src_cls(directory=str(src_dir))
    dst = get_keystore("mock_hsm")()
    raw, meta = src.export_key("k1")
    new_id = dst.import_key(raw, meta)
    raw2, meta2 = dst.export_key(new_id)
    dst_dir = tmp_path / "dst"
    dst_dir.mkdir()
    local2_cls = cast(type[LocalKeyStore], get_keystore("local"))
    local2 = local2_cls(directory=str(dst_dir))
    new_id2 = local2.import_key(raw2, meta2)
    raw3, meta3 = local2.export_key(new_id2)
    assert raw == raw3
    assert meta["type"] == meta3["type"]
    assert meta3["encrypted"] is True


def test_local_import_blocks_plaintext_downgrade(tmp_path: Path):
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    local = LocalKeyStore(directory=str(tmp_path))
    with pytest.raises(StrictKeyPolicyError, match="unencrypted private key"):
        local.import_key(pem, {"id": "plain", "type": "ed25519"})


def test_aws_kms_import_is_not_supported(monkeypatch):
    load_plugins()
    fake_client = types.SimpleNamespace()
    boto3_mod = types.SimpleNamespace(client=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore()
    with pytest.raises(NotImplementedError, match="raw private key import"):
        ks.import_key(b"raw", {"type": "rsa", "id": "kid"})
