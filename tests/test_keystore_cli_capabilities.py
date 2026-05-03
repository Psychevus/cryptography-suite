from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_suite.cli import keystore_cli
from cryptography_suite.keystores import KeyStoreCapability
from cryptography_suite.keystores.base import supports_capability


class SrcNoExport:
    capabilities = frozenset({KeyStoreCapability.SIGN})

    def list_keys(self):
        return ["k1"]


class DstNoImport:
    capabilities = frozenset(
        {KeyStoreCapability.SIGN, KeyStoreCapability.EXPORT_PRIVATE_KEY}
    )


class SrcWithExport:
    capabilities = frozenset({KeyStoreCapability.EXPORT_PRIVATE_KEY})

    def list_keys(self):
        return ["k1"]

    def export_key(self, key_id):
        return (b"x", {"id": key_id, "type": "rsa"})


class SrcPlaintextExport:
    capabilities = frozenset({KeyStoreCapability.EXPORT_PRIVATE_KEY})

    def __init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def list_keys(self):
        return ["plain"]

    def export_key(self, key_id):
        return (self.pem, {"id": key_id, "type": "rsa", "encrypted": False})


class DstWithImport:
    capabilities = frozenset({KeyStoreCapability.IMPORT_PRIVATE_KEY})

    def __init__(self) -> None:
        self.imported: list[tuple[bytes, dict[str, object], bool]] = []

    def import_key(
        self,
        raw: bytes,
        meta: dict[str, object],
        *,
        allow_unencrypted: bool = False,
    ) -> str:
        self.imported.append((raw, meta, allow_unencrypted))
        return "new"


def test_migrate_fails_closed_when_source_cannot_export(monkeypatch):
    import cryptography_suite.keystores as ks

    monkeypatch.setattr(ks, "load_plugins", lambda directory=None: None)
    monkeypatch.setattr(ks, "failed_plugins", lambda: [])
    monkeypatch.setattr(
        ks, "get_keystore", lambda name: SrcNoExport if name == "src" else DstNoImport
    )

    with pytest.raises(ValueError, match="does not support raw key export"):
        keystore_cli(["migrate", "--from", "src", "--to", "dst", "--apply"])


def test_migrate_fails_closed_when_destination_cannot_import(monkeypatch):
    import cryptography_suite.keystores as ks

    monkeypatch.setattr(ks, "load_plugins", lambda directory=None: None)
    monkeypatch.setattr(ks, "failed_plugins", lambda: [])
    monkeypatch.setattr(
        ks, "get_keystore", lambda name: SrcWithExport if name == "src" else DstNoImport
    )

    with pytest.raises(ValueError, match="does not support raw key import"):
        keystore_cli(["migrate", "--from", "src", "--to", "dst", "--apply"])


def test_supports_capability_checks_declared_capabilities() -> None:
    class BareStore:
        capabilities = frozenset({KeyStoreCapability.SIGN})

    assert supports_capability(BareStore(), KeyStoreCapability.SIGN)
    assert not supports_capability(BareStore(), KeyStoreCapability.IMPORT_PRIVATE_KEY)


def test_migrate_requires_apply_unless_dry_run(monkeypatch):
    import cryptography_suite.keystores as ks

    monkeypatch.setattr(ks, "load_plugins", lambda directory=None: None)
    monkeypatch.setattr(ks, "failed_plugins", lambda: [])
    monkeypatch.setattr(
        ks, "get_keystore", lambda name: SrcWithExport if name == "src" else DstNoImport
    )

    with pytest.raises(ValueError, match="without --apply"):
        keystore_cli(["migrate", "--from", "src", "--to", "dst"])


def test_migrate_blocks_plaintext_private_key_by_default(monkeypatch, capsys):
    import cryptography_suite.keystores as ks

    monkeypatch.setattr(ks, "load_plugins", lambda directory=None: None)
    monkeypatch.setattr(ks, "failed_plugins", lambda: [])
    monkeypatch.setattr(
        ks,
        "get_keystore",
        lambda name: SrcPlaintextExport if name == "src" else DstWithImport,
    )

    with pytest.raises(SystemExit):
        keystore_cli(["migrate", "--from", "src", "--to", "dst", "--apply"])
    assert "Refusing to migrate unencrypted" in capsys.readouterr().out


def test_migrate_plaintext_requires_explicit_unsafe_flag(monkeypatch, capsys):
    import cryptography_suite.keystores as ks

    destination = DstWithImport()

    monkeypatch.setattr(ks, "load_plugins", lambda directory=None: None)
    monkeypatch.setattr(ks, "failed_plugins", lambda: [])

    def fake_get_keystore(name: str) -> Any:
        if name == "src":
            return SrcPlaintextExport

        def destination_factory() -> DstWithImport:
            return destination

        return destination_factory

    monkeypatch.setattr(ks, "get_keystore", fake_get_keystore)

    keystore_cli(
        [
            "migrate",
            "--from",
            "src",
            "--to",
            "dst",
            "--apply",
            "--unsafe-allow-unencrypted-private-key",
        ]
    )

    assert destination.imported[0][2] is True
    assert "plain -> new" in capsys.readouterr().out
