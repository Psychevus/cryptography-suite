import pytest

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
