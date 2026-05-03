from __future__ import annotations

from ..audit import audit_log
from . import register_keystore
from .base import KeyStoreCapability


@register_keystore("mock_hsm")
class MockHSMKeyStore:
    """In-memory keystore emulating an HSM for testing."""

    name = "mock_hsm"
    status = "testing"
    capabilities = frozenset(
        {
            KeyStoreCapability.SIGN,
            KeyStoreCapability.DECRYPT,
            KeyStoreCapability.UNWRAP,
            KeyStoreCapability.EXPORT_PRIVATE_KEY,
            KeyStoreCapability.IMPORT_PRIVATE_KEY,
        }
    )

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {"test": b"secret"}
        self._meta: dict[str, dict] = {"test": {"type": "raw"}}

    def list_keys(self) -> list[str]:
        return list(self._keys.keys())

    def test_connection(self) -> bool:
        return True

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise FileNotFoundError(key_id)
        return data + key  # fake signature

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise FileNotFoundError(key_id)
        return data.replace(key, b"")

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return wrapped_key[::-1]

    @audit_log
    def export_key(self, key_id: str) -> tuple[bytes, dict]:
        data = self._keys[key_id]
        meta = self._meta.get(key_id, {"type": "raw"})
        return data, {"id": key_id, **meta}

    @audit_log
    def import_key(
        self,
        raw: bytes,
        meta: dict,
        *,
        allow_unencrypted: bool = False,
    ) -> str:
        key_id = meta.get("id", f"k{len(self._keys)}")
        self._keys[key_id] = raw
        self._meta[key_id] = {k: v for k, v in meta.items() if k != "id"}
        return key_id
