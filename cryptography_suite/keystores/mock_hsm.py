from __future__ import annotations

from typing import List

from . import register_keystore
from ..audit import audit_log


@register_keystore("mock_hsm")
class MockHSMKeyStore:
    """In-memory keystore emulating an HSM for testing."""

    name = "mock_hsm"
    status = "testing"

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {"test": b"secret"}

    def list_keys(self) -> List[str]:
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
