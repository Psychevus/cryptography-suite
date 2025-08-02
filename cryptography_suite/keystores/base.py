from __future__ import annotations

from typing import Any, Dict, Protocol, Tuple, runtime_checkable


@runtime_checkable
class KeyStore(Protocol):
    """Common interface for key store backends."""

    name: str
    status: str

    def list_keys(self) -> list[str]:
        """Return available key identifiers."""

    def test_connection(self) -> bool:
        """Check backend availability."""

    def sign(self, key_id: str, data: bytes) -> bytes:
        """Sign ``data`` using ``key_id``."""

    def decrypt(self, key_id: str, data: bytes) -> bytes:
        """Decrypt ``data`` using ``key_id``."""

    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        """Unwrap ``wrapped_key`` using ``key_id``."""

    def export_key(self, key_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Return raw key material and associated metadata."""

    def import_key(self, raw: bytes, meta: Dict[str, Any]) -> str:
        """Import ``raw`` with ``meta`` and return the new key identifier."""
