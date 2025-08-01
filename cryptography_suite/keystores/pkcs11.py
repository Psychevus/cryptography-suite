"""Sample PKCS#11 keystore plugin skeleton.

This module is not registered by default.  It serves as a template for
implementing PKCS#11-backed key stores.  Developers should install a
``python-pkcs11`` compatible library and fill in the methods below.
"""

from __future__ import annotations

from typing import List

# from . import register_keystore  # Uncomment to register
# from ..audit import audit_log


# @register_keystore("pkcs11")
class PKCS11KeyStore:
    """PKCS#11 KeyStore example (not functional)."""

    name = "pkcs11"
    status = "experimental"

    def __init__(self, library_path: str, token_label: str, pin: str) -> None:
        raise NotImplementedError("PKCS#11 support is a skeleton example")

    def list_keys(self) -> List[str]:
        raise NotImplementedError

    def test_connection(self) -> bool:
        raise NotImplementedError

    def sign(self, key_id: str, data: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key_id: str, data: bytes) -> bytes:
        raise NotImplementedError

    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        raise NotImplementedError
