from __future__ import annotations

from pathlib import Path
from typing import List

from . import register_keystore
from ..audit import audit_log
from ..asymmetric import load_private_key, rsa_decrypt
from ..asymmetric.signatures import sign_message


@register_keystore("local")
class LocalKeyStore:
    """File-based keystore for development and testing."""

    name = "local"

    def __init__(self, directory: str = "keys") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(exist_ok=True)

    def list_keys(self) -> List[str]:
        return [p.stem for p in self.dir.glob("*.pem")]

    def test_connection(self) -> bool:
        return True

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        with open(key_path, "rb") as f:
            priv = load_private_key(f.read(), None)
        return sign_message(data, priv, raw_output=True)

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        with open(key_path, "rb") as f:
            priv = load_private_key(f.read(), None)
        return rsa_decrypt(data, priv)

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)
