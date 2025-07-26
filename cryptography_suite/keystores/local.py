from __future__ import annotations

from pathlib import Path
from typing import List, cast

from . import register_keystore
from ..audit import audit_log
from ..asymmetric import rsa_decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
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
            pem = f.read()
            priv = cast(ed25519.Ed25519PrivateKey,
                        serialization.load_pem_private_key(pem, password=None))
        signature = cast(bytes, sign_message(data, priv, raw_output=True))
        return signature

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        with open(key_path, "rb") as f:
            pem = f.read()
            priv = cast(rsa.RSAPrivateKey,
                        serialization.load_pem_private_key(pem, password=None))
        return rsa_decrypt(data, priv)

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)
