from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple, cast

from . import register_keystore
from ..audit import audit_log
from ..asymmetric import rsa_decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from ..asymmetric.signatures import (
    sign_message,
    sign_message_ecdsa,
    sign_message_rsa,
)


@register_keystore("local")
class LocalKeyStore:
    """File-based keystore for development and testing."""

    name = "local"
    status = "testing"

    def __init__(self, directory: str = "keys") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(exist_ok=True)

    def list_keys(self) -> List[str]:
        return [p.stem for p in self.dir.glob("*.pem")]

    def test_connection(self) -> bool:
        return True

    def _load_key(self, key_id: str) -> Tuple[object, str]:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        with open(key_path, "rb") as f:
            pem = f.read()
            key = serialization.load_pem_private_key(pem, password=None)

        meta_path = key_path.with_suffix(".json")
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                algo = meta.get("type")
            except Exception:
                algo = None
        else:
            algo = None

        if algo is None:
            if isinstance(key, ed25519.Ed25519PrivateKey):
                algo = "ed25519"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                algo = "ecdsa"
            elif isinstance(key, rsa.RSAPrivateKey):
                algo = "rsa"
            else:
                raise ValueError("Unsupported key type")
            meta_path.write_text(json.dumps({"type": algo}))

        return key, cast(str, algo)

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        key, algo = self._load_key(key_id)
        if algo == "ed25519":
            signature = cast(
                bytes,
                sign_message(data, cast(ed25519.Ed25519PrivateKey, key), raw_output=True),
            )
        elif algo == "ecdsa":
            signature = cast(
                bytes,
                sign_message_ecdsa(
                    data, cast(ec.EllipticCurvePrivateKey, key), raw_output=True
                ),
            )
        elif algo == "rsa":
            signature = cast(
                bytes,
                sign_message_rsa(data, cast(rsa.RSAPrivateKey, key), raw_output=True),
            )
        else:
            raise ValueError(f"Unsupported key type: {algo}")
        return signature

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        key, algo = self._load_key(key_id)
        if algo != "rsa":
            raise ValueError("Key type not suitable for decryption")
        return rsa_decrypt(data, cast(rsa.RSAPrivateKey, key))

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)

    @audit_log
    def export_key(self, key_id: str) -> Tuple[bytes, dict]:
        key_path = self.dir / f"{key_id}.pem"
        raw = key_path.read_bytes()
        _, algo = self._load_key(key_id)
        return raw, {"id": key_id, "type": algo}

    @audit_log
    def import_key(self, raw: bytes, meta: dict) -> str:
        key_id = cast(str, meta.get("id", "imported"))
        key_path = self.dir / f"{key_id}.pem"
        if key_path.exists():
            i = 1
            while (self.dir / f"{key_id}_{i}.pem").exists():
                i += 1
            key_id = f"{key_id}_{i}"
            key_path = self.dir / f"{key_id}.pem"
        key_path.write_bytes(raw)
        (key_path.with_suffix(".json")).write_text(json.dumps({"type": meta.get("type")}))
        return key_id
