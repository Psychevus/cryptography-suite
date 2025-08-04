from __future__ import annotations

import json
import os
import warnings
import hashlib
import datetime as dt
from pathlib import Path
from typing import List, Tuple, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec

from . import register_keystore
from ..audit import audit_log
from ..asymmetric import rsa_decrypt
from ..asymmetric.signatures import (
    sign_message,
    sign_message_ecdsa,
    sign_message_rsa,
)
from ..errors import StrictKeyPolicyError
from ..utils import is_encrypted_pem

PrivateKey = ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey


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

    def _load_key(self, key_id: str) -> Tuple[PrivateKey, str]:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        policy = os.getenv("CRYPTOSUITE_STRICT_KEYS")
        if policy and not is_encrypted_pem(key_path):
            msg = f"Unencrypted private key: {key_path}"
            if policy == "1":
                raise StrictKeyPolicyError(msg)
            elif policy == "warn":
                warnings.warn(msg, UserWarning)
        meta_path = key_path.with_suffix(".json")
        password = None
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                algo = meta.get("type")
                password = meta.get("password")
            except Exception:
                algo = None
                password = None
        else:
            algo = None
        with open(key_path, "rb") as f:
            pem = f.read()
            key = serialization.load_pem_private_key(
                pem, password=password.encode() if isinstance(password, str) else None
            )

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

        return cast(PrivateKey, key), cast(str, algo)

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        key, algo = self._load_key(key_id)
        if algo == "ed25519":
            signature = cast(
                bytes,
                sign_message(
                    data, cast(ed25519.Ed25519PrivateKey, key), raw_output=True
                ),
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

    def _fingerprint(self, key: PrivateKey) -> str:
        pub = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(pub).hexdigest()

    def _algo(self, key: PrivateKey) -> str:
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return "ecdsa"
        if isinstance(key, rsa.RSAPrivateKey):
            return "rsa"
        raise ValueError("Unsupported key type")

    @audit_log
    def add_key(
        self, private_key_obj: PrivateKey, name: str, password: str | None = None
    ) -> str:
        algo = self._algo(private_key_obj)
        fingerprint = self._fingerprint(private_key_obj)
        key_id = fingerprint[:16]
        key_path = self.dir / f"{key_id}.pem"
        policy = os.getenv("CRYPTOSUITE_STRICT_KEYS")
        if not password:
            msg = "Adding unencrypted private key"
            if policy == "1":
                raise StrictKeyPolicyError(msg)
            warnings.warn(msg, UserWarning)
            encryption: serialization.KeySerializationEncryption = (
                serialization.NoEncryption()
            )
        else:
            encryption = serialization.BestAvailableEncryption(password.encode())
        pem = private_key_obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        key_path.write_bytes(pem)
        meta = {
            "name": name,
            "type": algo,
            "created": dt.datetime.now(dt.timezone.utc).isoformat(),
            "fingerprint": fingerprint,
        }
        if password:
            meta["password"] = password
        key_path.with_suffix(".json").write_text(json.dumps(meta))
        return key_id

    @audit_log
    def import_key(
        self, raw: bytes, name_or_meta: str | dict, password: str | None = None
    ) -> str:
        if isinstance(name_or_meta, dict):
            meta = name_or_meta
            key_id = cast(str, meta.get("id", "imported"))
            policy = os.getenv("CRYPTOSUITE_STRICT_KEYS")
            if policy:
                try:
                    serialization.load_pem_private_key(raw, password=None)
                    encrypted = False
                except TypeError as exc:
                    encrypted = "encrypted" in str(exc).lower()
                if not encrypted:
                    msg = "Importing unencrypted private key"
                    if policy == "1":
                        raise StrictKeyPolicyError(msg)
                    elif policy == "warn":
                        warnings.warn(msg, UserWarning)
            key_path = self.dir / f"{key_id}.pem"
            if key_path.exists():
                i = 1
                while (self.dir / f"{key_id}_{i}.pem").exists():
                    i += 1
                key_id = f"{key_id}_{i}"
                key_path = self.dir / f"{key_id}.pem"
            key_path.write_bytes(raw)
            (key_path.with_suffix(".json")).write_text(
                json.dumps({"type": meta.get("type")})
            )
            return key_id
        name = cast(str, name_or_meta)
        key = serialization.load_pem_private_key(
            raw, password=password.encode() if password else None
        )
        return self.add_key(key, name, password)
