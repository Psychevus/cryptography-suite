from __future__ import annotations

import datetime as dt
import hashlib
import json
import warnings
from pathlib import Path
from typing import Any, TypeAlias, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .. import config
from .._key_files import atomic_write_bytes
from ..asymmetric import rsa_decrypt
from ..asymmetric.signatures import (
    sign_message,
    sign_message_ecdsa,
    sign_message_rsa,
)
from ..audit import audit_log
from ..errors import StrictKeyPolicyError
from ..utils import _detect_private_pem_encryption, is_encrypted_pem
from . import register_keystore
from .base import KeyStoreCapability

PrivateKey: TypeAlias = (
    ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
)


@register_keystore("local")
class LocalKeyStore:
    """File-based keystore for development and testing."""

    name = "local"
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

    def __init__(self, directory: str = "keys") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def list_keys(self) -> list[str]:
        return [p.stem for p in self.dir.glob("*.pem")]

    def test_connection(self) -> bool:
        return True

    def _load_key(
        self, key_id: str, password: str | None = None
    ) -> tuple[PrivateKey, str]:
        key_path = self.dir / f"{key_id}.pem"
        if not key_path.exists():
            raise FileNotFoundError(key_path)
        policy = config.STRICT_KEYS
        detected_encrypted = is_encrypted_pem(key_path)
        if policy in {"warn", "error"} and not detected_encrypted:
            msg = f"Unencrypted private key: {key_path}"
            if policy == "error":
                raise StrictKeyPolicyError(msg)
            warnings.warn(msg, UserWarning, stacklevel=2)
        meta_path = key_path.with_suffix(".json")
        encrypted = detected_encrypted
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                algo = meta.get("type")
                encrypted = detected_encrypted or bool(meta.get("encrypted", False))
                if "password" in meta:
                    warnings.warn(
                        (
                            "Ignoring legacy persisted password metadata for key: "
                            f"{key_id}"
                        ),
                        UserWarning,
                        stacklevel=2,
                    )
            except Exception:
                algo = None
                encrypted = False
        else:
            algo = None
        if encrypted and password is None:
            raise ValueError(f"Password required to load encrypted key: {key_id}")
        with open(key_path, "rb") as f:
            pem = f.read()
            try:
                key = serialization.load_pem_private_key(
                    pem,
                    password=password.encode() if isinstance(password, str) else None,
                )
            except TypeError as exc:
                if "encrypted" in str(exc).lower() and password is None:
                    raise ValueError(
                        f"Password required to load encrypted key: {key_id}"
                    ) from exc
                raise

        if algo is None:
            if isinstance(key, ed25519.Ed25519PrivateKey):
                algo = "ed25519"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                algo = "ecdsa"
            elif isinstance(key, rsa.RSAPrivateKey):
                algo = "rsa"
            else:
                raise ValueError("Unsupported key type")
            self._write_metadata(meta_path, {"type": algo, "encrypted": encrypted})

        return cast(PrivateKey, key), cast(str, algo)

    @audit_log
    def sign(self, key_id: str, data: bytes, password: str | None = None) -> bytes:
        key, algo = self._load_key(key_id, password=password)
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
    def decrypt(self, key_id: str, data: bytes, password: str | None = None) -> bytes:
        key, algo = self._load_key(key_id, password=password)
        if algo != "rsa":
            raise ValueError("Key type not suitable for decryption")
        return rsa_decrypt(data, cast(rsa.RSAPrivateKey, key))

    @audit_log
    def unwrap(
        self, key_id: str, wrapped_key: bytes, password: str | None = None
    ) -> bytes:
        return self.decrypt(key_id, wrapped_key, password=password)

    @audit_log
    def export_key(
        self, key_id: str, password: str | None = None
    ) -> tuple[bytes, dict]:
        key_path = self.dir / f"{key_id}.pem"
        raw = key_path.read_bytes()
        encrypted = _detect_private_pem_encryption(raw)
        if encrypted is None:
            raise ValueError(f"Stored key is not a PEM private key: {key_id}")

        meta = self._read_metadata(key_path.with_suffix(".json"))
        algo = meta.get("type")
        if algo is None or password is not None or not encrypted:
            _, algo = self._load_key(key_id, password=password)
        return raw, {
            "id": key_id,
            "type": algo,
            "encrypted": encrypted,
            "fingerprint": meta.get("fingerprint"),
            "name": meta.get("name", key_id),
        }

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

    def _read_metadata(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write_metadata(self, path: Path, meta: dict[str, Any]) -> None:
        atomic_write_bytes(path, json.dumps(meta, sort_keys=True).encode())

    def _enforce_unencrypted_write_policy(
        self,
        action: str,
        *,
        allow_unencrypted: bool,
    ) -> None:
        msg = (
            f"{action} unencrypted private key is disabled by default. Provide a "
            "password or pass allow_unencrypted=True only for controlled "
            "development/testing migration."
        )
        if config.STRICT_KEYS == "error":
            raise StrictKeyPolicyError(
                f"{action} unencrypted private key is blocked by "
                "CRYPTOSUITE_STRICT_KEYS=error"
            )
        if not allow_unencrypted:
            raise StrictKeyPolicyError(msg)
        if config.STRICT_KEYS == "warn":
            warnings.warn(
                (
                    f"UNSAFE: {action.lower()} unencrypted private key in "
                    "LocalKeyStore. Use encrypted PEM or a hardware-backed keystore "
                    "outside controlled testing/migration."
                ),
                UserWarning,
                stacklevel=3,
            )

    def _allocate_import_path(self, key_id: str) -> tuple[str, Path]:
        candidate = key_id
        key_path = self.dir / f"{candidate}.pem"
        if not key_path.exists():
            return candidate, key_path
        i = 1
        while (self.dir / f"{key_id}_{i}.pem").exists():
            i += 1
        candidate = f"{key_id}_{i}"
        return candidate, self.dir / f"{candidate}.pem"

    @audit_log
    def add_key(
        self,
        private_key_obj: PrivateKey,
        name: str,
        password: str | None = None,
        *,
        allow_unencrypted: bool = False,
    ) -> str:
        algo = self._algo(private_key_obj)
        fingerprint = self._fingerprint(private_key_obj)
        key_id = fingerprint[:16]
        key_path = self.dir / f"{key_id}.pem"
        if not password:
            self._enforce_unencrypted_write_policy(
                "Adding",
                allow_unencrypted=allow_unencrypted,
            )
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
        atomic_write_bytes(key_path, pem)
        meta = {
            "name": name,
            "type": algo,
            "created": dt.datetime.now(dt.timezone.utc).isoformat(),
            "fingerprint": fingerprint,
            "encrypted": bool(password),
        }
        self._write_metadata(key_path.with_suffix(".json"), meta)
        return key_id

    @audit_log
    def import_key(
        self,
        raw: bytes,
        name_or_meta: str | dict,
        password: str | None = None,
        *,
        allow_unencrypted: bool = False,
    ) -> str:
        detected_encrypted = _detect_private_pem_encryption(raw)
        if detected_encrypted is None:
            raise ValueError("LocalKeyStore only imports PEM private keys.")

        if isinstance(name_or_meta, dict):
            meta = name_or_meta
            key_id = cast(str, meta.get("id", "imported"))
            if not detected_encrypted:
                self._enforce_unencrypted_write_policy(
                    "Importing",
                    allow_unencrypted=allow_unencrypted,
                )
            key_id, key_path = self._allocate_import_path(key_id)
            atomic_write_bytes(key_path, raw)
            migrated_meta = {
                "name": meta.get("name", key_id),
                "type": meta.get("type"),
                "created": dt.datetime.now(dt.timezone.utc).isoformat(),
                "fingerprint": meta.get("fingerprint"),
                "encrypted": detected_encrypted,
            }
            self._write_metadata(
                key_path.with_suffix(".json"),
                migrated_meta,
            )
            return key_id
        name = name_or_meta
        if detected_encrypted and password is None:
            raise ValueError("Password required to import encrypted private key.")
        load_password = (
            password.encode() if detected_encrypted and password is not None else None
        )
        key = serialization.load_pem_private_key(
            raw,
            password=load_password,
        )
        if detected_encrypted or password:
            return self.add_key(cast(PrivateKey, key), name, password)
        return self.add_key(
            cast(PrivateKey, key),
            name,
            allow_unencrypted=allow_unencrypted,
        )
