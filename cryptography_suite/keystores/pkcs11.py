"""PKCS#11 keystore plugin using python-pkcs11."""

from __future__ import annotations

import os
import threading
import pathlib
import contextlib
import hashlib
from typing import List

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover - fallback for older Python
    tomllib = None  # type: ignore

try:  # optional dependency
    import pkcs11  # type: ignore[import-not-found, import-untyped]
    from pkcs11 import (  # type: ignore[import-not-found, import-untyped]
        Attribute,
        ObjectClass,
        KeyType,
        Mechanism,
    )
except Exception:  # pragma: no cover - dependency missing
    pkcs11 = None  # type: ignore

from . import register_keystore
from ..audit import audit_log


@register_keystore("pkcs11")
class PKCS11KeyStore:
    """PKCS#11 backed keystore.

    Configuration is loaded from environment variables or ``~/.cryptosuite.toml``:

    - ``PKCS11_LIBRARY`` / ``library_path``
    - ``PKCS11_TOKEN_LABEL`` / ``token_label``
    - ``PKCS11_PIN`` / ``pin``
    """

    name = "pkcs11"
    status = "production"

    def __init__(self,
                 library_path: str | None = None,
                 token_label: str | None = None,
                 pin: str | None = None) -> None:
        if pkcs11 is None:  # pragma: no cover - dependency missing
            raise ImportError(
                "python-pkcs11>=0.8.1 is required for PKCS11KeyStore"
            )

        library_path, token_label, pin = self._load_config(
            library_path, token_label, pin
        )

        self.library_path = library_path
        self.token_label = token_label
        self.pin = pin

        self.lib = pkcs11.lib(self.library_path)
        self.token = self.lib.get_token(token_label=self.token_label)
        self.token_serial = self.token.serial

        self._session_cache = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # configuration helpers
    def _load_config(
        self,
        library_path: str | None,
        token_label: str | None,
        pin: str | None,
    ) -> tuple[str, str, str]:
        env = os.environ
        library_path = library_path or env.get("PKCS11_LIBRARY")
        token_label = token_label or env.get("PKCS11_TOKEN_LABEL")
        pin = pin or env.get("PKCS11_PIN")

        if library_path and token_label and pin:
            return library_path, token_label, pin

        cfg_path = pathlib.Path.home() / ".cryptosuite.toml"
        if cfg_path.exists() and tomllib is not None:
            try:
                cfg = tomllib.loads(cfg_path.read_text())
                section = cfg.get("pkcs11", {})
                library_path = library_path or section.get("library_path")
                token_label = token_label or section.get("token_label")
                pin = pin or section.get("pin")
            except Exception:  # pragma: no cover - config errors
                pass

        if not (library_path and token_label and pin):
            raise ValueError("Missing PKCS#11 configuration")
        return library_path, token_label, pin

    # ------------------------------------------------------------------
    @contextlib.contextmanager
    def _session(self):
        """Return a cached session with locking and automatic login."""
        with self._lock:
            if self._session_cache is None:
                self._session_cache = self.token.open(user_pin=self.pin)
            yield self._session_cache

    def _get_key(self, session, label: str):
        objs = session.get_objects(
            {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: label}
        )
        for obj in objs:
            return obj
        raise FileNotFoundError(label)

    # ------------------------------------------------------------------
    def list_keys(self) -> List[str]:
        with self._session() as session:
            keys = []
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
                label = obj.get(Attribute.LABEL)
                if isinstance(label, bytes):
                    label = label.decode()
                keys.append(label)
            return keys

    def test_connection(self) -> bool:
        try:
            with self._session():
                pass
            return True
        except Exception:
            return False

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        with self._session() as session:
            key = self._get_key(session, key_id)
            ktype = key.key_type
            if ktype == KeyType.RSA:
                mech = Mechanism.SHA256_RSA_PKCS
                return key.sign(data, mechanism=mech)
            elif ktype == KeyType.EC:
                mech = getattr(Mechanism, "ECDSA_SHA256", Mechanism.ECDSA)
                if mech == Mechanism.ECDSA:
                    digest = hashlib.sha256(data).digest()
                    return key.sign(digest, mechanism=Mechanism.ECDSA)
                return key.sign(data, mechanism=mech)
            elif getattr(KeyType, "EC_EDWARDS", None) and ktype == KeyType.EC_EDWARDS:
                mech = getattr(Mechanism, "EDDSA")
                return key.sign(data, mechanism=mech)
            raise ValueError("Unsupported key type")

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        with self._session() as session:
            key = self._get_key(session, key_id)
            if key.key_type != KeyType.RSA:
                raise ValueError("Key type not suitable for decryption")
            return key.decrypt(data, mechanism=Mechanism.RSA_PKCS)

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)

    # export/import are intentionally not implemented for HSM-backed keys
    def export_key(self, key_id: str):  # pragma: no cover - not supported
        raise NotImplementedError

    def import_key(self, raw: bytes, meta: dict):  # pragma: no cover - not supported
        raise NotImplementedError
