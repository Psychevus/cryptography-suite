from __future__ import annotations

from typing import TYPE_CHECKING, List
from importlib import import_module

from . import register_keystore
from ..audit import audit_log
from ..errors import UnsupportedAlgorithm

if TYPE_CHECKING:  # pragma: no cover - used only for typing
    import boto3  # type: ignore[import]  # noqa: F401


@register_keystore("aws-kms")
class AWSKMSKeyStore:
    """AWS KMS backed keystore.

    Requires ``boto3`` and valid AWS credentials.  Only a subset of KMS
    features are exposed for demonstration purposes.
    """

    name = "aws-kms"
    status = "production"

    def __init__(self, region_name: str | None = None):
        try:
            boto3_mod = import_module("boto3")  # type: ignore[import]
        except Exception as exc:
            raise RuntimeError("boto3 is required for AWSKMSKeyStore") from exc
        self.client = boto3_mod.client("kms", region_name=region_name)

    def list_keys(self) -> List[str]:
        keys: List[str] = []
        paginator = self.client.get_paginator("list_keys")
        for page in paginator.paginate():
            keys.extend(k["KeyId"] for k in page.get("Keys", []))
        return keys

    def test_connection(self) -> bool:
        try:
            self.client.list_keys(Limit=1)
            return True
        except Exception:
            return False

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        resp = self.client.sign(
            KeyId=key_id,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PSS_SHA256",
        )
        return resp["Signature"]

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        resp = self.client.decrypt(KeyId=key_id, CiphertextBlob=data)
        return resp["Plaintext"]

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)

    @audit_log
    def export_key(self, key_id: str):  # pragma: no cover - not supported
        raise NotImplementedError("AWS KMS does not support key export")

    @audit_log
    def import_key(self, raw: bytes, meta: dict) -> str:
        algo = meta.get("type")
        if algo not in {"rsa", "ecdsa", "ed25519"}:
            raise UnsupportedAlgorithm(algo)
        try:
            self.client.import_key(KeyId=meta.get("id"), KeyMaterial=raw)
        except Exception as exc:  # pragma: no cover - passthrough
            raise RuntimeError("KMS import failed") from exc
        return meta.get("id", "")
