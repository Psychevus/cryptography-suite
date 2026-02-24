from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from ..audit import audit_log
from ..core.logging import get_structured_logger
from ..core.operations import RetryPolicy, retry_with_backoff
from . import register_keystore
from .base import KeyStoreCapability

if TYPE_CHECKING:  # pragma: no cover - used only for typing
    import boto3  # noqa: F401


@register_keystore("aws-kms")
class AWSKMSKeyStore:
    """AWS KMS backed keystore.

    Requires ``boto3`` and valid AWS credentials.

    Important: AWS KMS does not support exporting private key material and does
    not provide a simple API for importing arbitrary private key bytes.
    """

    name = "aws-kms"
    status = "limited"
    capabilities = frozenset(
        {
            KeyStoreCapability.SIGN,
            KeyStoreCapability.DECRYPT,
            KeyStoreCapability.UNWRAP,
        }
    )

    _SIGNING_PREFERENCES: dict[str, list[str]] = {
        "RSA_2048": ["RSASSA_PSS_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256"],
        "RSA_3072": [
            "RSASSA_PSS_SHA_384",
            "RSASSA_PSS_SHA_256",
            "RSASSA_PKCS1_V1_5_SHA_384",
        ],
        "RSA_4096": [
            "RSASSA_PSS_SHA_512",
            "RSASSA_PSS_SHA_384",
            "RSASSA_PSS_SHA_256",
            "RSASSA_PKCS1_V1_5_SHA_512",
        ],
        "ECC_NIST_P256": ["ECDSA_SHA_256"],
        "ECC_SECG_P256K1": ["ECDSA_SHA_256"],
        "ECC_NIST_P384": ["ECDSA_SHA_384"],
        "ECC_NIST_P521": ["ECDSA_SHA_512"],
        "ED25519": ["EDDSA"],
    }

    def __init__(self, region_name: str | None = None):
        try:
            boto3_mod = import_module("boto3")
        except Exception as exc:
            raise RuntimeError("boto3 is required for AWSKMSKeyStore") from exc
        self.client = boto3_mod.client("kms", region_name=region_name)
        self._logger_name = "cryptography_suite.keystores.aws_kms"
        self._retry = RetryPolicy(
            max_attempts=4, base_delay_s=0.25, max_delay_s=2.0, jitter_s=0.2
        )
        self._algorithm_cache: dict[str, str] = {}
        get_structured_logger(self._logger_name)

    def list_keys(self) -> list[str]:
        keys: list[str] = []
        paginator = retry_with_backoff(
            lambda: self.client.get_paginator("list_keys"),
            policy=self._retry,
            logger_name=self._logger_name,
            operation_name="aws_kms_get_paginator",
        )
        for page in paginator.paginate():
            keys.extend(k["KeyId"] for k in page.get("Keys", []))
        return keys

    def test_connection(self) -> bool:
        try:
            self.client.list_keys(Limit=1)
            return True
        except Exception:
            return False

    def _select_signing_algorithm(self, key_id: str) -> str:
        if key_id in self._algorithm_cache:
            return self._algorithm_cache[key_id]

        metadata = retry_with_backoff(
            lambda: self.client.get_public_key(KeyId=key_id),
            policy=self._retry,
            logger_name=self._logger_name,
            operation_name="aws_kms_get_public_key",
        )

        key_spec = metadata.get("KeySpec")
        supported = metadata.get("SigningAlgorithms", [])

        if not key_spec:
            described = retry_with_backoff(
                lambda: self.client.describe_key(KeyId=key_id),
                policy=self._retry,
                logger_name=self._logger_name,
                operation_name="aws_kms_describe_key",
            )
            key_spec = described.get("KeyMetadata", {}).get("KeySpec")

        preferences = self._SIGNING_PREFERENCES.get(str(key_spec), [])
        for candidate in preferences:
            if candidate in supported:
                self._algorithm_cache[key_id] = candidate
                return candidate

        if supported:
            selected = str(supported[0])
            self._algorithm_cache[key_id] = selected
            return selected

        raise ValueError(
            f"No supported KMS signing algorithm found for key '{key_id}' "
            f"(KeySpec={key_spec!r})"
        )

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        algorithm = self._select_signing_algorithm(key_id)
        resp = retry_with_backoff(
            lambda: self.client.sign(
                KeyId=key_id,
                Message=data,
                MessageType="RAW",
                SigningAlgorithm=algorithm,
            ),
            policy=self._retry,
            logger_name=self._logger_name,
            operation_name="aws_kms_sign",
        )
        return resp["Signature"]

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        resp = retry_with_backoff(
            lambda: self.client.decrypt(KeyId=key_id, CiphertextBlob=data),
            policy=self._retry,
            logger_name=self._logger_name,
            operation_name="aws_kms_decrypt",
        )
        return resp["Plaintext"]

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)

    @audit_log
    def export_key(self, key_id: str):  # pragma: no cover - not supported
        raise NotImplementedError("AWS KMS does not support private key export")

    @audit_log
    def import_key(self, raw: bytes, meta: dict) -> str:
        raise NotImplementedError(
            "AWS KMS raw private key import is not supported by this backend. "
            "Use AWS KMS-native key creation, or implement the full ImportKeyMaterial "
            "workflow for symmetric key material only."
        )
