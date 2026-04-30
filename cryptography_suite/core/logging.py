"""Structured logging helpers with correlation-id propagation."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

from ..debug import REDACTED_VALUE, redact_message

_CORRELATION_ID: ContextVar[str] = ContextVar("cryptosuite_correlation_id", default="")
SENSITIVE_FIELD_NAMES = (
    "argv",
    "ciphertext",
    "key",
    "nonce",
    "passphrase",
    "password",
    "pem",
    "plaintext",
    "private",
    "seed",
    "secret",
    "shared",
    "signature",
    "stderr",
    "stdout",
    "token",
)


class CorrelationIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        correlation_id = _CORRELATION_ID.get()
        if not correlation_id:
            correlation_id = str(uuid4())
            _CORRELATION_ID.set(correlation_id)
        record.correlation_id = correlation_id
        return True


def set_correlation_id(correlation_id: str) -> None:
    _CORRELATION_ID.set(correlation_id)


def get_correlation_id() -> str:
    return _CORRELATION_ID.get()


def configure_structured_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger("cryptography_suite")
    if root.handlers:
        root.setLevel(level)
        return

    handler = logging.StreamHandler()
    handler.addFilter(CorrelationIdFilter())
    handler.setFormatter(
        logging.Formatter(
            fmt=(
                "%(asctime)s %(levelname)s %(name)s correlation_id=%(correlation_id)s "
                "%(message)s"
            )
        )
    )
    root.addHandler(handler)
    root.setLevel(level)


def get_structured_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    parent = logging.getLogger("cryptography_suite")
    if parent.handlers:
        for handler in parent.handlers:
            if handler not in logger.handlers:
                logger.addHandler(handler)
    logger.setLevel(parent.level or logging.INFO)
    logger.propagate = True
    return logger


def _is_sensitive_field(key: str) -> bool:
    key_lower = key.lower()
    return any(part in key_lower for part in SENSITIVE_FIELD_NAMES)


def _redact_for_logging(value: Any, key_name: str | None = None) -> Any:
    if key_name is not None and _is_sensitive_field(key_name):
        if isinstance(value, (bytes, bytearray, memoryview)):
            return f"<{len(value)} bytes redacted>"
        if key_name.lower() == "argv":
            return [REDACTED_VALUE]
        return REDACTED_VALUE
    if isinstance(value, str):
        return redact_message(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{len(value)} bytes>"
    if isinstance(value, Mapping):
        return {
            k: _redact_for_logging(v, k if isinstance(k, str) else None)
            for k, v in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_redact_for_logging(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_for_logging(item) for item in value]
    return value


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    payload = " ".join(
        f"{key}={_redact_for_logging(value, key)!r}"
        for key, value in sorted(fields.items())
    )
    logger.info("%s %s", message, payload)
