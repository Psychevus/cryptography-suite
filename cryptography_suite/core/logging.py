"""Structured logging helpers with correlation-id propagation."""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

_CORRELATION_ID: ContextVar[str] = ContextVar("cryptosuite_correlation_id", default="")


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


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    payload = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    logger.info("%s %s", message, payload)
