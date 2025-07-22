from __future__ import annotations

import os
from datetime import datetime
from typing import Callable, Protocol

from cryptography.fernet import Fernet


class AuditLogger(Protocol):
    """Protocol for audit loggers."""

    def log(self, operation: str, status: str) -> None:
        ...


class InMemoryAuditLogger:
    """Store audit logs in memory."""

    def __init__(self) -> None:
        self.logs: list[dict[str, str]] = []

    def log(self, operation: str, status: str) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "status": status,
        }
        self.logs.append(entry)


class EncryptedFileAuditLogger:
    """Write audit logs to an encrypted file using Fernet."""

    def __init__(self, file_path: str, key: bytes) -> None:
        self.file_path = file_path
        self.fernet = Fernet(key)

    def log(self, operation: str, status: str) -> None:
        entry = f"{datetime.utcnow().isoformat()}|{operation}|{status}"
        data = self.fernet.encrypt(entry.encode())
        with open(self.file_path, "ab") as f:
            f.write(data + b"\n")


_AUDIT_LOGGER: AuditLogger | None = None


def set_audit_logger(
    logger: AuditLogger | None = None,
    *,
    log_file: str | None = None,
    key: bytes | None = None,
) -> None:
    """Configure the audit logger.

    Passing ``logger`` sets a custom logger instance. Alternatively ``log_file``
    and ``key`` can be provided to enable encrypted file logging. Passing
    ``None`` disables auditing.
    """
    global _AUDIT_LOGGER

    if logger is not None:
        _AUDIT_LOGGER = logger
    elif log_file is not None:
        if key is None:
            raise ValueError("Key required for encrypted file logging")
        _AUDIT_LOGGER = EncryptedFileAuditLogger(log_file, key)
    else:
        _AUDIT_LOGGER = None


def _get_audit_logger() -> AuditLogger | None:
    if _AUDIT_LOGGER is not None:
        return _AUDIT_LOGGER
    if os.getenv("AUDIT_MODE"):
        _set_default_logger()
        return _AUDIT_LOGGER
    return None


def _set_default_logger() -> None:
    global _AUDIT_LOGGER
    if _AUDIT_LOGGER is not None:
        return
    file_path = os.getenv("AUDIT_LOG_FILE")
    if file_path:
        key = os.getenv("AUDIT_LOG_KEY")
        if not key:
            raise ValueError("AUDIT_LOG_KEY must be set when using AUDIT_LOG_FILE")
        _AUDIT_LOGGER = EncryptedFileAuditLogger(file_path, key.encode())
    else:
        _AUDIT_LOGGER = InMemoryAuditLogger()


def audit_log(func: Callable) -> Callable:
    """Decorator to log cryptographic operations."""

    def wrapper(*args, **kwargs):
        logger = _get_audit_logger()
        try:
            result = func(*args, **kwargs)
            if logger is not None:
                logger.log(func.__name__, "success")
            return result
        except Exception:
            if logger is not None:
                logger.log(func.__name__, "failure")
            raise

    return wrapper
