from __future__ import annotations

from collections.abc import Callable
from typing import ParamSpec, Protocol, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


class AuditLogger(Protocol):
    def log(self, operation: str, status: str) -> None: ...


class InMemoryAuditLogger:
    logs: list[dict[str, str]]
    def __init__(self) -> None: ...
    def log(self, operation: str, status: str) -> None: ...


class EncryptedFileAuditLogger:
    file_path: str
    def __init__(self, file_path: str, key: bytes) -> None: ...
    def log(self, operation: str, status: str) -> None: ...


def set_audit_logger(
    logger: AuditLogger | None = None,
    *,
    log_file: str | None = None,
    key: bytes | None = None,
) -> None: ...


def audit_log(func: Callable[P, R]) -> Callable[P, R]: ...
