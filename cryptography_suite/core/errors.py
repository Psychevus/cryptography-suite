"""Domain-level typed errors and error codes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class ErrorCode(str, Enum):
    """Stable machine-readable error codes."""

    ENCRYPTION_FAILED = "ENCRYPTION_FAILED"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"
    KEY_DERIVATION_FAILED = "KEY_DERIVATION_FAILED"
    SIGNATURE_VERIFICATION_FAILED = "SIGNATURE_VERIFICATION_FAILED"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    STRICT_KEY_POLICY = "STRICT_KEY_POLICY"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"


@dataclass(slots=True)
class SuiteError(Exception):
    """Base typed exception for operationally-safe error handling."""

    message: str
    code: ErrorCode
    details: Mapping[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"
