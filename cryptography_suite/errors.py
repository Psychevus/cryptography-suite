"""Public exception hierarchy for cryptography-suite."""

from __future__ import annotations

from .core.errors import ErrorCode, SuiteError


class CryptographySuiteError(SuiteError):
    """Base exception for the cryptography suite."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.PROTOCOL_ERROR,
        details: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, details=details or {})


class EncryptionError(CryptographySuiteError):
    """Raised when encryption fails or invalid parameters are provided."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.ENCRYPTION_FAILED, details=details)


class DecryptionError(CryptographySuiteError):
    """Raised when decryption fails or invalid data is provided."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.DECRYPTION_FAILED, details=details)


class KeyDerivationError(CryptographySuiteError):
    """Raised when a key derivation operation fails."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.KEY_DERIVATION_FAILED, details=details)


class SignatureVerificationError(CryptographySuiteError):
    """Raised when signature verification fails."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(
            message, code=ErrorCode.SIGNATURE_VERIFICATION_FAILED, details=details
        )


class MissingDependencyError(CryptographySuiteError):
    """Raised when an optional dependency is missing."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.MISSING_DEPENDENCY, details=details)


class ProtocolError(CryptographySuiteError):
    """Raised when a protocol implementation encounters an error."""


class UnsupportedAlgorithm(CryptographySuiteError):
    """Raised when attempting to use an unsupported algorithm."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.UNSUPPORTED_ALGORITHM, details=details)


class SecurityError(CryptographySuiteError):
    """Raised when a security policy is violated."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(
            message, code=ErrorCode.SECURITY_POLICY_VIOLATION, details=details
        )


class StrictKeyPolicyError(CryptographySuiteError):
    """Raised when strict key policy prohibits unencrypted PEM usage."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code=ErrorCode.STRICT_KEY_POLICY, details=details)
