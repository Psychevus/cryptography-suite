class CryptographySuiteError(Exception):
    """Base exception for the cryptography suite."""


class EncryptionError(CryptographySuiteError):
    """Raised when encryption fails or invalid parameters are provided."""


class DecryptionError(CryptographySuiteError):
    """Raised when decryption fails or invalid data is provided."""


class KeyDerivationError(CryptographySuiteError):
    """Raised when a key derivation operation fails."""


class SignatureVerificationError(CryptographySuiteError):
    """Raised when signature verification fails."""


class MissingDependencyError(CryptographySuiteError):
    """Raised when an optional dependency is missing."""


class ProtocolError(CryptographySuiteError):
    """Raised when a protocol implementation encounters an error."""
