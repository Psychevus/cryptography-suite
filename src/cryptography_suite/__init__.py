"""Stable v4 package facade.

Phase 3 establishes declarations and value models only. Operational
cryptography is intentionally unavailable.
"""

from .context import EncryptionContext
from .envelope import Envelope, EnvelopeMetadata
from .errors import (
    AuthenticationError,
    ContextMismatchError,
    CryptographySuiteError,
    EnvelopeError,
    ErrorCode,
    MigrationError,
    PolicyError,
    ProviderError,
)
from .policy import Policy
from .protector import Protector
from .providers import KeyProvider, KeyRef

__version__ = "3.0.0"

__all__ = [
    "AuthenticationError",
    "ContextMismatchError",
    "CryptographySuiteError",
    "EncryptionContext",
    "Envelope",
    "EnvelopeError",
    "EnvelopeMetadata",
    "ErrorCode",
    "KeyProvider",
    "KeyRef",
    "MigrationError",
    "Policy",
    "PolicyError",
    "Protector",
    "ProviderError",
]
