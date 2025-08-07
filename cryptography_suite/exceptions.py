"""Custom exceptions for cryptographic misuse detection."""
from __future__ import annotations

__all__ = ["NonceReuseError", "KeyRotationRequired"]


class NonceReuseError(RuntimeError):
    """Raised when a nonce is reused."""


class KeyRotationRequired(RuntimeError):
    """Raised when cryptographic keys must be rotated.

    Used when either the byte limit or message cap for an AEAD key has
    been reached.
    """
