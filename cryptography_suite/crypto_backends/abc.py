"""Abstract base classes for cryptographic primitives."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AEAD(ABC):
    """Authenticated encryption with associated data interface."""

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt ``plaintext`` using AEAD."""

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt ciphertext encrypted with AEAD."""


class KDF(ABC):
    """Key derivation function interface."""

    @abstractmethod
    def derive(self, password: str, salt: bytes, *, length: int) -> bytes:
        """Derive a key from ``password`` and ``salt``."""
