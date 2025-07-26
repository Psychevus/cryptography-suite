"""PyCA based backend implementation."""

from __future__ import annotations

from typing import Any

from .abc import AEAD, KDF
from . import register_backend
from ..aead import chacha20_encrypt_aead, chacha20_decrypt_aead
from ..symmetric import derive_key_pbkdf2


@register_backend("pyca")
class PyCABackend:
    """Backend powered by the ``cryptography`` package."""

    class AEADImpl(AEAD):
        def encrypt(
            self,
            plaintext: bytes,
            key: bytes,
            nonce: bytes,
            *,
            associated_data: bytes | None = None,
        ) -> bytes:
            return chacha20_encrypt_aead(
                plaintext, key, nonce, associated_data=associated_data
            )

        def decrypt(
            self,
            ciphertext: bytes,
            key: bytes,
            nonce: bytes,
            *,
            associated_data: bytes | None = None,
        ) -> bytes:
            return chacha20_decrypt_aead(
                ciphertext, key, nonce, associated_data=associated_data
            )

    class KDFImpl(KDF):
        def derive(self, password: str, salt: bytes, *, length: int) -> bytes:
            return derive_key_pbkdf2(password, salt, key_size=length)

    def __init__(self) -> None:
        self.aead: AEAD = PyCABackend.AEADImpl()
        self.kdf: KDF = PyCABackend.KDFImpl()

