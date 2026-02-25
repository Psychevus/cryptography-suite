"""Stable entry-point wrappers for AEAD plugins."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12


def _derive_iv(key: bytes, nonce: bytes, associated_data: bytes | None) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=NONCE_SIZE,
        salt=nonce,
        info=associated_data or b"",
    )
    return hkdf.derive(key)


def aes_gcm_sst_encrypt(
    key: bytes,
    nonce: bytes,
    data: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    iv = _derive_iv(key, nonce, associated_data)
    return AESGCM(key).encrypt(iv, data, associated_data)


def aes_gcm_sst_decrypt(
    key: bytes,
    nonce: bytes,
    data: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    iv = _derive_iv(key, nonce, associated_data)
    return AESGCM(key).decrypt(iv, data, associated_data)
