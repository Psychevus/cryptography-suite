from __future__ import annotations

"""Preview implementation of AES-GCM-SST.

The algorithm follows the Nov 2024 draft of NIST SP 800-38D section 6.3.
It derives a synthetic IV using HKDF-SHA-512 before invoking the standard
AES-GCM primitive provided by ``cryptography``.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12  # 96-bit selector per draft


def _derive_iv(key: bytes, nonce: bytes, associated_data: bytes | None) -> bytes:
    """Derive the synthetic IV using HKDF-SHA-512."""
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
    """Encrypt ``data`` using AES-GCM-SST.

    The API mirrors :class:`AESGCM.encrypt` but mixes in the synthetic
    IV derivation step defined in the draft specification. ``nonce``
    acts as the public selector and must be 96 bits.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    iv = _derive_iv(key, nonce, associated_data)
    cipher = AESGCM(key)
    return cipher.encrypt(iv, data, associated_data)


def aes_gcm_sst_decrypt(
    key: bytes,
    nonce: bytes,
    data: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data encrypted with :func:`aes_gcm_sst_encrypt`."""
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    iv = _derive_iv(key, nonce, associated_data)
    cipher = AESGCM(key)
    return cipher.decrypt(iv, data, associated_data)
