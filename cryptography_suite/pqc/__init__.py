"""Experimental post-quantum cryptography wrappers using pqcrypto.

This module provides simple interfaces for ML-KEM (formerly CRYSTALS-Kyber)
and ML-DSA/Dilithium using the ``pqcrypto`` Python bindings. These helpers are
for demos and interoperability experiments only; they are not production
audited. ML-KEM encryption returns sealed envelopes and never exposes KEM
shared secrets through the public API.
"""

from __future__ import annotations

import base64
import os
import struct
import warnings
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import DecryptionError, EncryptionError
from ..symmetric.kdf import derive_hkdf
from ..utils import KeyVault

try:  # pragma: no cover - optional dependency
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
    from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

    PQCRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - graceful fallback
    PQCRYPTO_AVAILABLE = False
    ml_kem_512 = ml_kem_768 = ml_kem_1024 = None
    ml_dsa_44 = ml_dsa_65 = ml_dsa_87 = None

try:  # pragma: no cover - optional dependency
    from pqcrypto.sign import (
        sphincs_sha256_128s_simple as _sphincs_module,
    )

    SPHINCS_AVAILABLE = True
except Exception:  # pragma: no cover - fallback
    try:  # pragma: no cover - check alternative naming
        from pqcrypto.sign import sphincs_sha2_128s_simple as _sphincs_module

        SPHINCS_AVAILABLE = True
    except Exception:  # pragma: no cover - final fallback
        try:
            from pqcrypto.sign import sphincs_shake_128s_simple as _sphincs_module

            SPHINCS_AVAILABLE = True
        except Exception:  # pragma: no cover - no sphincs available
            _sphincs_module = None
            SPHINCS_AVAILABLE = False


_KYBER_LEVEL_MAP = {512: ml_kem_512, 768: ml_kem_768, 1024: ml_kem_1024}
_DILITHIUM_LEVEL_MAP = {2: ml_dsa_44, 3: ml_dsa_65, 5: ml_dsa_87}
_ML_KEM_ENVELOPE_MAGIC = b"CSKEM1"
_ML_KEM_HEADER = struct.Struct(">HIII")
_ML_KEM_HEADER_SIZE = len(_ML_KEM_ENVELOPE_MAGIC) + _ML_KEM_HEADER.size
_ML_KEM_SALT_SIZE = 16
_ML_KEM_NONCE_SIZE = 12
_ML_KEM_TAG_SIZE = 16


def _get_ml_kem_algorithm(
    level: int, error_type: type[EncryptionError] | type[DecryptionError]
) -> Any:
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for ML-KEM functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise error_type("Invalid ML-KEM level")
    return alg


def _ml_kem_hkdf_info(level: int) -> bytes:
    return b"cryptography-suite ml-kem aes-gcm envelope v1 level=" + str(level).encode(
        "ascii"
    )


def _decode_ml_kem_envelope(envelope: bytes | str) -> bytes:
    if isinstance(envelope, str):
        try:
            return base64.b64decode(envelope, validate=True)
        except Exception as exc:
            raise DecryptionError("Invalid ML-KEM envelope") from exc
    if not isinstance(envelope, bytes):
        raise DecryptionError("Invalid ML-KEM envelope")
    if envelope.startswith(_ML_KEM_ENVELOPE_MAGIC):
        return envelope
    try:
        decoded = base64.b64decode(envelope, validate=True)
    except Exception as exc:
        raise DecryptionError("Invalid ML-KEM envelope") from exc
    if not decoded.startswith(_ML_KEM_ENVELOPE_MAGIC):
        raise DecryptionError("Invalid ML-KEM envelope")
    return decoded


def _parse_ml_kem_envelope(
    envelope: bytes | str, *, level: int
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    envelope_bytes = _decode_ml_kem_envelope(envelope)
    if len(envelope_bytes) < _ML_KEM_HEADER_SIZE:
        raise DecryptionError("Invalid ML-KEM envelope")
    if not envelope_bytes.startswith(_ML_KEM_ENVELOPE_MAGIC):
        raise DecryptionError("Invalid ML-KEM envelope")

    alg = _get_ml_kem_algorithm(level, DecryptionError)
    try:
        envelope_level, kem_ct_len, salt_len, nonce_len = _ML_KEM_HEADER.unpack_from(
            envelope_bytes, len(_ML_KEM_ENVELOPE_MAGIC)
        )
    except struct.error as exc:
        raise DecryptionError("Invalid ML-KEM envelope") from exc

    if envelope_level != level:
        raise DecryptionError("Invalid ML-KEM envelope")
    if kem_ct_len != alg.CIPHERTEXT_SIZE:
        raise DecryptionError("Invalid ML-KEM envelope")
    if salt_len != _ML_KEM_SALT_SIZE or nonce_len != _ML_KEM_NONCE_SIZE:
        raise DecryptionError("Invalid ML-KEM envelope")

    body_len = len(envelope_bytes) - _ML_KEM_HEADER_SIZE
    prefix_len = kem_ct_len + salt_len + nonce_len
    if prefix_len > body_len or body_len - prefix_len < _ML_KEM_TAG_SIZE:
        raise DecryptionError("Invalid ML-KEM envelope")

    offset = _ML_KEM_HEADER_SIZE
    kem_ciphertext = envelope_bytes[offset : offset + kem_ct_len]
    offset += kem_ct_len
    salt = envelope_bytes[offset : offset + salt_len]
    offset += salt_len
    nonce = envelope_bytes[offset : offset + nonce_len]
    offset += nonce_len
    aes_ciphertext = envelope_bytes[offset:]
    aad = envelope_bytes[:_ML_KEM_HEADER_SIZE]
    return aad, kem_ciphertext, salt, nonce, aes_ciphertext


def generate_ml_kem_keypair(
    level: int = 512, *, sensitive: bool = True
) -> tuple[bytes, KeyVault | bytes]:
    """Generate an experimental ML-KEM key pair for the given ``level``.

    Parameters
    ----------
    level : int
        ML-KEM security level (512, 768 or 1024).
    sensitive : bool, optional
        If ``True`` (default) the private key is wrapped in :class:`KeyVault`
        so it can be securely erased after use.
    """
    alg = _get_ml_kem_algorithm(level, EncryptionError)
    pk, sk = alg.generate_keypair()
    return pk, KeyVault(sk) if sensitive else sk


def generate_kyber_keypair(
    level: int = 512, *, sensitive: bool = True
) -> tuple[bytes, KeyVault | bytes]:
    """Deprecated compatibility wrapper for :func:`generate_ml_kem_keypair`."""
    warnings.warn(
        "generate_kyber_keypair is deprecated; use generate_ml_kem_keypair.",
        DeprecationWarning,
        stacklevel=2,
    )
    return generate_ml_kem_keypair(level=level, sensitive=sensitive)


def ml_kem_encrypt(
    public_key: bytes,
    plaintext: bytes,
    *,
    level: int = 512,
    raw_output: bool = False,
) -> str | bytes:
    """Encrypt ``plaintext`` as a sealed ML-KEM/AES-GCM envelope.

    The returned envelope contains the KEM ciphertext, salt, nonce, and
    AES-GCM ciphertext/tag needed for decryption. The KEM shared secret remains
    internal and is never returned by this API.

    Note: shared-secret cleanup is best-effort in Python because KEM backends
    return immutable ``bytes`` before this function can wrap them in
    :class:`KeyVault`.
    """
    alg = _get_ml_kem_algorithm(level, EncryptionError)

    try:
        kem_ciphertext, kem_secret = alg.encrypt(public_key)
    except Exception as exc:
        raise EncryptionError("ML-KEM encryption failed") from exc
    if len(kem_ciphertext) != alg.CIPHERTEXT_SIZE:
        raise EncryptionError("ML-KEM encryption failed")

    salt = os.urandom(_ML_KEM_SALT_SIZE)
    nonce = os.urandom(_ML_KEM_NONCE_SIZE)
    aad = _ML_KEM_ENVELOPE_MAGIC + _ML_KEM_HEADER.pack(
        level, len(kem_ciphertext), len(salt), len(nonce)
    )
    try:
        with KeyVault(kem_secret) as secret_buf:
            key = derive_hkdf(bytes(secret_buf), salt, _ml_kem_hkdf_info(level), 32)
        with KeyVault(key) as key_buf:
            aesgcm = AESGCM(bytes(key_buf))
            aes_ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    except Exception as exc:
        raise EncryptionError("ML-KEM envelope encryption failed") from exc

    envelope = aad + kem_ciphertext + salt + nonce + aes_ciphertext
    if raw_output:
        return envelope
    return base64.b64encode(envelope).decode()


def ml_kem_decrypt(
    private_key: bytes | KeyVault,
    envelope: bytes | str,
    *,
    level: int = 512,
) -> bytes:
    """Decrypt a sealed ML-KEM envelope.

    ``private_key`` may be raw bytes or a :class:`KeyVault` returned by
    :func:`generate_ml_kem_keypair`. Malformed envelopes, level mismatches,
    decapsulation failures, and AES-GCM authentication failures all raise
    :class:`DecryptionError` without exposing KEM shared secrets.

    Note: shared-secret cleanup is best-effort in Python because KEM backends
    return immutable ``bytes`` before this function can wrap them in
    :class:`KeyVault`.
    """
    alg = _get_ml_kem_algorithm(level, DecryptionError)
    aad, kem_ciphertext, salt, nonce, aes_ciphertext = _parse_ml_kem_envelope(
        envelope, level=level
    )
    priv = bytes(private_key) if isinstance(private_key, KeyVault) else private_key
    try:
        kem_secret = alg.decrypt(priv, kem_ciphertext)
    except Exception as exc:
        raise DecryptionError("Invalid ML-KEM envelope") from exc
    try:
        with KeyVault(kem_secret) as secret_buf:
            key = derive_hkdf(bytes(secret_buf), salt, _ml_kem_hkdf_info(level), 32)
        with KeyVault(key) as key_buf:
            aesgcm = AESGCM(bytes(key_buf))
            return aesgcm.decrypt(nonce, aes_ciphertext, aad)
    except Exception as exc:
        raise DecryptionError("Invalid ML-KEM envelope") from exc


def kyber_encrypt(
    public_key: bytes,
    plaintext: bytes,
    *,
    level: int = 512,
    raw_output: bool = False,
) -> str | bytes:
    """Deprecated compatibility wrapper for :func:`ml_kem_encrypt`.

    Breaking change: this wrapper now returns only the sealed envelope. It does
    not return a KEM shared secret.
    """
    warnings.warn(
        "kyber_encrypt is deprecated; use ml_kem_encrypt. It now returns only "
        "a sealed ML-KEM envelope and never returns the KEM shared secret.",
        DeprecationWarning,
        stacklevel=2,
    )
    return ml_kem_encrypt(public_key, plaintext, level=level, raw_output=raw_output)


def kyber_decrypt(
    private_key: bytes | KeyVault,
    ciphertext: bytes | str,
    shared_secret: bytes | str | None = None,
    *,
    level: int = 512,
) -> bytes:
    """Deprecated compatibility wrapper for :func:`ml_kem_decrypt`.

    ``shared_secret`` is ignored when provided. New-format envelopes contain
    the KEM ciphertext needed for decapsulation and do not require callers to
    handle shared secrets.
    """
    warnings.warn(
        "kyber_decrypt is deprecated; use ml_kem_decrypt with a sealed "
        "ML-KEM envelope.",
        DeprecationWarning,
        stacklevel=2,
    )
    if shared_secret is not None:
        warnings.warn(
            "kyber_decrypt(shared_secret=...) is deprecated and ignored; "
            "safe ML-KEM envelopes do not require caller-provided shared secrets.",
            DeprecationWarning,
            stacklevel=2,
        )
    return ml_kem_decrypt(private_key, ciphertext, level=level)


def generate_dilithium_keypair(
    *, sensitive: bool = True
) -> tuple[bytes, KeyVault | bytes]:
    """Generate a Dilithium key pair using level 2 parameters.

    When ``sensitive`` is ``True`` (default) the private key is wrapped in
    :class:`KeyVault`.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    pk, sk = ml_dsa_44.generate_keypair()
    return pk, KeyVault(sk) if sensitive else sk


def dilithium_sign(
    private_key: bytes | KeyVault,
    message: bytes,
    *,
    raw_output: bool = False,
) -> str | bytes:
    """Sign a message using Dilithium level 2.

    ``private_key`` may be provided as raw bytes or a :class:`KeyVault`.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    key = bytes(private_key) if isinstance(private_key, KeyVault) else private_key
    sig = ml_dsa_44.sign(key, message)
    if raw_output:
        return sig
    return base64.b64encode(sig).decode()


def dilithium_verify(
    public_key: bytes,
    message: bytes,
    signature: bytes | str,
) -> bool:
    """Verify a Dilithium signature using level 2."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception:
            return False
    try:
        ml_dsa_44.verify(public_key, message, signature)
        return True
    except Exception:
        return False


def generate_sphincs_keypair(
    *, sensitive: bool = True
) -> tuple[bytes, KeyVault | bytes]:
    """Generate a SPHINCS+ key pair using a 128-bit security level.

    When ``sensitive`` is ``True`` (default) the private key is wrapped in
    :class:`KeyVault`.
    """
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    pk, sk = _sphincs_module.generate_keypair()
    return pk, KeyVault(sk) if sensitive else sk


def sphincs_sign(
    private_key: bytes | KeyVault, message: bytes, *, raw_output: bool = False
) -> str | bytes:
    """Sign ``message`` with SPHINCS+ returning Base64 by default.

    ``private_key`` may be a byte string or :class:`KeyVault`.
    """
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    key = bytes(private_key) if isinstance(private_key, KeyVault) else private_key
    sig = _sphincs_module.sign(key, message)
    if raw_output:
        return sig
    return base64.b64encode(sig).decode()


def sphincs_verify(public_key: bytes, message: bytes, signature: bytes | str) -> bool:
    """Verify a SPHINCS+ signature."""
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception:
            return False
    try:
        return bool(_sphincs_module.verify(public_key, message, signature))
    except Exception:
        return False


__all__ = [
    "PQCRYPTO_AVAILABLE",
    "SPHINCS_AVAILABLE",
    "generate_ml_kem_keypair",
    "generate_kyber_keypair",
    "ml_kem_encrypt",
    "ml_kem_decrypt",
    "kyber_encrypt",
    "kyber_decrypt",
    "generate_dilithium_keypair",
    "dilithium_sign",
    "dilithium_verify",
    "generate_sphincs_keypair",
    "sphincs_sign",
    "sphincs_verify",
]
