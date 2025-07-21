"""Post-quantum cryptography wrappers using pqcrypto.

This module provides simple interfaces for the NIST CRYSTALS-Kyber
(KEM) and CRYSTALS-Dilithium (signature) algorithms using the
``pqcrypto`` Python bindings. The functions rely on constant-time
implementations from PQClean.
"""

from __future__ import annotations

from typing import Tuple

from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87


_KYBER_LEVEL_MAP = {512: ml_kem_512, 768: ml_kem_768, 1024: ml_kem_1024}
_DILITHIUM_LEVEL_MAP = {2: ml_dsa_44, 3: ml_dsa_65, 5: ml_dsa_87}


def generate_kyber_keypair(level: int = 512) -> Tuple[bytes, bytes]:
    """Generate an ML-KEM key pair.

    Parameters
    ----------
    level:
        Security level. One of ``512``, ``768``, or ``1024``.

    Returns
    -------
    Tuple[bytes, bytes]
        ``(public_key, secret_key)``.
    """
    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Kyber level")
    return alg.generate_keypair()


def kyber_encapsulate(public_key: bytes, level: int = 512) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using ML-KEM.

    Parameters
    ----------
    public_key:
        Public key bytes.
    level:
        Security level matching the key.

    Returns
    -------
    Tuple[bytes, bytes]
        ``(ciphertext, shared_secret)``.
    """
    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Kyber level")
    return alg.encrypt(public_key)


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, level: int = 512) -> bytes:
    """Decapsulate a shared secret using ML-KEM.

    Parameters
    ----------
    ciphertext:
        Ciphertext produced by :func:`kyber_encapsulate`.
    secret_key:
        Secret key bytes.
    level:
        Security level matching the key.

    Returns
    -------
    bytes
        The shared secret.
    """
    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Kyber level")
    return alg.decrypt(secret_key, ciphertext)


def generate_dilithium_keypair(level: int = 2) -> Tuple[bytes, bytes]:
    """Generate a Dilithium key pair.

    Parameters
    ----------
    level:
        Security level ``2``, ``3``, or ``5``.

    Returns
    -------
    Tuple[bytes, bytes]
        ``(public_key, secret_key)``.
    """
    alg = _DILITHIUM_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Dilithium level")
    return alg.generate_keypair()


def dilithium_sign(message: bytes, secret_key: bytes, level: int = 2) -> bytes:
    """Sign a message using Dilithium.

    Parameters
    ----------
    message:
        Message to sign.
    secret_key:
        Dilithium secret key.
    level:
        Security level matching the key.

    Returns
    -------
    bytes
        Signature bytes.
    """
    alg = _DILITHIUM_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Dilithium level")
    return alg.sign(secret_key, message)


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes, level: int = 2) -> bool:
    """Verify a Dilithium signature.

    Parameters
    ----------
    message:
        Original message.
    signature:
        Signature to verify.
    public_key:
        Dilithium public key.
    level:
        Security level matching the key.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    alg = _DILITHIUM_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Dilithium level")
    try:
        alg.verify(public_key, message, signature)
        return True
    except Exception:
        return False

