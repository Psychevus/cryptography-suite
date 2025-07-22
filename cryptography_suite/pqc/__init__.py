"""Post-quantum cryptography wrappers using pqcrypto.

This module provides simple interfaces for the NIST CRYSTALS-Kyber
(KEM) and CRYSTALS-Dilithium (signature) algorithms using the
``pqcrypto`` Python bindings. The functions rely on constant-time
implementations from PQClean.
"""

from __future__ import annotations

from typing import Tuple
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:  # pragma: no cover - optional dependency
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
    from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

    PQCRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - graceful fallback
    PQCRYPTO_AVAILABLE = False
    ml_kem_512 = ml_kem_768 = ml_kem_1024 = None
    ml_dsa_44 = ml_dsa_65 = ml_dsa_87 = None


_KYBER_LEVEL_MAP = {512: ml_kem_512, 768: ml_kem_768, 1024: ml_kem_1024}
_DILITHIUM_LEVEL_MAP = {2: ml_dsa_44, 3: ml_dsa_65, 5: ml_dsa_87}


def generate_kyber_keypair() -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair using ML-KEM-512."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    return ml_kem_512.generate_keypair()


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
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

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
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise ValueError("Invalid Kyber level")
    return alg.decrypt(secret_key, ciphertext)


def kyber_encrypt(public_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt ``plaintext`` using Kyber and AES-GCM.

    The function first encapsulates a shared secret with ML-KEM-512 and then
    derives an AES key from that secret to encrypt the plaintext. The returned
    tuple contains the Kyber ciphertext followed by the AES-GCM output and the
    shared secret used for encryption.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    kem_ct, ss = ml_kem_512.encrypt(public_key)
    key = hashlib.sha256(ss).digest()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    enc = nonce + aesgcm.encrypt(nonce, plaintext, None)
    return kem_ct + enc, ss


def kyber_decrypt(private_key: bytes, ciphertext: bytes, shared_secret: bytes) -> bytes:
    """Decrypt data encrypted by :func:`kyber_encrypt`."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    ct_size = ml_kem_512.CIPHERTEXT_SIZE
    if len(ciphertext) < ct_size + 12 + 16:
        raise ValueError("Invalid ciphertext")

    kem_ct = ciphertext[:ct_size]
    enc = ciphertext[ct_size:]
    ss_check = ml_kem_512.decrypt(private_key, kem_ct)
    if ss_check != shared_secret:
        raise ValueError("Shared secret mismatch")

    key = hashlib.sha256(shared_secret).digest()
    aesgcm = AESGCM(key)
    nonce = enc[:12]
    ct = enc[12:]
    return aesgcm.decrypt(nonce, ct, None)


def generate_dilithium_keypair() -> Tuple[bytes, bytes]:
    """Generate a Dilithium key pair using level 2 parameters."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    return ml_dsa_44.generate_keypair()


def dilithium_sign(private_key: bytes, message: bytes) -> bytes:
    """Sign a message using Dilithium level 2."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    return ml_dsa_44.sign(private_key, message)


def dilithium_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a Dilithium signature using level 2."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    try:
        ml_dsa_44.verify(public_key, message, signature)
        return True
    except Exception:
        return False
