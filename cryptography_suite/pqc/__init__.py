"""Post-quantum cryptography wrappers using pqcrypto.

This module provides simple interfaces for the NIST CRYSTALS-Kyber
(KEM) and CRYSTALS-Dilithium (signature) algorithms using the
``pqcrypto`` Python bindings. The functions rely on constant-time
implementations from PQClean.
"""

from __future__ import annotations

from typing import Tuple
from ..errors import EncryptionError, DecryptionError
from ..symmetric.kdf import derive_hkdf
from ..utils import KeyVault
import os
import hmac
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def generate_kyber_keypair(level: int = 512) -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair for the given ``level``."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise EncryptionError("Invalid Kyber level")
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
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise EncryptionError("Invalid Kyber level")
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
        raise DecryptionError("Invalid Kyber level")
    return alg.decrypt(secret_key, ciphertext)


def kyber_encrypt(
    public_key: bytes,
    plaintext: bytes,
    *,
    level: int = 512,
    raw_output: bool = False,
) -> Tuple[str | bytes, str | bytes]:
    """Encrypt ``plaintext`` using Kyber and AES-GCM.

    ``level`` selects the ML-KEM security level (512, 768 or 1024).
    The function encapsulates a shared secret with the chosen level and then
    derives an AES key from that secret to encrypt the plaintext. The returned
    tuple contains the Kyber ciphertext followed by the AES-GCM output and the
    shared secret used for encryption.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise EncryptionError("Invalid Kyber level")

    kem_ct, ss = alg.encrypt(public_key)
    salt = os.urandom(16)
    key = derive_hkdf(ss, salt, b"kyber-aes-key", 32)
    with KeyVault(key) as key_buf:
        aesgcm = AESGCM(bytes(key_buf))
        nonce = os.urandom(12)
        enc = nonce + aesgcm.encrypt(nonce, plaintext, None)
    ct = kem_ct + salt + enc
    if raw_output:
        return ct, ss
    return base64.b64encode(ct).decode(), base64.b64encode(ss).decode()


def kyber_decrypt(
    private_key: bytes,
    ciphertext: bytes | str,
    shared_secret: bytes | str | None = None,
    *,
    level: int = 512,
) -> bytes:
    """Decrypt data encrypted by :func:`kyber_encrypt`.

    ``shared_secret`` becomes optional. When omitted the function decapsulates
    it from ``ciphertext`` using the provided Kyber ``level``.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise DecryptionError("Invalid Kyber level")

    ct_size = alg.CIPHERTEXT_SIZE
    if isinstance(ciphertext, str):
        try:
            ciphertext = base64.b64decode(ciphertext)
        except Exception as exc:  # pragma: no cover - defensive
            raise DecryptionError(f"Invalid ciphertext: {exc}") from exc

    if isinstance(shared_secret, str):
        try:
            shared_secret = base64.b64decode(shared_secret)
        except Exception as exc:  # pragma: no cover - defensive
            raise DecryptionError(f"Invalid shared secret: {exc}") from exc

    if len(ciphertext) < ct_size + 12 + 16:
        raise DecryptionError("Invalid ciphertext")

    kem_ct = ciphertext[:ct_size]
    salt = ciphertext[ct_size:ct_size + 16]
    enc = ciphertext[ct_size + 16:]
    ss_check = alg.decrypt(private_key, kem_ct)
    if shared_secret is None:
        shared_secret = ss_check
    elif not hmac.compare_digest(ss_check, shared_secret):
        raise DecryptionError("Shared secret mismatch")

    key = derive_hkdf(shared_secret, salt, b"kyber-aes-key", 32)
    with KeyVault(key) as key_buf:
        aesgcm = AESGCM(bytes(key_buf))
        nonce = enc[:12]
        ct = enc[12:]
        return aesgcm.decrypt(nonce, ct, None)


def generate_dilithium_keypair() -> Tuple[bytes, bytes]:
    """Generate a Dilithium key pair using level 2 parameters."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    return ml_dsa_44.generate_keypair()


def dilithium_sign(
    private_key: bytes,
    message: bytes,
    *,
    raw_output: bool = False,
) -> str | bytes:
    """Sign a message using Dilithium level 2."""
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Dilithium functions")

    sig = ml_dsa_44.sign(private_key, message)
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


def generate_sphincs_keypair() -> Tuple[bytes, bytes]:
    """Generate a SPHINCS+ key pair using a 128-bit security level."""
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    return _sphincs_module.generate_keypair()


def sphincs_sign(private_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with SPHINCS+ returning the raw signature bytes."""
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    return _sphincs_module.sign(private_key, message)


def sphincs_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a SPHINCS+ signature."""
    if not PQCRYPTO_AVAILABLE or not SPHINCS_AVAILABLE:
        raise ImportError("pqcrypto with SPHINCS+ support is required")

    try:
        return bool(_sphincs_module.verify(public_key, message, signature))
    except Exception:
        return False
