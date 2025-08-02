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


def generate_kyber_keypair(
    level: int = 512, *, sensitive: bool = True
) -> Tuple[bytes, KeyVault | bytes]:
    """Generate a Kyber key pair for the given ``level``.

    Parameters
    ----------
    level : int
        Kyber security level (512, 768 or 1024).
    sensitive : bool, optional
        If ``True`` (default) the private key is wrapped in :class:`KeyVault`
        so it can be securely erased after use.
    """
    if not PQCRYPTO_AVAILABLE:
        raise ImportError("pqcrypto is required for Kyber functions")

    alg = _KYBER_LEVEL_MAP.get(level)
    if alg is None:
        raise EncryptionError("Invalid Kyber level")
    pk, sk = alg.generate_keypair()
    return pk, KeyVault(sk) if sensitive else sk


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
    private_key: bytes | KeyVault,
    ciphertext: bytes | str,
    shared_secret: bytes | str | None = None,
    *,
    level: int = 512,
) -> bytes:
    """Decrypt data encrypted by :func:`kyber_encrypt`.

    ``private_key`` may be raw bytes or a :class:`KeyVault` returned by
    :func:`generate_kyber_keypair`. ``shared_secret`` becomes optional; when
    omitted the function decapsulates it from ``ciphertext``.
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
    salt = ciphertext[ct_size : ct_size + 16]
    enc = ciphertext[ct_size + 16 :]
    priv = bytes(private_key) if isinstance(private_key, KeyVault) else private_key
    ss_check = alg.decrypt(priv, kem_ct)
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


def generate_dilithium_keypair(*, sensitive: bool = True) -> Tuple[bytes, KeyVault | bytes]:
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


def generate_sphincs_keypair(*, sensitive: bool = True) -> Tuple[bytes, KeyVault | bytes]:
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
