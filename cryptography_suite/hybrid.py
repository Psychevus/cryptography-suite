from __future__ import annotations

import base64
from os import urandom
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .asymmetric import ec_decrypt, ec_encrypt, rsa_decrypt, rsa_encrypt
from .errors import DecryptionError, EncryptionError


def hybrid_encrypt(message: bytes, public_key: Any) -> Dict[str, str]:
    """Encrypt ``message`` using hybrid RSA/ECIES + AES-GCM.

    The AES key is randomly generated and encrypted with the recipient's
    public key. The message itself is encrypted with AES-GCM.
    """
    if not message:
        raise EncryptionError("Message cannot be empty.")

    if isinstance(public_key, rsa.RSAPublicKey):
        key_encrypt = lambda k: rsa_encrypt(k, public_key)
    elif isinstance(public_key, x25519.X25519PublicKey):
        key_encrypt = lambda k: ec_encrypt(k, public_key)
    else:
        raise TypeError("Unsupported public key type.")

    aes_key = urandom(32)
    aesgcm = AESGCM(aes_key)
    nonce = urandom(12)
    enc = aesgcm.encrypt(nonce, message, None)
    ciphertext = enc[:-16]
    tag = enc[-16:]

    encrypted_key = key_encrypt(aes_key)

    return {
        "encrypted_key": encrypted_key,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def hybrid_decrypt(private_key: Any, data: Dict[str, str]) -> bytes:
    """Decrypt data produced by :func:`hybrid_encrypt`."""

    for field in ("encrypted_key", "nonce", "ciphertext", "tag"):
        if field not in data:
            raise DecryptionError("Invalid encrypted payload.")

    enc_key = data["encrypted_key"]
    nonce_b64 = data["nonce"]
    ct_b64 = data["ciphertext"]
    tag_b64 = data["tag"]

    if isinstance(private_key, rsa.RSAPrivateKey):
        aes_key = rsa_decrypt(enc_key, private_key)
    elif isinstance(private_key, x25519.X25519PrivateKey):
        aes_key = ec_decrypt(enc_key, private_key)
    else:
        raise TypeError("Unsupported private key type.")

    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ct_b64)
        tag = base64.b64decode(tag_b64)
    except Exception as exc:  # pragma: no cover - defensive parsing
        raise DecryptionError(f"Invalid encoded data: {exc}") from exc

    aesgcm = AESGCM(aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise DecryptionError(f"Decryption failed: {exc}") from exc


__all__ = ["hybrid_encrypt", "hybrid_decrypt"]
