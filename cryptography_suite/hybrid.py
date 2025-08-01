from __future__ import annotations

import base64
from dataclasses import dataclass
from os import urandom
from typing import Mapping, TYPE_CHECKING, cast

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .protocols.signal import EncryptedMessage

from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .utils import KeyVault

from .asymmetric import ec_decrypt, ec_encrypt, rsa_decrypt, rsa_encrypt
from .errors import DecryptionError, EncryptionError


@dataclass
class EncryptedHybridMessage:
    """Container for a hybrid encrypted message."""

    encrypted_key: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class HybridEncryptor:
    """Object-oriented helper for hybrid encryption."""

    def encrypt(
        self,
        message: bytes,
        public_key: rsa.RSAPublicKey | x25519.X25519PublicKey,
        *,
        raw_output: bool = False,
    ) -> EncryptedHybridMessage:
        """Encrypt ``message`` using :func:`hybrid_encrypt`."""

        return hybrid_encrypt(message, public_key, raw_output=raw_output)

    def decrypt(
        self,
        private_key: rsa.RSAPrivateKey | x25519.X25519PrivateKey,
        data: EncryptedHybridMessage
        | Mapping[str, str | bytes]
        | str
        | "EncryptedMessage",
    ) -> bytes:
        """Decrypt data produced by :meth:`encrypt`."""

        return hybrid_decrypt(private_key, data)


def hybrid_encrypt(
    message: bytes,
    public_key: rsa.RSAPublicKey | x25519.X25519PublicKey,
    *,
    raw_output: bool = False,
) -> EncryptedHybridMessage:
    """Encrypt ``message`` using hybrid RSA/ECIES + AES-GCM.

    The AES key is randomly generated and encrypted with the recipient's
    public key. The message itself is encrypted with AES-GCM.
    """
    if not message:
        raise EncryptionError("Message cannot be empty.")

    aes_key = urandom(32)

    if isinstance(public_key, rsa.RSAPublicKey):
        import warnings

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            encrypted_key = cast(
                bytes, rsa_encrypt(aes_key, public_key, raw_output=True)
            )
    elif isinstance(public_key, x25519.X25519PublicKey):
        encrypted_key = cast(bytes, ec_encrypt(aes_key, public_key, raw_output=True))
    else:
        raise TypeError("Unsupported public key type.")

    aesgcm = AESGCM(aes_key)
    nonce = urandom(12)
    enc = aesgcm.encrypt(nonce, message, None)
    ciphertext = enc[:-16]
    tag = enc[-16:]

    return EncryptedHybridMessage(
        encrypted_key=encrypted_key,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


def hybrid_decrypt(
    private_key: rsa.RSAPrivateKey | x25519.X25519PrivateKey,
    data: EncryptedHybridMessage | Mapping[str, str | bytes] | str | EncryptedMessage,
) -> bytes:
    """Decrypt data produced by :func:`hybrid_encrypt`."""

    if isinstance(data, str):
        from .utils import decode_encrypted_message

        data = cast(
            EncryptedHybridMessage | Mapping[str, bytes] | EncryptedMessage,
            decode_encrypted_message(data),
        )

    if isinstance(data, EncryptedHybridMessage):
        enc_key = data.encrypted_key
        nonce = data.nonce
        ciphertext = data.ciphertext
        tag = data.tag
    elif isinstance(data, dict):
        for field in ("encrypted_key", "nonce", "ciphertext", "tag"):
            if field not in data:
                raise DecryptionError("Invalid encrypted payload.")

        enc_key = data["encrypted_key"]
        nonce_data = data["nonce"]
        ct_data = data["ciphertext"]
        tag_data = data["tag"]

        try:
            nonce = (
                base64.b64decode(nonce_data)
                if isinstance(nonce_data, str)
                else nonce_data
            )
            ciphertext = (
                base64.b64decode(ct_data) if isinstance(ct_data, str) else ct_data
            )
            tag = base64.b64decode(tag_data) if isinstance(tag_data, str) else tag_data
        except Exception as exc:  # pragma: no cover - defensive parsing
            raise DecryptionError(f"Invalid encoded data: {exc}") from exc
    else:
        raise DecryptionError("Invalid encrypted payload.")

    if isinstance(private_key, rsa.RSAPrivateKey):
        import warnings

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            aes_key = rsa_decrypt(enc_key, private_key)
    elif isinstance(private_key, x25519.X25519PrivateKey):
        aes_key = ec_decrypt(enc_key, private_key)
    else:
        raise TypeError("Unsupported private key type.")

    with KeyVault(aes_key) as key_buf:
        aesgcm = AESGCM(bytes(key_buf))
        try:
            return aesgcm.decrypt(nonce, ciphertext + tag, None)
        except Exception as exc:  # pragma: no cover - high-level error handling
            raise DecryptionError(f"Decryption failed: {exc}") from exc


__all__ = [
    "EncryptedHybridMessage",
    "hybrid_encrypt",
    "hybrid_decrypt",
    "HybridEncryptor",
]
