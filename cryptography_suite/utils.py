from __future__ import annotations

import ctypes
import ctypes.util
import hmac
import secrets
import string
import warnings
from functools import wraps
from typing import TYPE_CHECKING, Any, Mapping, TypeAlias, cast
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .hybrid import EncryptedHybridMessage
    from .experimental.signal_demo import EncryptedMessage

BASE62_ALPHABET = string.digits + string.ascii_letters


def base62_encode(data: bytes) -> str:
    """
    Encodes byte data into Base62 format.
    """
    if not data:
        return "0"

    value = int.from_bytes(data, byteorder="big")
    encoded = ""
    while value > 0:
        value, remainder = divmod(value, 62)
        encoded = BASE62_ALPHABET[remainder] + encoded
    return encoded


def base62_decode(data: str) -> bytes:
    """
    Decodes a Base62-encoded string into bytes.
    """
    if not data or data == "0":
        return b""

    value = 0
    for char in data:
        value = value * 62 + BASE62_ALPHABET.index(char)
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, byteorder="big")


def secure_zero(data: bytearray) -> None:
    """Overwrite ``data`` with zeros in-place.

    Only mutable ``bytearray`` objects can be wiped in Python. Passing
    an immutable ``bytes`` instance will raise ``TypeError`` and the
    original data may remain in memory until garbage collection. Use
    :class:`KeyVault` or convert to ``bytearray`` before calling.
    """

    if not isinstance(data, bytearray):
        raise TypeError("secure_zero expects a bytearray")

    buf = (ctypes.c_char * len(data)).from_buffer(data)

    libc_name = ctypes.util.find_library("c")
    memset_s = None
    if libc_name:
        libc = ctypes.CDLL(libc_name)
        memset_s = getattr(libc, "memset_s", None)

    if memset_s:
        memset_s.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_size_t,
        ]
        memset_s.restype = ctypes.c_int
        memset_s(ctypes.addressof(buf), len(data), 0, len(data))
    else:  # Fallback to ctypes.memset
        ctypes.memset(ctypes.addressof(buf), 0, len(data))

    if hasattr(buf, "release"):
        buf.release()


def constant_time_compare(val1: bytes | bytearray, val2: bytes | bytearray) -> bool:
    """Return ``True`` if ``val1`` equals ``val2`` using a timing-safe check."""

    return hmac.compare_digest(bytes(val1), bytes(val2))


def deprecated(message: str = "This function is deprecated."):
    """Decorator to mark functions as deprecated."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def generate_secure_random_string(length: int = 32) -> str:
    """
    Generates a secure random string using Base62 encoding.
    """
    random_bytes = secrets.token_bytes(length)
    return base62_encode(random_bytes)


class KeyVault:
    """Context manager for sensitive key storage.

    Secrets wrapped by ``KeyVault`` are wiped from memory when the
    context exits or the object is garbage collected. Plain ``bytes``
    values passed around in Python cannot be reliably erased and may
    linger until the interpreter frees them.
    """

    def __init__(self, key: bytes | bytearray):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("KeyVault expects key data as bytes or bytearray.")
        self._key = bytearray(key)

    def __enter__(self) -> bytearray:
        return self._key

    def __exit__(self, _exc_type, _exc, _tb):
        """Zero the stored key on exit."""
        secure_zero(self._key)
        return False

    def __bytes__(self) -> bytes:  # pragma: no cover - helper for APIs
        return bytes(self._key)

    def __del__(self):  # pragma: no cover - best effort cleanup
        try:
            secure_zero(self._key)
        except Exception:
            pass


PrivateKeyTypes: TypeAlias = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
    | x25519.X25519PrivateKey
    | x448.X448PrivateKey
)

PublicKeyTypes: TypeAlias = (
    rsa.RSAPublicKey
    | ec.EllipticCurvePublicKey
    | ed25519.Ed25519PublicKey
    | ed448.Ed448PublicKey
    | x25519.X25519PublicKey
    | x448.X448PublicKey
)


def to_pem(key: PrivateKeyTypes | PublicKeyTypes) -> str:
    """Return a PEM-formatted string for a key."""
    from cryptography.hazmat.primitives import serialization

    if isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            x25519.X25519PrivateKey,
            x448.X448PrivateKey,
        ),
    ):
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    elif isinstance(
        key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
            x25519.X25519PublicKey,
            x448.X448PublicKey,
        ),
    ):
        pem_bytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise TypeError("Unsupported key type for PEM conversion.")

    return pem_bytes.decode()


def from_pem(pem_str: str) -> PrivateKeyTypes | PublicKeyTypes:
    """Load a key object from a PEM-formatted string."""
    from cryptography.hazmat.primitives import serialization

    if not isinstance(pem_str, str):
        raise TypeError("PEM data must be provided as a string.")

    pem_bytes = pem_str.encode()
    try:
        return cast(
            PrivateKeyTypes | PublicKeyTypes,
            serialization.load_pem_private_key(pem_bytes, password=None),
        )
    except ValueError:
        try:
            return cast(
                PrivateKeyTypes | PublicKeyTypes,
                serialization.load_pem_public_key(pem_bytes),
            )
        except ValueError as exc:
            from .errors import DecryptionError

            raise DecryptionError(f"Invalid PEM data: {exc}") from exc


def is_encrypted_pem(path: str | Path) -> bool:
    """Return ``True`` if the PEM file at ``path`` is encrypted."""
    from cryptography.hazmat.primitives import serialization

    pem_bytes = Path(path).read_bytes()
    try:
        serialization.load_pem_private_key(pem_bytes, password=None)
        return False
    except TypeError as exc:
        if "encrypted" in str(exc).lower():
            return True
        raise
    except ValueError:
        return False


def pem_to_json(key: PrivateKeyTypes | PublicKeyTypes) -> str:
    """Serialize a key to a JSON object containing a PEM string."""
    import json

    pem = to_pem(key)
    return json.dumps({"pem": pem})


def encode_encrypted_message(
    message: EncryptedHybridMessage | Mapping[str, bytes | bytearray],
) -> str:
    """Convert a hybrid or Signal encrypted message into a Base64 string."""
    import base64
    import json
    from dataclasses import asdict, is_dataclass

    if is_dataclass(message):
        data = asdict(cast(Any, message))
    else:
        data = dict(cast(Mapping[str, bytes | bytearray], message))

    enc = {}
    for k, v in data.items():
        if isinstance(v, (bytes, bytearray)):
            enc[k] = base64.b64encode(bytes(v)).decode()
        else:
            enc[k] = v

    json_bytes = json.dumps(enc).encode()
    return base64.b64encode(json_bytes).decode()


def decode_encrypted_message(
    data: str,
) -> EncryptedHybridMessage | Mapping[str, bytes] | EncryptedMessage:
    """Parse a Base64 string produced by :func:`encode_encrypted_message`."""
    import base64
    import json

    json_bytes = base64.b64decode(data)
    parsed = json.loads(json_bytes.decode())
    out = {
        k: base64.b64decode(v) if isinstance(v, str) else v for k, v in parsed.items()
    }

    try:  # Return EncryptedMessage if fields match
        from .experimental.signal_demo import EncryptedMessage

        if set(out.keys()) == {"dh_public", "nonce", "ciphertext"}:
            return EncryptedMessage(**out)
    except Exception:
        pass

    try:
        from .hybrid import EncryptedHybridMessage

        if set(out.keys()) == {"encrypted_key", "nonce", "ciphertext", "tag"}:
            return EncryptedHybridMessage(**out)
    except Exception:
        pass

    return out
