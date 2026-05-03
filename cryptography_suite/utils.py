from __future__ import annotations

import ctypes
import ctypes.util
import secrets
import string
import warnings
from collections.abc import Mapping
from functools import wraps
from hmac import compare_digest
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

from ._key_files import atomic_write_bytes

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .experimental.signal_demo import EncryptedMessage
    from .hybrid import EncryptedHybridMessage

BASE62_ALPHABET = string.digits + string.ascii_letters
ct_equal = compare_digest


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
    return ct_equal(bytes(val1), bytes(val2))


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
        if not isinstance(key, bytes | bytearray):
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

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        try:
            secure_zero(self._key)
        except Exception:
            pass

    def _write_pem(self, path: str | Path, *, encrypted: bool) -> None:
        """Write key material to ``path`` enforcing strict key policy."""
        from .config import STRICT_KEYS
        from .errors import SecurityError

        if STRICT_KEYS in {"warn", "error"} and not encrypted:
            msg = "Unencrypted key file detected"
            if STRICT_KEYS == "error":
                raise SecurityError(msg)
            warnings.warn(msg, UserWarning, stacklevel=2)
        atomic_write_bytes(path, bytes(self._key))


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

PRIVATE_KEY_CLASSES: tuple[type[Any], ...] = (
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)

PUBLIC_KEY_CLASSES: tuple[type[Any], ...] = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
)


def _coerce_pem_bytes(pem: str | bytes) -> bytes:
    if isinstance(pem, str):
        return pem.encode()
    if isinstance(pem, bytes):
        return pem
    raise TypeError("PEM data must be provided as str or bytes.")


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty private key password is required.")
    return password.encode()


def _detect_private_pem_encryption(pem: str | bytes) -> bool | None:
    """Return private PEM encryption status, or ``None`` for non-private PEM."""

    from cryptography.hazmat.primitives import serialization

    pem_bytes = _coerce_pem_bytes(pem)
    try:
        serialization.load_pem_private_key(pem_bytes, password=None)
        return False
    except TypeError as exc:
        message = str(exc).lower()
        if "encrypted" in message or "password" in message:
            return True
        raise
    except ValueError:
        return None


def to_public_pem(public_key: PublicKeyTypes) -> str:
    """Return a PEM-formatted public key string."""

    from cryptography.hazmat.primitives import serialization

    if not isinstance(public_key, PUBLIC_KEY_CLASSES):
        raise TypeError("Unsupported public key type for PEM conversion.")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def to_encrypted_private_pem(private_key: PrivateKeyTypes, password: str) -> str:
    """Return a password-encrypted PKCS#8 private key PEM string."""

    from cryptography.hazmat.primitives import serialization

    if not isinstance(private_key, PRIVATE_KEY_CLASSES):
        raise TypeError("Unsupported private key type for PEM conversion.")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            _password_bytes(password)
        ),
    ).decode()


def to_unencrypted_private_pem_unsafe(private_key: PrivateKeyTypes) -> str:
    """Return an unencrypted private key PEM after emitting an explicit warning."""

    from cryptography.hazmat.primitives import serialization

    if not isinstance(private_key, PRIVATE_KEY_CLASSES):
        raise TypeError("Unsupported private key type for PEM conversion.")
    warnings.warn(
        (
            "UNSAFE: exporting unencrypted private key PEM. Use only for controlled "
            "testing or one-time migration, never for production storage."
        ),
        UserWarning,
        stacklevel=2,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def load_public_pem(pem: str | bytes) -> PublicKeyTypes:
    """Load a PEM-formatted public key."""

    from cryptography.hazmat.primitives import serialization

    pem_bytes = _coerce_pem_bytes(pem)
    try:
        key = serialization.load_pem_public_key(pem_bytes)
    except ValueError as exc:
        from .errors import DecryptionError

        raise DecryptionError(f"Invalid public PEM data: {exc}") from exc
    if not isinstance(key, PUBLIC_KEY_CLASSES):
        raise TypeError("Loaded PEM is not a supported public key.")
    return cast(PublicKeyTypes, key)


def load_encrypted_private_pem(
    pem: str | bytes,
    password: str,
) -> PrivateKeyTypes:
    """Load a password-encrypted private key PEM."""

    from cryptography.hazmat.primitives import serialization

    pem_bytes = _coerce_pem_bytes(pem)
    try:
        key = serialization.load_pem_private_key(
            pem_bytes,
            password=_password_bytes(password),
        )
    except Exception as exc:
        from .errors import DecryptionError

        raise DecryptionError(f"Failed to load encrypted private PEM: {exc}") from exc
    if not isinstance(key, PRIVATE_KEY_CLASSES):
        raise TypeError("Loaded PEM is not a supported private key.")
    return cast(PrivateKeyTypes, key)


def to_pem(key: PrivateKeyTypes | PublicKeyTypes) -> str:
    """Return a PEM-formatted string for public keys only.

    Private key export must be explicit: use ``to_encrypted_private_pem`` or
    ``to_unencrypted_private_pem_unsafe``.
    """

    if isinstance(key, PRIVATE_KEY_CLASSES):
        raise ValueError(
            "to_pem(private_key) no longer exports unencrypted private keys. "
            "Use to_encrypted_private_pem(private_key, password) for safe export "
            "or to_unencrypted_private_pem_unsafe(private_key) only for controlled "
            "testing or migration."
        )
    if isinstance(key, PUBLIC_KEY_CLASSES):
        return to_public_pem(cast(PublicKeyTypes, key))
    raise TypeError("Unsupported key type for PEM conversion.")


def from_pem(pem_str: str) -> PrivateKeyTypes | PublicKeyTypes:
    """Load a public PEM through a deprecated ambiguous compatibility shim."""

    from cryptography.hazmat.primitives import serialization

    from .errors import DecryptionError

    if not isinstance(pem_str, str):
        raise TypeError("PEM data must be provided as a string.")

    warnings.warn(
        (
            "from_pem is ambiguous for private keys and is deprecated. Use "
            "load_public_pem for public keys or load_encrypted_private_pem with "
            "a password for private keys."
        ),
        DeprecationWarning,
        stacklevel=2,
    )

    pem_bytes = pem_str.encode()
    try:
        return cast(PrivateKeyTypes | PublicKeyTypes, load_public_pem(pem_bytes))
    except DecryptionError:
        pass

    try:
        serialization.load_pem_private_key(pem_bytes, password=None)
    except TypeError as exc:
        message = str(exc).lower()
        if "encrypted" in message or "password" in message:
            raise ValueError(
                "Encrypted private PEM requires "
                "load_encrypted_private_pem(pem, password)."
            ) from exc
        raise
    except ValueError as exc:
        raise DecryptionError(f"Invalid PEM data: {exc}") from exc
    raise ValueError(
        "Unencrypted private PEM loading through from_pem is disabled. Store "
        "private keys encrypted and load them with load_encrypted_private_pem."
    )


def is_encrypted_pem(path: str | Path) -> bool:
    """Return ``True`` if the PEM file at ``path`` is an encrypted private key."""

    detected = _detect_private_pem_encryption(Path(path).read_bytes())
    return detected is True


def pem_to_json(
    key: PrivateKeyTypes | PublicKeyTypes,
    password: str | None = None,
    *,
    unsafe_unencrypted_private_key: bool = False,
) -> str:
    """Serialize a key to a JSON object containing a PEM string."""

    import json

    if isinstance(key, PUBLIC_KEY_CLASSES):
        pem = to_public_pem(cast(PublicKeyTypes, key))
        return json.dumps({"pem": pem, "encrypted": False, "key_type": "public"})
    if isinstance(key, PRIVATE_KEY_CLASSES):
        if password:
            pem = to_encrypted_private_pem(cast(PrivateKeyTypes, key), password)
            return json.dumps({"pem": pem, "encrypted": True, "key_type": "private"})
        if unsafe_unencrypted_private_key:
            pem = to_unencrypted_private_pem_unsafe(cast(PrivateKeyTypes, key))
            return json.dumps({"pem": pem, "encrypted": False, "key_type": "private"})
        raise ValueError(
            "pem_to_json(private_key) requires password=... so the private key "
            "is encrypted, or unsafe_unencrypted_private_key=True for controlled "
            "testing/migration only."
        )
    raise TypeError("Unsupported key type for JSON PEM conversion.")


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
        if isinstance(v, bytes | bytearray):
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
