from __future__ import annotations

"""Key-derivation helpers using :mod:`pyca/cryptography`.

Argon2id, Scrypt, PBKDF2, and HKDF are provided via ``pyca/cryptography`` and
serve as the authoritative implementations.
"""

from os import urandom

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
try:  # pragma: no cover - optional dependency
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - gracefully handle missing support
    ARGON2_AVAILABLE = False
    Argon2id = None  # type: ignore
from ..errors import KeyDerivationError, MissingDependencyError
from ..utils import deprecated
from ..constants import (
    AES_KEY_SIZE,
    CHACHA20_KEY_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    PBKDF2_ITERATIONS,
)
from os import getenv

# Argon2 parameters can be tuned via environment variables to balance security
# and performance. These values are loaded at import time so tests can
# override them by setting environment variables before reloading this module.
ARGON2_MEMORY_COST = int(getenv("CRYPTOSUITE_ARGON2_MEMORY_COST", "65536"))
ARGON2_TIME_COST = int(getenv("CRYPTOSUITE_ARGON2_TIME_COST", "3"))
ARGON2_PARALLELISM = int(getenv("CRYPTOSUITE_ARGON2_PARALLELISM", "1"))

# ``Argon2`` is the default KDF when available; otherwise fall back to Scrypt.
DEFAULT_KDF = "argon2" if ARGON2_AVAILABLE else "scrypt"


def generate_salt(size: int = SALT_SIZE) -> bytes:
    """Generate a cryptographically secure random salt."""
    return urandom(size)


def derive_key_scrypt(password: str, salt: bytes, key_size: int = AES_KEY_SIZE) -> bytes:
    """Derive a cryptographic key using Scrypt KDF."""
    if not password:
        raise KeyDerivationError("Password cannot be empty.")
    kdf = Scrypt(salt=salt, length=key_size, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode())


def verify_derived_key_scrypt(password: str, salt: bytes, expected_key: bytes) -> bool:
    """Verify a password against an expected key using Scrypt."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes.")
    if not isinstance(expected_key, bytes):
        raise TypeError("Expected key must be bytes.")

    kdf = Scrypt(
        salt=salt,
        length=len(expected_key),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    try:
        kdf.verify(password.encode(), expected_key)
        return True
    except InvalidKey:
        return False


def derive_key_pbkdf2(password: str, salt: bytes, key_size: int = AES_KEY_SIZE) -> bytes:
    """Derive a key using PBKDF2 HMAC SHA-256."""
    if not password:
        raise KeyDerivationError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def verify_derived_key_pbkdf2(password: str, salt: bytes, expected_key: bytes) -> bool:
    """Verify a password against a previously derived PBKDF2 key."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=len(expected_key),
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        kdf.verify(password.encode(), expected_key)
        return True
    except InvalidKey:
        return False


def derive_key_argon2(
    password: str,
    salt: bytes,
    key_size: int = AES_KEY_SIZE,
    memory_cost: int = ARGON2_MEMORY_COST,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    """Derive a key using Argon2id.

    The cost parameters default to module constants which may be overridden via
    the ``CRYPTOSUITE_ARGON2_*`` environment variables.
    """
    if not ARGON2_AVAILABLE:
        raise MissingDependencyError("Argon2id KDF is not supported in this environment")
    if not password:
        raise KeyDerivationError("Password cannot be empty.")
    kdf = Argon2id(
        salt=salt,
        length=key_size,
        iterations=time_cost,
        lanes=parallelism,
        memory_cost=memory_cost,
    )
    return kdf.derive(password.encode())


def derive_hkdf(key: bytes, salt: bytes | None, info: bytes | None, length: int) -> bytes:
    """Derive a key using HKDF-SHA256."""

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes or None.")
    if info is not None and not isinstance(info, bytes):
        raise TypeError("Info must be bytes or None.")
    if length <= 0:
        raise ValueError("Length must be positive.")

    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(key)


def kdf_pbkdf2(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    """Derive a key using PBKDF2-HMAC-SHA256 with configurable iterations."""

    if not password:
        raise KeyDerivationError("Password cannot be empty.")
    if iterations <= 0:
        raise ValueError("Iterations must be positive.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


@deprecated("derive_pbkdf2 is deprecated; use kdf_pbkdf2")
def derive_pbkdf2(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    """Deprecated alias for :func:`kdf_pbkdf2`.

    Deprecated: will be removed in v4.0.0. Use :func:`kdf_pbkdf2` instead.
    """

    return kdf_pbkdf2(password, salt, iterations, length)


def select_kdf(password: str, salt: bytes, kdf: str = DEFAULT_KDF, *, key_size: int = AES_KEY_SIZE) -> bytes:
    """Return a key derived using the specified KDF.

    Supported values for ``kdf`` are ``"argon2"`` (default when available),
    ``"scrypt"`` and ``"pbkdf2"``.
    """

    if kdf == "scrypt":
        return derive_key_scrypt(password, salt, key_size=key_size)
    if kdf == "pbkdf2":
        return derive_key_pbkdf2(password, salt, key_size=key_size)
    if kdf == "argon2":
        return derive_key_argon2(password, salt, key_size=key_size)
    raise KeyDerivationError("Unsupported KDF specified.")


__all__ = [
    "AES_KEY_SIZE",
    "CHACHA20_KEY_SIZE",
    "SALT_SIZE",
    "NONCE_SIZE",
    "DEFAULT_KDF",
    "derive_key_scrypt",
    "verify_derived_key_scrypt",
    "derive_key_pbkdf2",
    "verify_derived_key_pbkdf2",
    "derive_key_argon2",
    "derive_hkdf",
    "kdf_pbkdf2",
    "select_kdf",
    "generate_salt",
]
