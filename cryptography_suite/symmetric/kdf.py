from __future__ import annotations

from os import urandom

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from ..errors import KeyDerivationError

# Constants
AES_KEY_SIZE = 32  # 256 bits
CHACHA20_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
PBKDF2_ITERATIONS = 100_000
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 1


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
    """Derive a key using Argon2id."""
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


__all__ = [
    "AES_KEY_SIZE",
    "CHACHA20_KEY_SIZE",
    "SALT_SIZE",
    "NONCE_SIZE",
    "derive_key_scrypt",
    "verify_derived_key_scrypt",
    "derive_key_pbkdf2",
    "verify_derived_key_pbkdf2",
    "derive_key_argon2",
    "generate_salt",
]
