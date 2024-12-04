from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import scrypt, pbkdf2
from cryptography.exceptions import InvalidKey
from os import urandom

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Constants
SALT_SIZE = 16
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
PBKDF2_ITERATIONS = 100_000


def generate_salt(size: int = SALT_SIZE) -> bytes:
    """
    Generates a cryptographically secure random salt.
    """
    return urandom(size)


def sha256_hash(data: str) -> str:
    """
    Generates a SHA-256 hash of the given data.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize().hex()


def sha384_hash(data: str) -> str:
    """
    Generates a SHA-384 hash of the given data.
    """
    digest = hashes.Hash(hashes.SHA384())
    digest.update(data.encode())
    return digest.finalize().hex()


def sha512_hash(data: str) -> str:
    """
    Generates a SHA-512 hash of the given data.
    """
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data.encode())
    return digest.finalize().hex()


def blake2b_hash(data: str) -> str:
    """
    Generates a BLAKE2b hash of the given data.
    """
    digest = hashes.Hash(hashes.BLAKE2b(64))
    digest.update(data.encode())
    return digest.finalize().hex()


def derive_key_scrypt(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a cryptographic key from a password using Scrypt KDF.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = scrypt.Scrypt(
        salt=salt,
        length=length,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode())


def verify_derived_key_scrypt(password: str, salt: bytes, expected_key: bytes) -> bool:
    """
    Verifies a password against an expected key using Scrypt.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes.")
    if not isinstance(expected_key, bytes):
        raise TypeError("Expected key must be bytes.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    try:
        kdf.verify(password.encode(), expected_key)
        return True
    except InvalidKey:
        return False



def derive_key_pbkdf2(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2 HMAC SHA-256.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def verify_derived_key_pbkdf2(password: str, salt: bytes, expected_key: bytes) -> bool:
    """
    Verifies a password against a previously derived key using PBKDF2 KDF.
    """
    try:
        kdf = pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=len(expected_key),
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        kdf.verify(password.encode(), expected_key)
        return True
    except InvalidKey:
        return False
