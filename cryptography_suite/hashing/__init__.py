from cryptography.hazmat.primitives import hashes

from ..symmetric.kdf import (  # noqa: F401
    derive_key_scrypt,
    verify_derived_key_scrypt,
    derive_key_pbkdf2,
    verify_derived_key_pbkdf2,
    generate_salt,
)


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
