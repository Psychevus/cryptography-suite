"""Hashing utilities.

SHA and BLAKE2b use :mod:`pyca/cryptography`. BLAKE3 relies on the standalone
``blake3`` library. These are the authoritative backends for hashing within the
project.
"""

from typing import Protocol, cast

from cryptography.hazmat.primitives import hashes

from ..errors import MissingDependencyError
from ..symmetric.kdf import (  # noqa: F401
    derive_key_pbkdf2,
    derive_key_scrypt,
    generate_salt,
    verify_derived_key_pbkdf2,
    verify_derived_key_scrypt,
)


class _Blake3Digest(Protocol):
    def hexdigest(self) -> str: ...


class _Blake3Factory(Protocol):
    def __call__(self, data: bytes) -> _Blake3Digest: ...


def _load_blake3() -> _Blake3Factory:
    try:
        from blake3 import blake3
    except Exception as exc:  # pragma: no cover - dependency missing
        raise MissingDependencyError(
            "BLAKE3 hashing requires blake3. "
            "Install cryptography-suite[hashing-extra] to use this feature."
        ) from exc
    return cast(_Blake3Factory, blake3)


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


def sha3_256_hash(data: str) -> str:
    """Generates a SHA3-256 hash of the given data."""
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data.encode())
    return digest.finalize().hex()


def sha3_512_hash(data: str) -> str:
    """Generates a SHA3-512 hash of the given data."""
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(data.encode())
    return digest.finalize().hex()


def blake2b_hash(data: str) -> str:
    """
    Generates a BLAKE2b hash of the given data.
    """
    digest = hashes.Hash(hashes.BLAKE2b(64))
    digest.update(data.encode())
    return digest.finalize().hex()


def blake3_hash(data: str) -> str:
    """Generates a BLAKE3 hash of the given data."""
    blake3 = _load_blake3()
    return blake3(data.encode()).hexdigest()


def blake3_hash_v2(data: str) -> str:
    """Another BLAKE3 hash helper used for testing."""
    blake3 = _load_blake3()
    digest = blake3(data.encode())
    return digest.hexdigest()
