import string
import secrets

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


def secure_zero(data: bytearray):
    """
    Overwrites the contents of a bytearray with zeros to clear sensitive data from memory.
    """
    for i in range(len(data)):
        data[i] = 0


def generate_secure_random_string(length: int = 32) -> str:
    """
    Generates a secure random string using Base62 encoding.
    """
    random_bytes = secrets.token_bytes(length)
    return base62_encode(random_bytes)


class KeyVault:
    """Context manager for sensitive key storage."""

    def __init__(self, key: bytes | bytearray):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("KeyVault expects key data as bytes or bytearray.")
        self._key = bytearray(key)

    def __enter__(self) -> bytearray:
        return self._key

    def __exit__(self, exc_type, exc, tb):
        secure_zero(self._key)
        return False


def to_pem(key) -> str:
    """Return a PEM-formatted string for a key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import (
        rsa,
        ec,
        ed25519,
        ed448,
        x25519,
        x448,
    )

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


def from_pem(pem_str: str):
    """Load a key object from a PEM-formatted string."""
    from cryptography.hazmat.primitives import serialization

    if not isinstance(pem_str, str):
        raise TypeError("PEM data must be provided as a string.")

    pem_bytes = pem_str.encode()
    try:
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except ValueError:
        try:
            return serialization.load_pem_public_key(pem_bytes)
        except ValueError as exc:
            from .errors import DecryptionError

            raise DecryptionError(f"Invalid PEM data: {exc}") from exc
