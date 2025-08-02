import hmac
import time
import base64
import struct
import warnings
from hashlib import sha1, sha256, sha512
from typing import Optional
from ..errors import ProtocolError


def _pad_base32(secret: str) -> str:
    """Return a base32 string padded for decoding."""
    secret = secret.upper()
    missing = len(secret) % 8
    if missing:
        secret += "=" * (8 - missing)
    return secret


def generate_hotp(secret: str, counter: int, digits: int = 6, algorithm: str = 'sha1') -> str:
    """
    Generates an HOTP code based on a shared secret and counter.

    By default, this implementation uses SHA-1 for compatibility with existing
    standards (RFC 4226/RFC 6238). SHA-256 and SHA-512 are supported as
    alternatives via the ``algorithm`` parameter. For high-security use, prefer
    SHA-256 or higher if your authenticator supports it.
    """
    if algorithm == 'sha1':
        warnings.warn(
            (
                "Defaulting to SHA-1 for compatibility. SHA-256 or SHA-512 are "
                "recommended for high-security use."
            ),
            UserWarning,
            stacklevel=2,
        )
    try:
        key = base64.b32decode(_pad_base32(secret), casefold=True)
    except Exception as e:
        raise ProtocolError(f"Invalid secret: {e}")

    if algorithm == 'sha1':
        hash_function = sha1
    elif algorithm == 'sha256':
        hash_function = sha256
    elif algorithm == 'sha512':
        hash_function = sha512
    else:
        raise ProtocolError("Unsupported algorithm.")

    msg = struct.pack(">Q", counter)
    hmac_digest = hmac.new(key, msg, hash_function).digest()
    o = hmac_digest[-1] & 0x0F
    code_int = (struct.unpack(">I", hmac_digest[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    code = f"{code_int:0{digits}d}"
    return code


def verify_hotp(
    code: str,
    secret: str,
    counter: int,
    digits: int = 6,
    window: int = 1,
    algorithm: str = 'sha1'
) -> bool:
    """
    Verifies an HOTP code within the allowed counter window.

    By default, this implementation uses SHA-1 for compatibility with existing
    standards (RFC 4226/RFC 6238). SHA-256 and SHA-512 are supported as
    alternatives via the ``algorithm`` parameter. For high-security use, prefer
    SHA-256 or higher if your authenticator supports it.
    """
    for offset in range(-window, window + 1):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            calculated_code = generate_hotp(secret, counter + offset, digits, algorithm)
        if hmac.compare_digest(calculated_code, code):
            return True
    return False


def generate_totp(
    secret: str,
    interval: int = 30,
    digits: int = 6,
    algorithm: str = 'sha1',
    timestamp: Optional[int] = None
) -> str:
    """
    Generates a TOTP code based on a shared secret.

    By default, this implementation uses SHA-1 for compatibility with existing
    standards (RFC 6238). SHA-256 and SHA-512 are supported as alternatives via
    the ``algorithm`` parameter. For high-security use, prefer SHA-256 or higher
    if your authenticator supports it.
    """
    if timestamp is None:
        timestamp = int(time.time())

    time_counter = int(timestamp // interval)
    return generate_hotp(secret, time_counter, digits, algorithm)


def verify_totp(
    code: str,
    secret: str,
    interval: int = 30,
    window: int = 1,
    digits: int = 6,
    algorithm: str = 'sha1',
    timestamp: Optional[int] = None
) -> bool:
    """
    Verifies a TOTP code within the allowed time window.

    By default, this implementation uses SHA-1 for compatibility with existing
    standards (RFC 6238). SHA-256 and SHA-512 are supported as alternatives via
    the ``algorithm`` parameter. For high-security use, prefer SHA-256 or higher
    if your authenticator supports it.
    """
    if timestamp is None:
        timestamp = int(time.time())

    time_counter = int(timestamp // interval)
    return verify_hotp(code, secret, time_counter, digits, window, algorithm)
