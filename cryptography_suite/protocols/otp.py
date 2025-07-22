import hmac
import time
import base64
import struct
from hashlib import sha1, sha256, sha512
from typing import Optional
from ..errors import ProtocolError


def generate_hotp(secret: str, counter: int, digits: int = 6, algorithm: str = 'sha1') -> str:
    """
    Generates an HOTP code based on a shared secret and counter.
    """
    try:
        key = base64.b32decode(secret.upper(), casefold=True)
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
    """
    for offset in range(-window, window + 1):
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
    """
    if timestamp is None:
        timestamp = int(time.time())

    time_counter = int(timestamp // interval)
    return verify_hotp(code, secret, time_counter, digits, window, algorithm)
