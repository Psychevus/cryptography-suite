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
        return b''

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
