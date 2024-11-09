import base64
import string
from typing import Union

# Define Base62 alphabet
BASE62_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


def base62_encode(data: bytes) -> str:
    """
    Encodes byte data into Base62 format.
    """
    encoded_str = ""
    value = int.from_bytes(data, byteorder="big")

    while value > 0:
        value, remainder = divmod(value, 62)
        encoded_str = BASE62_ALPHABET[remainder] + encoded_str

    # If data was empty, return '0' as the default encoding
    return encoded_str or "0"


def base62_decode(data: str) -> bytes:
    """
    Decodes a Base62-encoded string into bytes.
    """
    value = 0
    for char in data:
        value = value * 62 + BASE62_ALPHABET.index(char)

    # Convert integer back to byte data
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")


def chars_to_bytes(chars: Union[str, list]) -> bytes:
    """
    Converts a list of characters or a string into a byte array.
    """
    if isinstance(chars, str):
        chars = list(chars)
    return ''.join(chars).encode("utf-8")


def bytes_to_chars(data: bytes) -> list:
    """
    Converts byte data to a list of characters.
    """
    return list(data.decode("utf-8", errors="ignore"))


# Optional utility for zeroing out byte arrays after use to avoid lingering sensitive data
def secure_zero(data: bytearray):
    """
    Overwrites the contents of a bytearray with zeros.
    This is useful for clearing sensitive information from memory.
    """
    for i in range(len(data)):
        data[i] = 0
