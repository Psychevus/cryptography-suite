from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64

# Constants
SALT_SIZE = 16          # Size for generated salts
PBKDF2_ITERATIONS = 100000  # Number of iterations for PBKDF2-HMAC

def generate_salt() -> bytes:
    """
    Generates a secure random salt.
    """
    return urandom(SALT_SIZE)


def sha384_hash(data: str) -> str:
    """
    Generates a SHA-384 hash of the given data.
    Returns the hash as a hexadecimal string.
    """
    digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize().hex()


def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2 with HMAC-SHA256.
    Returns the derived key in base64 encoding.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    return base64.b64encode(derived_key).decode()


def verify_derived_key(password: str, salt: bytes, expected_key: str) -> bool:
    """
    Verifies a password against a previously derived key.
    Returns True if the password produces the expected key, False otherwise.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=len(base64.b64decode(expected_key)),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), base64.b64decode(expected_key))
        return True
    except Exception:
        return False
