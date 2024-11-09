from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64


# Constants
AES_KEY_SIZE = 32  # AES-256 requires a 32-byte (256-bit) key
SALT_SIZE = 16     # Recommended salt size for PBKDF2
ITERATIONS = 100000  # Iteration count for PBKDF2, recommended for high security

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure AES key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def aes_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext using AES-CBC with a password-derived key and PBKDF2.
    Returns the encrypted data as a base64-encoded string (IV + ciphertext).
    """
    salt = urandom(SALT_SIZE)
    key = generate_key(password, salt)
    iv = urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 Padding
    pad_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + chr(pad_length) * pad_length

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()

    # Concatenate salt, IV, and ciphertext, then encode in base64
    encrypted_data = salt + iv + ciphertext
    return base64.b64encode(encrypted_data).decode()


def aes_decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypts AES-CBC encrypted data using a password-derived key and PBKDF2.
    Expects base64 input format (salt + IV + ciphertext).
    """
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract salt, IV, and ciphertext
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE + 16]
    ciphertext = encrypted_data[SALT_SIZE + 16:]

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and remove PKCS7 padding
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_length].decode()

    return plaintext
