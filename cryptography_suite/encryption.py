from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from os import urandom
import base64

# Constants
AES_KEY_SIZE = 32  # 256 bits
CHACHA20_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
PBKDF2_ITERATIONS = 100_000
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 1


def derive_key_scrypt(
    password: str,
    salt: bytes,
    key_size: int = AES_KEY_SIZE,
) -> bytes:
    """
    Derives a cryptographic key using Scrypt KDF.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = Scrypt(
        salt=salt,
        length=key_size,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode())


def derive_key_pbkdf2(
    password: str,
    salt: bytes,
    key_size: int = AES_KEY_SIZE,
) -> bytes:
    """
    Derives a cryptographic key using PBKDF2 HMAC SHA-256.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def derive_key_argon2(
    password: str,
    salt: bytes,
    key_size: int = AES_KEY_SIZE,
    memory_cost: int = ARGON2_MEMORY_COST,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    """Derive a key using Argon2id.

    Args:
        password: User supplied password.
        salt: Cryptographic salt.
        key_size: Desired length of the derived key in bytes.
        memory_cost: Memory usage in kibibytes (default 64 MiB).
        time_cost: Number of iterations to perform.
        parallelism: How many parallel threads to use.

    Returns:
        The derived key as bytes.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = Argon2id(
        salt=salt,
        length=key_size,
        iterations=time_cost,
        lanes=parallelism,
        memory_cost=memory_cost,
    )
    return kdf.derive(password.encode())


def aes_encrypt(plaintext: str, password: str, kdf: str = 'scrypt') -> str:
    """
    Encrypts plaintext using AES-GCM with a key derived from the password.
    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == 'scrypt':
        key = derive_key_scrypt(password, salt)
    elif kdf == 'pbkdf2':
        key = derive_key_pbkdf2(password, salt)
    elif kdf == 'argon2':
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    encrypted_data = base64.b64encode(salt + nonce + ciphertext).decode()
    return encrypted_data


def aes_decrypt(
    encrypted_data: str,
    password: str,
    kdf: str = 'scrypt',
) -> str:
    """
    Decrypts data encrypted with AES-GCM using a key derived from the password.
    """
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    encrypted_data_bytes = base64.b64decode(encrypted_data)

    if len(encrypted_data_bytes) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted data.")

    salt = encrypted_data_bytes[:SALT_SIZE]
    nonce = encrypted_data_bytes[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + NONCE_SIZE:]

    if kdf == 'scrypt':
        key = derive_key_scrypt(password, salt)
    elif kdf == 'pbkdf2':
        key = derive_key_pbkdf2(password, salt)
    elif kdf == 'argon2':
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def chacha20_encrypt(plaintext: str, password: str) -> str:
    """Encrypt using ChaCha20-Poly1305 with a Scrypt-derived key."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    key = derive_key_scrypt(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)
    nonce = urandom(NONCE_SIZE)

    ciphertext = chacha.encrypt(nonce, plaintext.encode(), None)
    encrypted_data = base64.b64encode(salt + nonce + ciphertext).decode()
    return encrypted_data


def chacha20_decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt data encrypted with ChaCha20-Poly1305 and Scrypt-derived key."""
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    encrypted_data_bytes = base64.b64decode(encrypted_data)

    if len(encrypted_data_bytes) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted data.")

    salt = encrypted_data_bytes[:SALT_SIZE]
    nonce = encrypted_data_bytes[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + NONCE_SIZE:]

    key = derive_key_scrypt(password, salt, key_size=CHACHA20_KEY_SIZE)
    chacha = ChaCha20Poly1305(key)

    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def scrypt_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext using AES-GCM with Scrypt KDF.
    """
    return aes_encrypt(plaintext, password, kdf='scrypt')


def scrypt_decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypts data encrypted with AES-GCM using Scrypt KDF.
    """
    return aes_decrypt(encrypted_data, password, kdf='scrypt')


def pbkdf2_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext using AES-GCM with PBKDF2 KDF.
    """
    return aes_encrypt(plaintext, password, kdf='pbkdf2')


def pbkdf2_decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypts data encrypted with AES-GCM using PBKDF2 KDF.
    """
    return aes_decrypt(encrypted_data, password, kdf='pbkdf2')


def argon2_encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext using AES-GCM with Argon2id KDF."""
    return aes_encrypt(plaintext, password, kdf='argon2')


def argon2_decrypt(encrypted_data: str, password: str) -> str:
    """Decrypt data encrypted with AES-GCM using Argon2id KDF."""
    return aes_decrypt(encrypted_data, password, kdf='argon2')


def encrypt_file(
    input_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = 'scrypt',
):
    """
    Encrypts a file using AES-GCM with a key derived from the password.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = urandom(SALT_SIZE)
    if kdf == 'scrypt':
        key = derive_key_scrypt(password, salt)
    elif kdf == 'pbkdf2':
        key = derive_key_pbkdf2(password, salt)
    elif kdf == 'argon2':
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)
    nonce = urandom(NONCE_SIZE)

    try:
        with open(input_file_path, 'rb') as f:
            data = f.read()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        with open(output_file_path, 'wb') as f:
            f.write(salt + nonce + ciphertext)
    except Exception as e:
        raise IOError(f"File encryption failed: {e}")


def decrypt_file(
    encrypted_file_path: str,
    output_file_path: str,
    password: str,
    kdf: str = 'scrypt',
):
    """Decrypt a file encrypted with AES-GCM using a password-derived key."""
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
    except Exception as e:
        raise IOError(f"Failed to read encrypted file: {e}")

    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid encrypted file.")

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]

    if kdf == 'scrypt':
        key = derive_key_scrypt(password, salt)
    elif kdf == 'pbkdf2':
        key = derive_key_pbkdf2(password, salt)
    elif kdf == 'argon2':
        key = derive_key_argon2(password, salt)
    else:
        raise ValueError("Unsupported KDF specified.")

    aesgcm = AESGCM(key)

    try:
        data = aesgcm.decrypt(nonce, ciphertext, None)
        with open(output_file_path, 'wb') as f:
            f.write(data)
    except Exception as e:
        raise ValueError(
            "File decryption failed: Invalid password or corrupted file."
        ) from e
