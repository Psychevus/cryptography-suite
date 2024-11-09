import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from os import urandom, path
from typing import Tuple
import base64

# Constants
DEFAULT_RSA_KEY_SIZE = 3072
DEFAULT_AES_KEY_SIZE = 32  # 256 bits


def generate_aes_key() -> bytes:
    """
    Generates a secure random AES key.
    Returns the key in base64 encoding for easy storage.
    """
    key = urandom(DEFAULT_AES_KEY_SIZE)
    return base64.b64encode(key).decode()


def generate_rsa_key_pair(key_size: int = DEFAULT_RSA_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates an RSA private and public key pair.
    Returns the private and public keys.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: rsa.RSAPrivateKey, password: str) -> bytes:
    """
    Serializes the private key to PEM format, encrypted with the provided password.
    Returns the PEM-encoded key as bytes.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    return pem


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serializes the public key to PEM format.
    Returns the PEM-encoded public key as bytes.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def secure_save_key_to_file(key_data: bytes, filepath: str):
    """
    Saves key data to a specified file path with secure permissions.
    """
    with open(filepath, 'wb') as key_file:
        key_file.write(key_data)
    # Set file to be read/write only by the owner
    os.chmod(filepath, 0o600)


def load_private_key_from_file(filepath: str, password: str) -> rsa.RSAPrivateKey:
    """
    Loads a PEM-encoded private key from a file, decrypted with the provided password.
    Returns the RSA private key.
    """
    with open(filepath, 'rb') as key_file:
        pem_data = key_file.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password.encode(),
        backend=default_backend()
    )
    return private_key


def load_public_key_from_file(filepath: str) -> rsa.RSAPublicKey:
    """
    Loads a PEM-encoded public key from a file.
    Returns the RSA public key.
    """
    with open(filepath, 'rb') as key_file:
        pem_data = key_file.read()
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key


def rotate_aes_key() -> str:
    """
    Generates a new AES key to replace an old one.
    Returns the new AES key as a base64-encoded string.
    """
    return generate_aes_key()


def key_exists(filepath: str) -> bool:
    """
    Checks if a key file exists at the given filepath.
    """
    return path.exists(filepath)
