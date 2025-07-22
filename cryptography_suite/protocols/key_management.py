import os
from cryptography.hazmat.primitives.asymmetric import ec
from os import path
from ..asymmetric import (
    load_private_key,
    load_public_key,
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    generate_ec_keypair,
)

# Constants
DEFAULT_AES_KEY_SIZE = 32  # 256 bits


def generate_aes_key() -> bytes:
    """
    Generates a secure random AES key.
    """
    return os.urandom(DEFAULT_AES_KEY_SIZE)


def rotate_aes_key() -> bytes:
    """
    Generates a new AES key to replace the old one.
    """
    return generate_aes_key()


def secure_save_key_to_file(key_data: bytes, filepath: str):
    """
    Saves key data to a specified file path with secure permissions.
    """
    try:
        with open(filepath, 'wb') as key_file:
            key_file.write(key_data)
        os.chmod(filepath, 0o600)
    except Exception as e:
        raise IOError(f"Failed to save key to {filepath}: {e}")


def load_private_key_from_file(filepath: str, password: str):
    """
    Loads a PEM-encoded private key from a file.
    """
    if not path.exists(filepath):
        raise FileNotFoundError(f"Private key file {filepath} does not exist.")

    with open(filepath, 'rb') as key_file:
        pem_data = key_file.read()
    return load_private_key(pem_data, password)


def load_public_key_from_file(filepath: str):
    """
    Loads a PEM-encoded public key from a file.
    """
    if not path.exists(filepath):
        raise FileNotFoundError(f"Public key file {filepath} does not exist.")

    with open(filepath, 'rb') as key_file:
        pem_data = key_file.read()
    return load_public_key(pem_data)


def key_exists(filepath: str) -> bool:
    """
    Checks if a key file exists at the given filepath.
    """
    return path.exists(filepath)


def generate_rsa_keypair_and_save(
    private_key_path: str,
    public_key_path: str,
    password: str,
    key_size: int = 4096,
):
    """
    Generates an RSA key pair and saves them to files.
    """
    private_key, public_key = generate_rsa_keypair(key_size=key_size)
    private_pem = serialize_private_key(private_key, password)
    public_pem = serialize_public_key(public_key)

    secure_save_key_to_file(private_pem, private_key_path)
    secure_save_key_to_file(public_pem, public_key_path)


def generate_ec_keypair_and_save(
    private_key_path: str,
    public_key_path: str,
    password: str,
    curve: ec.EllipticCurve = ec.SECP256R1(),
):
    """
    Generates an EC key pair and saves them to files.
    """
    private_key, public_key = generate_ec_keypair(curve=curve)
    private_pem = serialize_private_key(private_key, password)
    public_pem = serialize_public_key(public_key)

    secure_save_key_to_file(private_pem, private_key_path)
    secure_save_key_to_file(public_pem, public_key_path)
