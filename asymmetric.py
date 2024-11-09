from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from typing import Tuple
import base64

# Constants
RSA_KEY_SIZE = 3072  # Key size for RSA-3072 security


def generate_rsa_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(plaintext: str, public_key: rsa.RSAPublicKey) -> str:
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The provided public key is not an RSA public key.")

    if not plaintext:
        raise ValueError("Plaintext cannot be empty")

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(encrypted_data: str, private_key: rsa.RSAPrivateKey) -> str:
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided private key is not an RSA private key.")

    ciphertext = base64.b64decode(encrypted_data)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


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


def load_private_key(pem_data: bytes, password: str) -> rsa.RSAPrivateKey:
    """
    Loads a PEM-encoded private key from bytes, decrypted with the provided password.
    Returns the RSA private key.
    """
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password.encode(),
        backend=default_backend()
    )
    return private_key


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    Loads a PEM-encoded public key from bytes.
    Returns the RSA public key.
    """
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key
