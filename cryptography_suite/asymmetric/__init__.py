from typing import Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
from cryptography.hazmat.primitives.asymmetric import x25519

# Constants
DEFAULT_RSA_KEY_SIZE = 4096  # 4096 bits for enhanced security
DEFAULT_EC_CURVE = ec.SECP256R1()  # NIST P-256 curve


def generate_rsa_keypair(
        key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates an RSA private and public key pair.
    """
    if key_size < 2048:
        raise ValueError("Key size should be at least 2048 bits for security reasons.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypts plaintext using RSA-OAEP with SHA-256.
    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Invalid RSA public key provided.")

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypts ciphertext using RSA-OAEP with SHA-256.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Invalid RSA private key provided.")

    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty.")

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def serialize_private_key(private_key, password: str) -> bytes:
    """
    Serializes a private key to PEM format, encrypted with a password.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not isinstance(private_key, (
    rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
        raise TypeError("Invalid private key type.")

    encryption_algorithm = serialization.BestAvailableEncryption(password.encode())

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def serialize_public_key(public_key) -> bytes:
    """
    Serializes a public key to PEM format.
    """
    if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
        raise TypeError("Invalid public key type.")

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )



def load_private_key(pem_data: bytes, password: str):
    """
    Loads a private key (RSA, X25519, or EC) from PEM data.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        private_key = serialization.load_pem_private_key(
            pem_data, password=password.encode()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")


def load_public_key(pem_data: bytes):
    """
    Loads a public key (RSA, X25519, or EC) from PEM data.
    """
    try:
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to load public key: {e}")


def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generates an X25519 private and public key pair.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_x25519_shared_key(private_key, peer_public_key) -> bytes:
    """
    Derives a shared key using X25519 key exchange.
    """
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("Invalid X25519 private key.")
    if not isinstance(peer_public_key, x25519.X25519PublicKey):
        raise TypeError("Invalid X25519 public key.")
    shared_key = private_key.exchange(peer_public_key)
    return shared_key


def generate_ec_keypair(curve=ec.SECP256R1()) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates an Elliptic Curve key pair.
    """
    if not isinstance(curve, ec.EllipticCurve):
        raise TypeError("Curve must be an instance of EllipticCurve.")
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key



def ec_encrypt(plaintext: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Encrypts plaintext using ECIES (Elliptic Curve Integrated Encryption Scheme).
    """
    # Note: ECIES is not directly supported in cryptography library.
    # This is a placeholder for an actual ECIES implementation.
    raise NotImplementedError("ECIES encryption is not implemented.")


def ec_decrypt(ciphertext: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Decrypts ciphertext using ECIES (Elliptic Curve Integrated Encryption Scheme).
    """
    # Note: ECIES is not directly supported in cryptography library.
    # This is a placeholder for an actual ECIES implementation.
    raise NotImplementedError("ECIES decryption is not implemented.")
