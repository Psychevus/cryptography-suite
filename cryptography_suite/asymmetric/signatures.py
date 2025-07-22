from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from typing import Tuple


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """
    Generates an Ed25519 private and public key pair.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(message: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """
    Signs a message using Ed25519.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Invalid Ed25519 private key.")

    signature = private_key.sign(message)
    return signature


def verify_signature(message: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    """
    Verifies an Ed25519 signature.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Invalid Ed25519 public key.")

    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def generate_ed448_keypair() -> Tuple[ed448.Ed448PrivateKey, ed448.Ed448PublicKey]:
    """Generates an Ed448 private and public key pair."""
    private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message_ed448(message: bytes, private_key: ed448.Ed448PrivateKey) -> bytes:
    """Signs a message using Ed448."""
    if not message:
        raise ValueError("Message cannot be empty.")
    if not isinstance(private_key, ed448.Ed448PrivateKey):
        raise ValueError("Invalid Ed448 private key.")

    return private_key.sign(message)


def verify_signature_ed448(message: bytes, signature: bytes, public_key: ed448.Ed448PublicKey) -> bool:
    """Verifies an Ed448 signature."""
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    if not isinstance(public_key, ed448.Ed448PublicKey):
        raise ValueError("Invalid Ed448 public key.")

    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def serialize_ed25519_private_key(private_key: ed25519.Ed25519PrivateKey, password: str) -> bytes:
    """
    Serializes an Ed25519 private key to PEM format with encryption.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    return pem_data


def serialize_ed25519_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """
    Serializes an Ed25519 public key to PEM format.
    """
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_data


def load_ed25519_private_key(pem_data: bytes, password: str) -> ed25519.Ed25519PrivateKey:
    """
    Loads an Ed25519 private key from PEM data.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password.encode(),
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Loaded key is not an Ed25519 private key.")
    return private_key


def load_ed25519_public_key(pem_data: bytes) -> ed25519.Ed25519PublicKey:
    """
    Loads an Ed25519 public key from PEM data.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Loaded key is not an Ed25519 public key.")
    return public_key


def generate_ecdsa_keypair(
    curve: ec.EllipticCurve = ec.SECP256R1(),
) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates an ECDSA private and public key pair.
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message_ecdsa(message: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Signs a message using ECDSA.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Invalid ECDSA private key.")

    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature_ecdsa(message: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
    """
    Verifies an ECDSA signature.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Invalid ECDSA public key.")

    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def serialize_ecdsa_private_key(private_key: ec.EllipticCurvePrivateKey, password: str) -> bytes:
    """
    Serializes an ECDSA private key to PEM format with encryption.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    return pem_data


def serialize_ecdsa_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Serializes an ECDSA public key to PEM format.
    """
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_data


def load_ecdsa_private_key(pem_data: bytes, password: str) -> ec.EllipticCurvePrivateKey:
    """
    Loads an ECDSA private key from PEM data.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password.encode(),
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Loaded key is not an ECDSA private key.")
    return private_key


def load_ecdsa_public_key(pem_data: bytes) -> ec.EllipticCurvePublicKey:
    """
    Loads an ECDSA public key from PEM data.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Loaded key is not an ECDSA public key.")
    return public_key
