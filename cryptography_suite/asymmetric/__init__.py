from typing import Tuple
from ..errors import EncryptionError, DecryptionError

from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding,
    ec,
    ed25519,
    x25519,
    x448,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from os import urandom

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
        raise EncryptionError(
            "Key size should be at least 2048 bits for security reasons."
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypts plaintext using RSA-OAEP with SHA-256.
    """
    if not plaintext:
        raise EncryptionError("Plaintext cannot be empty.")
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
        raise DecryptionError("Ciphertext cannot be empty.")

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
        raise DecryptionError(f"Decryption failed: {e}")


def serialize_private_key(private_key, password: str) -> bytes:
    """
    Serializes a private key to PEM format, encrypted with a password.
    """
    if not password:
        raise EncryptionError("Password cannot be empty.")
    if not isinstance(
        private_key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            x25519.X25519PrivateKey,
            x448.X448PrivateKey,
        ),
    ):
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
    if not isinstance(
        public_key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            x25519.X25519PublicKey,
            x448.X448PublicKey,
        ),
    ):
        raise TypeError("Invalid public key type.")

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes, password: str):
    """
    Loads a private key (RSA, X25519, X448, or EC) from PEM data.
    """
    if not password:
        raise DecryptionError("Password cannot be empty.")

    try:
        private_key = serialization.load_pem_private_key(
            pem_data, password=password.encode()
        )
        return private_key
    except Exception as e:
        raise DecryptionError(f"Failed to load private key: {e}")


def load_public_key(pem_data: bytes):
    """
    Loads a public key (RSA, X25519, X448, or EC) from PEM data.
    """
    try:
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key
    except Exception as e:
        raise DecryptionError(f"Failed to load public key: {e}")


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


def generate_x448_keypair() -> Tuple[x448.X448PrivateKey, x448.X448PublicKey]:
    """Generates an X448 private and public key pair."""
    private_key = x448.X448PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_x448_shared_key(private_key, peer_public_key) -> bytes:
    """Derives a shared key using X448 key exchange."""
    if not isinstance(private_key, x448.X448PrivateKey):
        raise TypeError("Invalid X448 private key.")
    if not isinstance(peer_public_key, x448.X448PublicKey):
        raise TypeError("Invalid X448 public key.")
    return private_key.exchange(peer_public_key)


def generate_ec_keypair(curve=ec.SECP256R1()) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates an Elliptic Curve key pair.
    """
    if not isinstance(curve, ec.EllipticCurve):
        raise TypeError("Curve must be an instance of EllipticCurve.")
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


def ec_encrypt(plaintext: bytes, public_key: x25519.X25519PublicKey) -> bytes:
    """Encrypt ``plaintext`` for ``public_key`` using ECIES.

    This implementation follows best practices:

    1. Generate a fresh ephemeral X25519 key pair.
    2. Derive the ECDH shared secret with the recipient's public key.
    3. Use HKDF-SHA256 to turn the shared secret into a 256-bit AES key.
    4. Encrypt the plaintext with AES-GCM using a random nonce.

    The returned value consists of the ephemeral public key, nonce, and
    ciphertext concatenated together.
    """

    if not plaintext:
        raise EncryptionError("Plaintext cannot be empty.")
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise TypeError("Invalid X25519 public key provided.")

    eph_priv = x25519.X25519PrivateKey.generate()
    shared = eph_priv.exchange(public_key)
    if constant_time.bytes_eq(shared, b"\x00" * 32):
        raise EncryptionError("Invalid shared secret derived.")

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cryptography-suite-ecies",
    ).derive(shared)

    nonce = urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return eph_pub_bytes + nonce + ciphertext


def ec_decrypt(ciphertext: bytes, private_key: x25519.X25519PrivateKey) -> bytes:
    """Decrypt ECIES ``ciphertext`` using ``private_key``.

    The ``ciphertext`` must contain the ephemeral public key, nonce, and the
    AES-GCM encrypted payload produced by :func:`ec_encrypt`.
    """

    if not ciphertext:
        raise DecryptionError("Ciphertext cannot be empty.")
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("Invalid X25519 private key provided.")
    if len(ciphertext) < 32 + 12 + 16:
        raise DecryptionError("Invalid ciphertext.")

    eph_pub_bytes = ciphertext[:32]
    nonce = ciphertext[32:44]
    enc = ciphertext[44:]

    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)

    if not constant_time.bytes_eq(
        eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        eph_pub_bytes,
    ):
        raise DecryptionError("Invalid ephemeral public key.")

    shared = private_key.exchange(eph_pub)
    if constant_time.bytes_eq(shared, b"\x00" * 32):
        raise DecryptionError("Invalid shared secret derived.")

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cryptography-suite-ecies",
    ).derive(shared)

    try:
        return AESGCM(key).decrypt(nonce, enc, None)
    except Exception as exc:  # pragma: no cover - high-level error handling
        raise DecryptionError(f"Decryption failed: {exc}") from exc
