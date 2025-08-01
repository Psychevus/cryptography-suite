import os
from ..utils import deprecated
from cryptography.hazmat.primitives import serialization
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
from ..asymmetric.signatures import (
    generate_ed25519_keypair,
    generate_ed448_keypair,
)
from ..errors import DecryptionError

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
        with open(filepath, "wb") as key_file:
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

    with open(filepath, "rb") as key_file:
        pem_data = key_file.read()
    return load_private_key(pem_data, password)


def load_public_key_from_file(filepath: str):
    """
    Loads a PEM-encoded public key from a file.
    """
    if not path.exists(filepath):
        raise FileNotFoundError(f"Public key file {filepath} does not exist.")

    with open(filepath, "rb") as key_file:
        pem_data = key_file.read()
    return load_public_key(pem_data)


def key_exists(filepath: str) -> bool:
    """
    Checks if a key file exists at the given filepath.
    """
    return path.exists(filepath)


@deprecated("generate_rsa_keypair_and_save is deprecated; use KeyManager.generate_rsa_keypair_and_save")
def generate_rsa_keypair_and_save(
    private_key_path: str,
    public_key_path: str,
    password: str,
    key_size: int = 4096,
):
    """Legacy wrapper for :class:`KeyManager` RSA key generation.

    .. deprecated:: 2.0.0
       Use :class:`KeyManager.generate_rsa_keypair_and_save` instead.
    """

    km = KeyManager()
    return km.generate_rsa_keypair_and_save(
        private_key_path, public_key_path, password, key_size
    )


@deprecated(
    "generate_ec_keypair_and_save is deprecated; "
    "use KeyManager.generate_ec_keypair_and_save"
)
def generate_ec_keypair_and_save(
    private_key_path: str,
    public_key_path: str,
    password: str,
    curve: ec.EllipticCurve = ec.SECP256R1(),
):
    """Legacy wrapper for :class:`KeyManager` EC key generation."""

    km = KeyManager()
    return km.generate_ec_keypair_and_save(
        private_key_path, public_key_path, password, curve
    )


class KeyManager:
    """Utility class for handling private key storage and rotation."""

    def save_private_key(
        self, private_key, filepath: str, password: str | None = None
    ) -> None:
        """Save a private key in PEM format.

        If ``password`` is provided the key is wrapped using AES-256-CBC.
        """

        if password:
            encryption: serialization.KeySerializationEncryption = (
                serialization.BestAvailableEncryption(password.encode())
            )
        else:
            encryption = serialization.NoEncryption()

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        secure_save_key_to_file(pem_data, filepath)

    def load_private_key(self, filepath: str, password: str | None = None):
        """Load a private key from ``filepath``.

        ``password`` should be provided if the key is encrypted.
        """

        if not path.exists(filepath):
            raise FileNotFoundError(f"Private key file {filepath} does not exist.")

        with open(filepath, "rb") as key_file:
            pem_data = key_file.read()

        pwd = password.encode() if password else None
        try:
            return serialization.load_pem_private_key(pem_data, password=pwd)
        except Exception as exc:  # pragma: no cover - defensive
            raise DecryptionError(f"Failed to load private key: {exc}") from exc

    def rotate_keys(self, key_dir: str) -> None:
        """Generate a new RSA key pair replacing any existing pair in ``key_dir``."""

        private_path = os.path.join(key_dir, "private_key.pem")
        public_path = os.path.join(key_dir, "public_key.pem")

        if path.exists(private_path):
            os.remove(private_path)
        if path.exists(public_path):
            os.remove(public_path)

        private_key, public_key = generate_rsa_keypair()
        self.save_private_key(private_key, private_path)
        secure_save_key_to_file(
            serialize_public_key(public_key),
            public_path,
        )

    def generate_rsa_keypair_and_save(
        self,
        private_key_path: str,
        public_key_path: str,
        password: str,
        key_size: int = 4096,
    ):
        """Generate an RSA key pair and save to ``private_key_path`` and ``public_key_path``."""

        private_key, public_key = generate_rsa_keypair(key_size=key_size)
        private_pem = serialize_private_key(private_key, password)
        public_pem = serialize_public_key(public_key)
        secure_save_key_to_file(private_pem, private_key_path)
        secure_save_key_to_file(public_pem, public_key_path)
        return private_key, public_key

    def generate_ec_keypair_and_save(
        self,
        private_key_path: str,
        public_key_path: str,
        password: str,
        curve: ec.EllipticCurve = ec.SECP256R1(),
    ):
        """Generate an EC key pair and save to ``private_key_path`` and ``public_key_path``."""

        private_key, public_key = generate_ec_keypair(curve=curve)
        private_pem = serialize_private_key(private_key, password)
        public_pem = serialize_public_key(public_key)
        secure_save_key_to_file(private_pem, private_key_path)
        secure_save_key_to_file(public_pem, public_key_path)
        return private_key, public_key

    def generate_ed25519_keypair_and_save(
        self,
        private_key_path: str,
        public_key_path: str,
        password: str,
    ):
        """Generate an Ed25519 key pair and save to disk."""

        private_key, public_key = generate_ed25519_keypair()
        private_pem = serialize_private_key(private_key, password)
        public_pem = serialize_public_key(public_key)
        secure_save_key_to_file(private_pem, private_key_path)
        secure_save_key_to_file(public_pem, public_key_path)
        return private_key, public_key

    def generate_ed448_keypair_and_save(
        self,
        private_key_path: str,
        public_key_path: str,
        password: str,
    ):
        """Generate an Ed448 key pair and save to disk."""

        private_key, public_key = generate_ed448_keypair()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        secure_save_key_to_file(private_pem, private_key_path)
        secure_save_key_to_file(public_pem, public_key_path)
        return private_key, public_key
