from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from spake2 import SPAKE2_A, SPAKE2_B, SPAKEError


class SPAKE2Party:
    """
    Base class for SPAKE2 protocol parties.
    """

    def __init__(self, password: str):
        if not password:
            raise ValueError("Password cannot be empty.")
        self.password = password
        self.private_key = None
        self.public_key = None
        self.shared_key = None

    def generate_message(self) -> bytes:
        """
        Generates the party's public key to send to the other party.
        """
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """
        Computes the shared key using the peer's public key.
        """
        if self.private_key is None:
            raise ValueError("generate_message() must be called before compute_shared_key().")
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        except (ValueError, TypeError) as e:
            raise InvalidKey(f"Invalid peer public key: {e}")
        self.shared_key = self.private_key.exchange(peer_public_key)
        return self.shared_key

    def get_shared_key(self) -> bytes:
        """
        Returns the computed shared key.
        """
        if self.shared_key is None:
            raise ValueError("Shared key has not been computed yet.")
        return self.shared_key


class SPAKE2Client(SPAKE2Party):
    """
    Client-side implementation of the SPAKE2 protocol.
    """
    def __init__(self, password: str):
        super().__init__(password)
        self._spake = SPAKE2_A(password.encode())

    def generate_message(self) -> bytes:
        """Generates the client's SPAKE2 message."""
        self.public_key = self._spake.start()
        return self.public_key

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """Computes the shared key using the server's message."""
        if self.public_key is None:
            raise ValueError("generate_message() must be called before compute_shared_key().")
        try:
            self.shared_key = self._spake.finish(peer_public_bytes)
        except SPAKEError as e:
            raise InvalidKey(str(e))
        return self.shared_key


class SPAKE2Server(SPAKE2Party):
    """
    Server-side implementation of the SPAKE2 protocol.
    """
    def __init__(self, password: str):
        super().__init__(password)
        self._spake = SPAKE2_B(password.encode())

    def generate_message(self) -> bytes:
        """Generates the server's SPAKE2 message."""
        self.public_key = self._spake.start()
        return self.public_key

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """Computes the shared key using the client's message."""
        if self.public_key is None:
            raise ValueError("generate_message() must be called before compute_shared_key().")
        try:
            self.shared_key = self._spake.finish(peer_public_bytes)
        except SPAKEError as e:
            raise InvalidKey(str(e))
        return self.shared_key
