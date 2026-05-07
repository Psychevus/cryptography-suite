from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from ..errors import MissingDependencyError, ProtocolError

SPAKE2_A: Any | None = None
SPAKE2_B: Any | None = None


def _require_spake2() -> tuple[Any, Any]:
    global SPAKE2_A, SPAKE2_B
    if SPAKE2_A is None or SPAKE2_B is None:
        try:
            from spake2 import SPAKE2_A as spake2_a
            from spake2 import SPAKE2_B as spake2_b
        except Exception as exc:  # pragma: no cover - dependency missing
            raise MissingDependencyError(
                "SPAKE2 PAKE support requires spake2. "
                "Install cryptography-suite[pake] to use this feature."
            ) from exc
        SPAKE2_A = spake2_a
        SPAKE2_B = spake2_b
    return SPAKE2_A, SPAKE2_B


class SPAKE2Party:
    """
    Base class for SPAKE2 protocol parties.
    """

    def __init__(self, password: str):
        if not password:
            raise ProtocolError("Password cannot be empty.")
        self.password = password
        self.private_key: x25519.X25519PrivateKey | None = None
        self.public_key: x25519.X25519PublicKey | bytes | None = None
        self.shared_key: bytes | None = None

    def generate_message(self) -> bytes:
        """
        Generates the party's public key to send to the other party.
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key = public_key
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """
        Computes the shared key using the peer's public key.
        """
        if self.private_key is None:
            raise ProtocolError(
                "generate_message() must be called before compute_shared_key()."
            )
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                peer_public_bytes
            )
        except (ValueError, TypeError) as exc:
            raise InvalidKey(f"Invalid peer public key: {exc}") from exc
        shared_key = self.private_key.exchange(peer_public_key)
        self.shared_key = shared_key
        return shared_key

    def get_shared_key(self) -> bytes:
        """
        Returns the computed shared key.
        """
        if self.shared_key is None:
            raise ProtocolError("Shared key has not been computed yet.")
        return self.shared_key


class SPAKE2Client(SPAKE2Party):
    """
    Client-side implementation of the SPAKE2 protocol.
    """

    def __init__(self, password: str):
        super().__init__(password)
        spake2_a, _ = _require_spake2()
        self._spake = spake2_a(password.encode())

    def generate_message(self) -> bytes:
        """Generates the client's SPAKE2 message."""
        public_message = self._spake.start()
        self.public_key = public_message
        return bytes(public_message)

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """Computes the shared key using the server's message."""
        if self.public_key is None:
            raise ProtocolError(
                "generate_message() must be called before compute_shared_key()."
            )
        try:
            shared_key = self._spake.finish(peer_public_bytes)
        except Exception as exc:
            raise InvalidKey(str(exc)) from exc
        self.shared_key = bytes(shared_key)
        return self.shared_key


class SPAKE2Server(SPAKE2Party):
    """
    Server-side implementation of the SPAKE2 protocol.
    """

    def __init__(self, password: str):
        super().__init__(password)
        _, spake2_b = _require_spake2()
        self._spake = spake2_b(password.encode())

    def generate_message(self) -> bytes:
        """Generates the server's SPAKE2 message."""
        public_message = self._spake.start()
        self.public_key = public_message
        return bytes(public_message)

    def compute_shared_key(self, peer_public_bytes: bytes) -> bytes:
        """Computes the shared key using the client's message."""
        if self.public_key is None:
            raise ProtocolError(
                "generate_message() must be called before compute_shared_key()."
            )
        try:
            shared_key = self._spake.finish(peer_public_bytes)
        except Exception as exc:
            raise InvalidKey(str(exc)) from exc
        self.shared_key = bytes(shared_key)
        return self.shared_key
