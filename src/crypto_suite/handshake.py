from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
from typing import List


class Alert(Enum):
    """Alerts that may be raised during the handshake."""

    NoCommonKEM = "NoCommonKEM"


class HandshakeError(Exception):
    """Exception raised when a handshake alert occurs."""

    def __init__(self, alert: Alert):
        super().__init__(alert.value)
        self.alert = alert


@dataclass
class HandshakeHello:
    """Client or server hello message containing supported KEMs."""

    supported_kem: List[str]

    def serialize(self) -> bytes:
        return ",".join(self.supported_kem).encode()


class HandshakeContext:
    """Maintains a transcript hash for downgrade protection."""

    def __init__(self) -> None:
        self._hash = hashlib.sha256()

    def add_hello(self, hello: HandshakeHello) -> None:
        self._hash.update(hello.serialize())

    def finished_mac(self, secret: bytes, chosen_kem: str) -> bytes:
        self._hash.update(chosen_kem.encode())
        return hmac.new(secret, self._hash.digest(), hashlib.sha256).digest()


def negotiate_kem(client: HandshakeHello, server: HandshakeHello) -> str:
    """Return the first common KEM in server preference order.

    Raises:
        HandshakeError: if no common KEM exists.
    """

    for kem in server.supported_kem:
        if kem in client.supported_kem:
            return kem
    raise HandshakeError(Alert.NoCommonKEM)
