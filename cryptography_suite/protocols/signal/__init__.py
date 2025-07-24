"""Simplified Signal protocol implementation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from ...errors import ProtocolError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class EncryptedMessage:
    """Container for an encrypted message."""

    dh_public: bytes
    nonce: bytes
    ciphertext: bytes


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 helper used for key derivation."""

    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def _kdf_rk(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """Derive new root and chain keys from a DH output."""

    out = _hkdf(dh_out, root_key, b"dr_rk", 64)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Derive the next chain key and message key."""

    h = hmac.HMAC(chain_key, hashes.SHA256())
    h.update(b"0")
    next_ck = h.finalize()

    h = hmac.HMAC(chain_key, hashes.SHA256())
    h.update(b"1")
    mk = h.finalize()
    return next_ck, mk


def x3dh_initiator(
    id_priv: x25519.X25519PrivateKey,
    eph_priv: x25519.X25519PrivateKey,
    peer_id_pub: x25519.X25519PublicKey,
    peer_prekey_pub: x25519.X25519PublicKey,
) -> bytes:
    """Perform the initiator side of the X3DH key agreement."""

    dh1 = id_priv.exchange(peer_prekey_pub)
    dh2 = eph_priv.exchange(peer_id_pub)
    dh3 = eph_priv.exchange(peer_prekey_pub)
    master = dh1 + dh2 + dh3
    return _hkdf(master, None, b"x3dh", 32)


def x3dh_responder(
    id_priv: x25519.X25519PrivateKey,
    prekey_priv: x25519.X25519PrivateKey,
    peer_id_pub: x25519.X25519PublicKey,
    peer_eph_pub: x25519.X25519PublicKey,
) -> bytes:
    """Perform the responder side of the X3DH key agreement."""

    dh1 = prekey_priv.exchange(peer_id_pub)
    dh2 = id_priv.exchange(peer_eph_pub)
    dh3 = prekey_priv.exchange(peer_eph_pub)
    master = dh1 + dh2 + dh3
    return _hkdf(master, None, b"x3dh", 32)


class DoubleRatchet:
    """Minimal Double Ratchet implementation."""

    def __init__(
        self,
        root_key: bytes,
        dh_priv: x25519.X25519PrivateKey,
        remote_dh_pub: x25519.X25519PublicKey,
        initiator: bool,
    ) -> None:
        self.root_key = root_key
        self.dh_priv = dh_priv
        self.dh_pub = dh_priv.public_key()
        self.remote_dh_pub = remote_dh_pub
        if initiator:
            self.root_key, self.send_chain_key = _kdf_rk(
                self.root_key, self.dh_priv.exchange(self.remote_dh_pub)
            )
            self.recv_chain_key = None
        else:
            self.root_key, self.recv_chain_key = _kdf_rk(
                self.root_key, self.dh_priv.exchange(self.remote_dh_pub)
            )
            self.send_chain_key = None

    def _ratchet_step(self, new_remote_pub: x25519.X25519PublicKey) -> None:
        """Derive new keys when a new DH public key is received."""

        self.root_key, self.recv_chain_key = _kdf_rk(
            self.root_key, self.dh_priv.exchange(new_remote_pub)
        )
        self.remote_dh_pub = new_remote_pub
        self.dh_priv = x25519.X25519PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key()
        self.root_key, self.send_chain_key = _kdf_rk(
            self.root_key, self.dh_priv.exchange(self.remote_dh_pub)
        )

    def encrypt(self, plaintext: bytes) -> EncryptedMessage:
        """Encrypt ``plaintext`` and return an :class:`EncryptedMessage`."""

        if self.send_chain_key is None:
            self.dh_priv = x25519.X25519PrivateKey.generate()
            self.dh_pub = self.dh_priv.public_key()
            self.root_key, self.send_chain_key = _kdf_rk(
                self.root_key, self.dh_priv.exchange(self.remote_dh_pub)
            )

        self.send_chain_key, msg_key = _kdf_ck(self.send_chain_key)
        nonce = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext, None)
        return EncryptedMessage(
            dh_public=self.dh_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt(self, message: EncryptedMessage) -> bytes:
        """Decrypt a received :class:`EncryptedMessage`."""

        remote_pub = x25519.X25519PublicKey.from_public_bytes(message.dh_public)
        if (
            self.remote_dh_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            != message.dh_public
        ):
            self._ratchet_step(remote_pub)

        if self.recv_chain_key is None:
            raise ProtocolError("No receiving chain key available")

        self.recv_chain_key, msg_key = _kdf_ck(self.recv_chain_key)
        return AESGCM(msg_key).decrypt(message.nonce, message.ciphertext, None)


class SignalSender:
    """Sender that initiates a Signal session."""

    def __init__(
        self,
        identity_priv: x25519.X25519PrivateKey,
        peer_identity_pub: x25519.X25519PublicKey,
        peer_prekey_pub: x25519.X25519PublicKey,
    ) -> None:
        self.identity_priv = identity_priv
        self.identity_pub = identity_priv.public_key()
        self.ephemeral_priv = x25519.X25519PrivateKey.generate()
        root = x3dh_initiator(
            self.identity_priv,
            self.ephemeral_priv,
            peer_identity_pub,
            peer_prekey_pub,
        )
        self.ratchet = DoubleRatchet(root, self.ephemeral_priv, peer_prekey_pub, True)

    @property
    def handshake_public(self) -> Tuple[bytes, bytes]:
        """Return identity and ephemeral public bytes for the handshake."""

        return (
            self.identity_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            self.ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def encrypt(self, plaintext: bytes) -> EncryptedMessage:
        """Encrypt a message for the receiver."""

        return self.ratchet.encrypt(plaintext)

    def decrypt(self, message: EncryptedMessage) -> bytes:
        """Decrypt a message from the receiver."""

        return self.ratchet.decrypt(message)


class SignalReceiver:
    """Receiver that responds to a Signal session."""

    def __init__(self, identity_priv: x25519.X25519PrivateKey) -> None:
        self.identity_priv = identity_priv
        self.identity_pub = identity_priv.public_key()
        self.prekey_priv = x25519.X25519PrivateKey.generate()
        self.prekey_pub = self.prekey_priv.public_key()
        self.ratchet: DoubleRatchet | None = None

    @property
    def public_bundle(self) -> Tuple[bytes, bytes]:
        """Return identity and prekey public bytes."""

        return (
            self.identity_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            self.prekey_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def initialize_session(
        self, sender_identity_pub: bytes, sender_eph_pub: bytes
    ) -> None:
        """Complete the handshake using the sender's public keys."""

        sid_pub = x25519.X25519PublicKey.from_public_bytes(sender_identity_pub)
        seph_pub = x25519.X25519PublicKey.from_public_bytes(sender_eph_pub)
        root = x3dh_responder(self.identity_priv, self.prekey_priv, sid_pub, seph_pub)
        self.ratchet = DoubleRatchet(root, self.prekey_priv, seph_pub, False)

    def encrypt(self, plaintext: bytes) -> EncryptedMessage:
        """Encrypt a message for the sender."""

        if self.ratchet is None:
            raise ProtocolError("Session not initialized")
        return self.ratchet.encrypt(plaintext)

    def decrypt(self, message: EncryptedMessage) -> bytes:
        """Decrypt a message from the sender."""

        if self.ratchet is None:
            raise ProtocolError("Session not initialized")
        return self.ratchet.decrypt(message)


def initialize_signal_session() -> Tuple[SignalSender, SignalReceiver]:
    """Convenience function to create two parties with a shared session."""

    sender_id_priv = x25519.X25519PrivateKey.generate()
    receiver_id_priv = x25519.X25519PrivateKey.generate()
    receiver = SignalReceiver(receiver_id_priv)
    sender = SignalSender(
        sender_id_priv,
        x25519.X25519PublicKey.from_public_bytes(receiver.public_bundle[0]),
        x25519.X25519PublicKey.from_public_bytes(receiver.public_bundle[1]),
    )
    receiver.initialize_session(*sender.handshake_public)
    return sender, receiver
