"""Simplified Signal protocol demonstration (X3DH + Double Ratchet).

This implementation is a simplified demonstration of the Signal protocol
(X3DH + Double Ratchet) and is NOT production-grade. It omits important
features (multi-session, message headers, robust identity binding, etc.)
and is suitable only for research, prototyping, or education. Do not use
for real secure messaging.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from ...errors import ProtocolError
from ...debug import verbose_print
from ...asymmetric.signatures import sign_message
from .init_session import verify_signed_prekey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


WARNING_MSG = (
    "Signal Protocol demo: This implementation is not production-grade and "
    "omits critical features (multi-session, message headers, robust identity "
    "binding, etc.). Use only for research, prototyping, or education. Do not "
    "use for real secure messaging."
)

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
    opk_priv: x25519.X25519PrivateKey | None = None,
) -> bytes:
    """Perform the initiator side of the X3DH key agreement."""

    dh1 = id_priv.exchange(peer_prekey_pub)
    verbose_print(f"DH1: {dh1.hex()}")
    dh2 = eph_priv.exchange(peer_id_pub)
    verbose_print(f"DH2: {dh2.hex()}")
    dh3 = eph_priv.exchange(peer_prekey_pub)
    verbose_print(f"DH3: {dh3.hex()}")
    master = dh1 + dh2 + dh3
    if opk_priv is not None:
        dh4 = opk_priv.exchange(peer_id_pub)
        verbose_print(f"DH4: {dh4.hex()}")
        master += dh4
    return _hkdf(master, None, b"x3dh", 32)


def x3dh_responder(
    id_priv: x25519.X25519PrivateKey,
    prekey_priv: x25519.X25519PrivateKey,
    peer_id_pub: x25519.X25519PublicKey,
    peer_eph_pub: x25519.X25519PublicKey,
    peer_opk_pub: x25519.X25519PublicKey | None = None,
) -> bytes:
    """Perform the responder side of the X3DH key agreement."""

    dh1 = prekey_priv.exchange(peer_id_pub)
    verbose_print(f"DH1: {dh1.hex()}")
    dh2 = id_priv.exchange(peer_eph_pub)
    verbose_print(f"DH2: {dh2.hex()}")
    dh3 = prekey_priv.exchange(peer_eph_pub)
    verbose_print(f"DH3: {dh3.hex()}")
    master = dh1 + dh2 + dh3
    if peer_opk_pub is not None:
        dh4 = id_priv.exchange(peer_opk_pub)
        verbose_print(f"DH4: {dh4.hex()}")
        master += dh4
    return _hkdf(master, None, b"x3dh", 32)


class DoubleRatchet:
    """Minimal Double Ratchet implementation.

    This class backs the experimental Signal protocol demo and is **not**
    production-grade. It omits features like skipped-message handling and
    header encryption. Suitable only for research, prototyping, or education.
    """

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
    """Sender that initiates a Signal session.

    WARNING: This implementation is a simplified demonstration of the Signal
    protocol (X3DH + Double Ratchet) and is NOT production-grade. It omits
    important features (multi-session, message headers, robust identity
    binding, etc.) and is suitable only for research, prototyping, or
    education. Do not use for real secure messaging.
    """

    def __init__(
        self,
        identity_priv: x25519.X25519PrivateKey,
        peer_identity_pub: x25519.X25519PublicKey,
        peer_prekey_pub: x25519.X25519PublicKey,
        *,
        use_one_time_prekey: bool = False,
    ) -> None:
        warnings.warn(WARNING_MSG, UserWarning, stacklevel=2)
        self.identity_priv = identity_priv
        self.identity_pub = identity_priv.public_key()
        self.ephemeral_priv = x25519.X25519PrivateKey.generate()
        self.signed_prekey_priv = x25519.X25519PrivateKey.generate()
        self.one_time_priv = x25519.X25519PrivateKey.generate() if use_one_time_prekey else None
        sign_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            self.identity_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.sign_pub = sign_key.public_key()
        self.signed_prekey_sig = sign_message(
            self.signed_prekey_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            sign_key,
            raw_output=True,
        )
        root = x3dh_initiator(
            self.identity_priv,
            self.ephemeral_priv,
            peer_identity_pub,
            peer_prekey_pub,
            self.one_time_priv,
        )
        self.ratchet = DoubleRatchet(root, self.ephemeral_priv, peer_prekey_pub, True)

    @property
    def handshake_public(self) -> Tuple[bytes, bytes, bytes, bytes, bytes | None, bytes]:
        """Return all public handshake bytes including signatures."""

        return self.handshake_bundle

    @property
    def handshake_bundle(self) -> Tuple[bytes, bytes, bytes, bytes, bytes | None, bytes]:
        """Return all public handshake data including signatures."""

        opk = (
            self.one_time_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if self.one_time_priv
            else None
        )
        return (
            self.identity_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            self.ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            self.signed_prekey_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            self.signed_prekey_sig,
            opk,
            self.sign_pub.public_bytes(
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
    """Receiver that responds to a Signal session.

    WARNING: This implementation is a simplified demonstration of the Signal
    protocol (X3DH + Double Ratchet) and is NOT production-grade. It omits
    important features (multi-session, message headers, robust identity
    binding, etc.) and is suitable only for research, prototyping, or
    education. Do not use for real secure messaging.
    """

    def __init__(self, identity_priv: x25519.X25519PrivateKey) -> None:
        warnings.warn(WARNING_MSG, UserWarning, stacklevel=2)
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
        self,
        sender_identity_pub: bytes,
        sender_eph_pub: bytes,
        sender_signed_prekey: bytes,
        prekey_signature: bytes,
        sender_one_time_prekey: bytes | None = None,
        sender_signing_pub: bytes = b"",
    ) -> None:
        """Complete the handshake using the sender's public keys."""

        id_verify = ed25519.Ed25519PublicKey.from_public_bytes(
            sender_signing_pub or sender_identity_pub
        )
        verify_signed_prekey(sender_signed_prekey, prekey_signature, id_verify)

        sid_pub = x25519.X25519PublicKey.from_public_bytes(sender_identity_pub)
        seph_pub = x25519.X25519PublicKey.from_public_bytes(sender_eph_pub)
        opk_pub = (
            x25519.X25519PublicKey.from_public_bytes(sender_one_time_prekey)
            if sender_one_time_prekey
            else None
        )
        root = x3dh_responder(
            self.identity_priv,
            self.prekey_priv,
            sid_pub,
            seph_pub,
            opk_pub,
        )
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


def initialize_signal_session(*, use_one_time_prekey: bool = False) -> Tuple[SignalSender, SignalReceiver]:
    """Convenience function to create two parties with a shared session.

    WARNING: This implementation is a simplified demonstration of the Signal
    protocol (X3DH + Double Ratchet) and is NOT production-grade. It omits
    important features (multi-session, message headers, robust identity
    binding, etc.) and is suitable only for research, prototyping, or
    education. Do not use for real secure messaging.
    """

    sender_id_priv = x25519.X25519PrivateKey.generate()
    receiver_id_priv = x25519.X25519PrivateKey.generate()
    warnings.warn(WARNING_MSG, UserWarning, stacklevel=2)
    receiver = SignalReceiver(receiver_id_priv)
    sender = SignalSender(
        sender_id_priv,
        x25519.X25519PublicKey.from_public_bytes(receiver.public_bundle[0]),
        x25519.X25519PublicKey.from_public_bytes(receiver.public_bundle[1]),
        use_one_time_prekey=use_one_time_prekey,
    )
    receiver.initialize_session(*sender.handshake_bundle)
    return sender, receiver
