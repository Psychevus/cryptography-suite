import importlib
import sys
import types

import pytest
from cryptography_suite.errors import DecryptionError
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.exceptions import InvalidTag

from cryptography_suite.asymmetric import (
    ec_decrypt,
    ec_encrypt,
    generate_x25519_keypair,
)
from cryptography_suite.protocols import (
    SPAKE2Client,
    SPAKE2Server,
    initialize_signal_session,
    SignalReceiver,
    SignalSender,
)
from cryptography_suite.zk import zksnark


# ----------------------- SPAKE2 Tests -----------------------


def test_spake2_success():
    client = SPAKE2Client("secret")
    server = SPAKE2Server("secret")
    cm = client.generate_message()
    sm = server.generate_message()
    ck = client.compute_shared_key(sm)
    sk = server.compute_shared_key(cm)
    assert ck == sk


def test_spake2_incorrect_password():
    client = SPAKE2Client("secret")
    server = SPAKE2Server("other")
    cm = client.generate_message()
    sm = server.generate_message()
    ck = client.compute_shared_key(sm)
    sk = server.compute_shared_key(cm)
    assert ck != sk


def test_spake2_invalid_peer_message():
    client = SPAKE2Client("secret")
    client.generate_message()
    with pytest.raises(InvalidKey):
        client.compute_shared_key(b"bad")


# ------------------- Signal Protocol Tests ------------------


def test_signal_protocol_valid_flow():
    sender, receiver = initialize_signal_session()
    msg = b"hi"
    enc = sender.encrypt(msg)
    dec = receiver.decrypt(enc)
    assert dec == msg
    reply = b"ok"
    enc2 = receiver.encrypt(reply)
    assert sender.decrypt(enc2) == reply


def test_signal_protocol_tampered_ciphertext():
    sender, receiver = initialize_signal_session()
    enc = sender.encrypt(b"hi")
    tampered = types.SimpleNamespace(
        dh_public=enc.dh_public,
        nonce=enc.nonce,
        ciphertext=enc.ciphertext[:-1] + bytes([enc.ciphertext[-1] ^ 1]),
    )
    with pytest.raises(InvalidTag):
        receiver.decrypt(tampered)


def test_signal_protocol_wrong_receiver():
    sender, receiver = initialize_signal_session()
    other = SignalReceiver(x25519.X25519PrivateKey.generate())
    other.initialize_session(*sender.handshake_public)
    enc = sender.encrypt(b"hi")
    # other has different keys; decryption should fail
    with pytest.raises(Exception):
        other.decrypt(enc)


# ----------------------- ECIES Tests -----------------------


def test_ecies_roundtrip():
    priv, pub = generate_x25519_keypair()
    msg = b"top"
    ct = ec_encrypt(msg, pub)
    assert ec_decrypt(ct, priv) == msg


def test_ecies_wrong_key():
    priv, pub = generate_x25519_keypair()
    wrong_priv, _ = generate_x25519_keypair()
    ct = ec_encrypt(b"msg", pub)
    with pytest.raises(DecryptionError):
        ec_decrypt(ct, wrong_priv)


def test_ecies_tamper(monkeypatch):
    priv, pub = generate_x25519_keypair()
    ct = ec_encrypt(b"msg", pub)
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    with pytest.raises(DecryptionError):
        ec_decrypt(tampered, priv)


def test_ecies_deterministic(monkeypatch):
    priv, pub = generate_x25519_keypair()
    fake_priv = x25519.X25519PrivateKey.from_private_bytes(b"\x01" * 32)
    monkeypatch.setattr(x25519.X25519PrivateKey, "generate", lambda: fake_priv)
    import cryptography_suite.asymmetric as asym

    monkeypatch.setattr(asym, "urandom", lambda n: b"\x02" * n)
    ct1 = ec_encrypt(b"msg", pub)
    ct2 = ec_encrypt(b"msg", pub)
    assert ct1 == ct2


# --------------------- ZK-SNARK Tests ----------------------


class DummyPrivVal:
    def __init__(self, val):
        self.val = val


def dummy_sha256(secret):
    class Bits:
        def __init__(self, val):
            self.val = val

    return Bits(secret.val)


class DummySnark:
    @staticmethod
    def prove():
        return "proof"


class DummyRun:
    def __init__(self, result=True):
        self._result = result

    def verify(self, hash_hex, proof_path):
        return self._result


def _setup_pysnark(monkeypatch, result=True):
    runtime = types.SimpleNamespace(
        PrivVal=DummyPrivVal, snark=DummySnark, run=DummyRun(result)
    )
    hash_mod = types.SimpleNamespace(sha256=dummy_sha256)
    monkeypatch.setitem(sys.modules, "pysnark.runtime", runtime)
    monkeypatch.setitem(sys.modules, "pysnark.hash", hash_mod)
    monkeypatch.setitem(
        sys.modules, "pysnark", types.SimpleNamespace(snarksetup=lambda x: None)
    )
    import cryptography_suite.zk.zksnark as zk

    importlib.reload(zk)
    return zk


def test_zksnark_valid(monkeypatch):
    zk = _setup_pysnark(monkeypatch, True)
    zk.setup()
    digest, proof = zk.prove(b"x")
    assert zk.verify(digest, proof)


def test_zksnark_invalid_proof(monkeypatch):
    zk = _setup_pysnark(monkeypatch, False)
    zk.setup()
    digest, proof = zk.prove(b"x")
    assert not zk.verify(digest, proof)
