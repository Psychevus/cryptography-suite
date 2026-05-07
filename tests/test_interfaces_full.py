import base64
import importlib
import os
import sys
import types
from typing import Any

import pytest

if not os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
    pytest.skip("experimental features disabled", allow_module_level=True)
import warnings

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519

from cryptography_suite.asymmetric import (
    ec_decrypt,
    ec_encrypt,
    generate_x25519_keypair,
)
from cryptography_suite.errors import DecryptionError
from cryptography_suite.experimental.signal_demo import (
    SignalReceiver,
    initialize_signal_session,
)

# ----------------------- SPAKE2 Tests -----------------------


def _spake2_classes() -> tuple[type[Any], type[Any]]:
    pytest.importorskip("spake2", reason="requires pake extra")
    from cryptography_suite.protocols import SPAKE2Client, SPAKE2Server

    return SPAKE2Client, SPAKE2Server


def test_spake2_success() -> None:
    spake2_client, spake2_server = _spake2_classes()
    client = spake2_client("secret")
    server = spake2_server("secret")
    cm = client.generate_message()
    sm = server.generate_message()
    ck = client.compute_shared_key(sm)
    sk = server.compute_shared_key(cm)
    assert ck == sk


def test_spake2_incorrect_password() -> None:
    spake2_client, spake2_server = _spake2_classes()
    client = spake2_client("secret")
    server = spake2_server("other")
    cm = client.generate_message()
    sm = server.generate_message()
    ck = client.compute_shared_key(sm)
    sk = server.compute_shared_key(cm)
    assert ck != sk


def test_spake2_invalid_peer_message() -> None:
    spake2_client, _ = _spake2_classes()
    client = spake2_client("secret")
    client.generate_message()
    with pytest.raises(InvalidKey):
        client.compute_shared_key(b"bad")


# ------------------- Signal Protocol Tests ------------------


def test_signal_protocol_valid_flow() -> None:
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        sender, receiver = initialize_signal_session()
    assert any("Signal Protocol" in str(wi.message) for wi in w)
    msg = b"hi"
    enc = sender.encrypt(msg)
    dec = receiver.decrypt(enc)
    assert dec == msg
    reply = b"ok"
    enc2 = receiver.encrypt(reply)
    assert sender.decrypt(enc2) == reply


def test_signal_protocol_tampered_ciphertext() -> None:
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        sender, receiver = initialize_signal_session()
    assert any("Signal Protocol" in str(wi.message) for wi in w)
    enc = sender.encrypt(b"hi")
    tampered = types.SimpleNamespace(
        dh_public=enc.dh_public,
        nonce=enc.nonce,
        ciphertext=enc.ciphertext[:-1] + bytes([enc.ciphertext[-1] ^ 1]),
    )
    with pytest.raises(InvalidTag):
        receiver.decrypt(tampered)


def test_signal_protocol_wrong_receiver() -> None:
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        sender, receiver = initialize_signal_session()
        other = SignalReceiver(x25519.X25519PrivateKey.generate())
    assert any("Signal Protocol" in str(wi.message) for wi in w)
    other.initialize_session(*sender.handshake_public)
    enc = sender.encrypt(b"hi")
    # other has different keys; decryption should fail
    with pytest.raises(InvalidTag):
        other.decrypt(enc)


# ----------------------- ECIES Tests -----------------------


def test_ecies_roundtrip() -> None:
    priv, pub = generate_x25519_keypair()
    msg = b"top"
    ct = ec_encrypt(msg, pub)
    assert isinstance(ct, str)
    assert ec_decrypt(ct, priv) == msg


def test_ecies_wrong_key() -> None:
    priv, pub = generate_x25519_keypair()
    wrong_priv, _ = generate_x25519_keypair()
    ct = ec_encrypt(b"msg", pub)
    with pytest.raises(DecryptionError):
        ec_decrypt(ct, wrong_priv)


def test_ecies_tamper(monkeypatch: pytest.MonkeyPatch) -> None:
    priv, pub = generate_x25519_keypair()
    ct = ec_encrypt(b"msg", pub)
    raw = base64.b64decode(ct)
    tampered = raw[:-1] + bytes([raw[-1] ^ 1])
    tampered_b64 = base64.b64encode(tampered).decode()
    with pytest.raises(DecryptionError):
        ec_decrypt(tampered_b64, priv)


def test_ecies_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
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
    def __init__(self, val: Any) -> None:
        self.val = val


def dummy_sha256(secret: DummyPrivVal) -> Any:
    class Bits:
        def __init__(self, val: Any) -> None:
            self.val = val

    return Bits(secret.val)


class DummySnark:
    @staticmethod
    def prove() -> str:
        return "proof"


class DummyRun:
    def __init__(self, result: bool = True) -> None:
        self._result = result

    def verify(self, hash_hex: str, proof_path: str) -> bool:
        return self._result


def _setup_pysnark(
    monkeypatch: pytest.MonkeyPatch, result: bool = True
) -> types.ModuleType:
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


def test_zksnark_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    zk = _setup_pysnark(monkeypatch, True)
    zk.setup()
    digest, proof = zk.prove(b"x")
    assert zk.verify(digest, proof)


def test_zksnark_invalid_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    zk = _setup_pysnark(monkeypatch, False)
    zk.setup()
    digest, proof = zk.prove(b"x")
    assert not zk.verify(digest, proof)
