import importlib
import sys
import types
from typing import Any

import pytest


class DummyKEM:
    CIPHERTEXT = b"ct"
    SECRET = b"stub shared secret marker"
    CIPHERTEXT_SIZE = len(CIPHERTEXT)

    @staticmethod
    def generate_keypair():
        return b"pk", b"sk"

    @staticmethod
    def encrypt(pk):
        return DummyKEM.CIPHERTEXT, DummyKEM.SECRET

    @staticmethod
    def decrypt(sk, ct):
        if sk != b"sk" or ct != DummyKEM.CIPHERTEXT:
            raise ValueError("bad KEM ciphertext")
        return DummyKEM.SECRET


class DummySIG:
    @staticmethod
    def generate_keypair():
        return b"pk", b"sk"

    @staticmethod
    def sign(sk, msg):
        return b"sig"

    @staticmethod
    def verify(pk, msg, sig):
        return sig == b"sig"


kem_mod = types.SimpleNamespace(
    ml_kem_512=DummyKEM, ml_kem_768=DummyKEM, ml_kem_1024=DummyKEM
)
sign_mod = types.SimpleNamespace(
    ml_dsa_44=DummySIG, ml_dsa_65=DummySIG, ml_dsa_87=DummySIG
)


def reload_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    pq = types.SimpleNamespace(kem=kem_mod, sign=sign_mod)
    monkeypatch.setitem(sys.modules, "pqcrypto", pq)
    monkeypatch.setitem(sys.modules, "pqcrypto.kem", kem_mod)
    monkeypatch.setitem(sys.modules, "pqcrypto.kem.ml_kem_512", DummyKEM)
    monkeypatch.setitem(sys.modules, "pqcrypto.kem.ml_kem_768", DummyKEM)
    monkeypatch.setitem(sys.modules, "pqcrypto.kem.ml_kem_1024", DummyKEM)
    monkeypatch.setitem(sys.modules, "pqcrypto.sign", sign_mod)
    monkeypatch.setitem(sys.modules, "pqcrypto.sign.ml_dsa_44", DummySIG)
    monkeypatch.setitem(sys.modules, "pqcrypto.sign.ml_dsa_65", DummySIG)
    monkeypatch.setitem(sys.modules, "pqcrypto.sign.ml_dsa_87", DummySIG)
    import cryptography_suite.pqc as pqc

    importlib.reload(pqc)
    return pqc


def test_pqc_key_enc_sign(monkeypatch):
    pqc = reload_module(monkeypatch)
    for lvl in (512, 768, 1024):
        pk, sk = pqc.generate_ml_kem_keypair(level=lvl)
        envelope = pqc.ml_kem_encrypt(pk, b"m", level=lvl)
        assert isinstance(envelope, str)
        assert not isinstance(envelope, tuple)
        assert DummyKEM.SECRET not in envelope.encode()
        assert pqc.ml_kem_decrypt(sk, envelope, level=lvl) == b"m"

        with pytest.warns(DeprecationWarning):
            compat_envelope = pqc.kyber_encrypt(pk, b"m", level=lvl)
        assert isinstance(compat_envelope, str)
        assert not isinstance(compat_envelope, tuple)
        with pytest.warns(DeprecationWarning):
            assert pqc.kyber_decrypt(sk, compat_envelope, b"ignored", level=lvl) == b"m"
    pk2, sk2 = pqc.generate_dilithium_keypair()
    sig = pqc.dilithium_sign(sk2, b"m")
    assert isinstance(sig, str)
    assert pqc.dilithium_verify(pk2, b"m", sig)


def test_pqc_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pqcrypto", None)
    import cryptography_suite.pqc as pqc

    importlib.reload(pqc)
    pqc.PQCRYPTO_AVAILABLE = False
    with pytest.raises(ImportError):
        pqc.generate_ml_kem_keypair()
