import importlib
import sys
import types
import pytest

class DummyKEM:
    @staticmethod
    def generate_keypair():
        return b"pk", b"sk"
    @staticmethod
    def encrypt(pk):
        return b"ct", b"ss"
    @staticmethod
    def decrypt(sk, ct):
        return b"ss"

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

kem_mod = types.SimpleNamespace(ml_kem_512=DummyKEM, ml_kem_768=DummyKEM, ml_kem_1024=DummyKEM)
sign_mod = types.SimpleNamespace(ml_dsa_44=DummySIG, ml_dsa_65=DummySIG, ml_dsa_87=DummySIG)


def reload_module(monkeypatch):
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
    pk, sk = pqc.generate_kyber_keypair()
    ct, ss = pqc.kyber_encapsulate(pk)
    assert pqc.kyber_decapsulate(ct, sk) == ss
    pk2, sk2 = pqc.generate_dilithium_keypair()
    sig = pqc.dilithium_sign(b"m", sk2)
    assert pqc.dilithium_verify(b"m", sig, pk2)
    with pytest.raises(ValueError):
        pqc.generate_kyber_keypair(999)
    with pytest.raises(ValueError):
        pqc.kyber_encapsulate(pk, 999)
    with pytest.raises(ValueError):
        pqc.kyber_decapsulate(ct, sk, 999)
    with pytest.raises(ValueError):
        pqc.generate_dilithium_keypair(0)
    with pytest.raises(ValueError):
        pqc.dilithium_sign(b"m", sk2, 0)
    with pytest.raises(ValueError):
        pqc.dilithium_verify(b"m", b"x", pk2, 0)


def test_pqc_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pqcrypto", None)
    import cryptography_suite.pqc as pqc
    importlib.reload(pqc)
    pqc.PQCRYPTO_AVAILABLE = False
    with pytest.raises(ImportError):
        pqc.generate_kyber_keypair()
