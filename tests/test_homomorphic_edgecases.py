import importlib
import importlib
import sys
import types
import pytest
from cryptography_suite.errors import EncryptionError


class FakePyCtxt:
    def __init__(self, value):
        self.value = value

    def __add__(self, other):
        return FakePyCtxt(self.value + other.value)

    def __mul__(self, other):
        return FakePyCtxt(self.value * other.value)


class FakePyfhel:
    def __init__(self):
        self.scheme = None

    def contextGen(self, scheme=None, **kwargs):
        self.scheme = scheme

    def keyGen(self):
        pass

    def encryptFrac(self, value):
        return FakePyCtxt(value)

    def decryptFrac(self, ctxt):
        return [ctxt.value]

    def encryptInt(self, value):
        return FakePyCtxt(value)

    def decryptInt(self, ctxt):
        return ctxt.value


fake_module = types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=FakePyfhel)


def reload_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "Pyfhel", fake_module)
    import cryptography_suite.homomorphic as h
    importlib.reload(h)
    return h

class FakePyfhelList(FakePyfhel):
    """Return list intact when decrypting for CKKS."""
    def decryptFrac(self, ctxt):
        return ctxt.value

class TrackFakePyfhel(FakePyfhel):
    def __init__(self):
        super().__init__()
        self.enc_frac_called = False
        self.enc_int_called = False
        self.dec_frac_called = False
        self.dec_int_called = False

    def encryptFrac(self, value):
        self.enc_frac_called = True
        return super().encryptFrac(value)

    def encryptInt(self, value):
        self.enc_int_called = True
        return super().encryptInt(value)

    def decryptFrac(self, ctxt):
        self.dec_frac_called = True
        return super().decryptFrac(ctxt)

    def decryptInt(self, ctxt):
        self.dec_int_called = True
        return super().decryptInt(ctxt)


def test_keygen_case_insensitive(monkeypatch):
    h = reload_module(monkeypatch)
    he = h.keygen("ckks")
    assert he.scheme == "CKKS"
    he = h.keygen("bFv")
    assert he.scheme == "BFV"
    with pytest.raises(EncryptionError):
        h.keygen("unsupported")


def test_encrypt_decrypt_iterable_ckks(monkeypatch):
    fake_module = types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=FakePyfhelList)
    monkeypatch.setitem(sys.modules, "Pyfhel", fake_module)
    import cryptography_suite.homomorphic as h
    importlib.reload(h)
    he = h.keygen("CKKS")
    values = [1.1, -2.2, 3.3]
    ct = h.encrypt(he, values)
    assert isinstance(ct, FakePyCtxt)
    assert h.decrypt(he, ct) == values


def test_large_integer_operations(monkeypatch):
    h = reload_module(monkeypatch)
    he = h.keygen("BFV")
    big = 2 ** 60
    ct1 = h.encrypt(he, big)
    ct2 = h.encrypt(he, big)
    assert h.decrypt(he, ct1) == big
    added = h.add(he, ct1, ct2)
    multiplied = h.multiply(he, ct1, ct2)
    assert added.value == big * 2
    assert multiplied.value == big ** 2


def test_unknown_scheme_uses_integer_ops(monkeypatch):
    fake_module = types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=TrackFakePyfhel)
    monkeypatch.setitem(sys.modules, "Pyfhel", fake_module)
    import cryptography_suite.homomorphic as h
    importlib.reload(h)

    he = TrackFakePyfhel()
    he.scheme = "OTHER"
    ct = h.encrypt(he, 5)
    assert he.enc_int_called and not he.enc_frac_called
    h.decrypt(he, ct)
    assert he.dec_int_called and not he.dec_frac_called
