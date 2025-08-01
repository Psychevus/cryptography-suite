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


def test_homomorphic_ckks_and_bfv(monkeypatch):
    h = reload_module(monkeypatch)
    he = h.keygen("CKKS")
    ct = h.encrypt(he, 1.5)
    assert h.decrypt(he, ct) == 1.5
    assert h.add(he, ct, ct).value == 3.0
    assert h.multiply(he, ct, ct).value == 2.25
    ser = h.serialize_context(he)
    he2 = h.load_context(ser)
    assert he2.scheme == "CKKS"
    he_bfv = h.keygen("BFV")
    ct2 = h.encrypt(he_bfv, 2)
    assert h.decrypt(he_bfv, ct2) == 2
    with pytest.raises(EncryptionError):
        h.keygen("BAD")
