import importlib
import sys
import types

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

class FakePyfhelMulti(FakePyfhel):
    def decryptFrac(self, ctxt):
        return [ctxt.value, ctxt.value * 2]

def test_decrypt_returns_list_when_multiple_values(monkeypatch):
    fake_module = types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=FakePyfhelMulti)
    monkeypatch.setitem(sys.modules, "Pyfhel", fake_module)
    import cryptography_suite.homomorphic as h
    importlib.reload(h)
    he = h.keygen("CKKS")
    ct = h.encrypt(he, 2.0)
    assert h.decrypt(he, ct) == [2.0, 4.0]
