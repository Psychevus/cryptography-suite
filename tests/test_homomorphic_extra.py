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


def _reload_experimental_fhe(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    monkeypatch.setitem(
        sys.modules,
        "Pyfhel",
        types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=FakePyfhelMulti),
    )
    for module_name in (
        "cryptography_suite.homomorphic",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental",
    ):
        sys.modules.pop(module_name, None)
    return importlib.import_module("cryptography_suite.experimental.fhe")


def test_decrypt_returns_list_when_multiple_values(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch)
    he = h.fhe_keygen("CKKS")
    ct = h.fhe_encrypt(he, 2.0)
    assert h.fhe_decrypt(he, ct) == [2.0, 4.0]
