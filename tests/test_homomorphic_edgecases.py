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


def _reload_experimental_fhe(monkeypatch, pyfhel_cls=FakePyfhel):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    monkeypatch.setitem(
        sys.modules,
        "Pyfhel",
        types.SimpleNamespace(PyCtxt=FakePyCtxt, Pyfhel=pyfhel_cls),
    )
    for module_name in (
        "cryptography_suite.homomorphic",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental",
    ):
        sys.modules.pop(module_name, None)
    return importlib.import_module("cryptography_suite.experimental.fhe")


def test_keygen_case_insensitive(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch)
    he = h.fhe_keygen("ckks")
    assert he.scheme == "CKKS"
    he = h.fhe_keygen("bFv")
    assert he.scheme == "BFV"
    with pytest.raises(EncryptionError):
        h.fhe_keygen("unsupported")


def test_encrypt_decrypt_iterable_ckks(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch, FakePyfhelList)
    he = h.fhe_keygen("CKKS")
    values = [1.1, -2.2, 3.3]
    ct = h.fhe_encrypt(he, values)
    assert isinstance(ct, FakePyCtxt)
    assert h.fhe_decrypt(he, ct) == values


def test_large_integer_operations(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch)
    he = h.fhe_keygen("BFV")
    big = 2**60
    ct1 = h.fhe_encrypt(he, big)
    ct2 = h.fhe_encrypt(he, big)
    assert h.fhe_decrypt(he, ct1) == big
    added = h.fhe_add(he, ct1, ct2)
    multiplied = h.fhe_multiply(he, ct1, ct2)
    assert added.value == big * 2
    assert multiplied.value == big**2


def test_unknown_scheme_uses_integer_ops(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch, TrackFakePyfhel)

    he = TrackFakePyfhel()
    he.scheme = "OTHER"
    ct = h.fhe_encrypt(he, 5)
    assert he.enc_int_called and not he.enc_frac_called
    h.fhe_decrypt(he, ct)
    assert he.dec_int_called and not he.dec_frac_called
