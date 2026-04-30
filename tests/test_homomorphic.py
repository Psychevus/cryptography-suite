# mypy: disable-error-code=no-untyped-call
import importlib
import inspect
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from cryptography_suite.errors import EncryptionError, UnsupportedOperationError


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


class SafeSerializationFakePyfhel(FakePyfhel):
    def to_bytes_context(self):
        return f"safe-context:{self.scheme}".encode("ascii")

    def from_bytes_context(self, data):
        if data != b"safe-context:CKKS":
            raise ValueError("invalid context")
        self.scheme = "CKKS"


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


def test_homomorphic_ckks_and_bfv_are_experimental(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch)
    assert h.__name__ == "cryptography_suite.experimental.fhe"
    assert h.FHE_AVAILABLE is True

    he = h.fhe_keygen("CKKS")
    ct = h.fhe_encrypt(he, 1.5)
    assert h.fhe_decrypt(he, ct) == 1.5
    assert h.fhe_add(he, ct, ct).value == 3.0
    assert h.fhe_multiply(he, ct, ct).value == 2.25

    he_bfv = h.fhe_keygen("BFV")
    ct2 = h.fhe_encrypt(he_bfv, 2)
    assert h.fhe_decrypt(he_bfv, ct2) == 2
    with pytest.raises(EncryptionError):
        h.fhe_keygen("BAD")


def test_context_serialization_uses_only_safe_pyfhel_bytes_api(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch, SafeSerializationFakePyfhel)
    he = h.fhe_keygen("CKKS")

    serialized = h.fhe_serialize_context(he)
    assert serialized == b"safe-context:CKKS"
    he2 = h.fhe_load_context(serialized)
    assert he2.scheme == "CKKS"


def test_context_serialization_has_no_pickle_fallback(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch)
    source = inspect.getsource(h)
    assert "pickle." + "dumps" not in source
    assert "pickle." + "loads" not in source

    he = h.fhe_keygen("CKKS")
    with pytest.raises(UnsupportedOperationError, match="pickle fallback is disabled"):
        h.fhe_serialize_context(he)
    with pytest.raises(UnsupportedOperationError, match="pickle fallback is disabled"):
        h.fhe_load_context(b"\x80\x04unsafe-pickle")


def test_load_context_rejects_unsupported_serialized_data(monkeypatch):
    h = _reload_experimental_fhe(monkeypatch, SafeSerializationFakePyfhel)
    with pytest.raises(UnsupportedOperationError, match="could not be loaded safely"):
        h.fhe_load_context(b"\x80\x04unsafe-pickle")
    with pytest.raises(UnsupportedOperationError, match="non-empty serialized bytes"):
        h.fhe_load_context(b"")
    with pytest.raises(UnsupportedOperationError, match="serialized bytes"):
        h.fhe_load_context("not bytes")


def test_legacy_homomorphic_module_requires_experimental_opt_in(monkeypatch):
    monkeypatch.delenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", raising=False)
    for module_name in (
        "cryptography_suite.homomorphic",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental",
    ):
        sys.modules.pop(module_name, None)

    with pytest.raises(ImportError, match="experimental"):
        importlib.import_module("cryptography_suite.homomorphic")


def test_top_level_import_does_not_import_fhe_dependencies(monkeypatch):
    monkeypatch.delenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", raising=False)
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.pop("CRYPTOSUITE_ALLOW_EXPERIMENTAL", None)
    env["PYTHONPATH"] = str(repo_root)
    code = "\n".join(
        (
            "import sys",
            "import cryptography_suite",
            "unexpected = [",
            "    name",
            "    for name in (",
            "        'Pyfhel',",
            "        'cryptography_suite.homomorphic',",
            "        'cryptography_suite.experimental.fhe',",
            "    )",
            "    if name in sys.modules",
            "]",
            "if unexpected:",
            "    raise SystemExit('unexpected FHE imports: ' + ', '.join(unexpected))",
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
