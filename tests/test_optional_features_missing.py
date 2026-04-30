import importlib
import sys

import pytest

from cryptography_suite.errors import MissingDependencyError


def test_homomorphic_requires_pyfhel(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    monkeypatch.setitem(sys.modules, "Pyfhel", None)
    for module_name in (
        "cryptography_suite.homomorphic",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental",
    ):
        sys.modules.pop(module_name, None)
    h = importlib.import_module("cryptography_suite.experimental.fhe")
    with pytest.raises(MissingDependencyError):
        h.fhe_keygen()


def test_bulletproof_requires_dependency(monkeypatch):
    from cryptography_suite.zk import bulletproof as bp

    monkeypatch.setattr(bp, "BULLETPROOF_AVAILABLE", False)
    with pytest.raises(MissingDependencyError):
        bp.prove(1)


def test_zksnark_requires_dependency(monkeypatch):
    from cryptography_suite.zk import zksnark as zk

    monkeypatch.setattr(zk, "ZKSNARK_AVAILABLE", False)
    with pytest.raises(MissingDependencyError):
        zk.setup()
