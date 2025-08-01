import importlib
import sys

import pytest

from cryptography_suite.errors import MissingDependencyError


def test_homomorphic_requires_pyfhel(monkeypatch):
    monkeypatch.setitem(sys.modules, "Pyfhel", None)
    import cryptography_suite.homomorphic as h
    importlib.reload(h)
    with pytest.raises(MissingDependencyError):
        h.keygen()


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

