import importlib
import sys
import types
import pytest
from cryptography_suite.errors import ProtocolError


def test_bulletproof_prove_verify(monkeypatch):
    stub = types.SimpleNamespace(
        zkrp_prove=lambda val, bits: (b"proof", b"commit", b"nonce"),
        zkrp_verify=lambda proof, commit: True,
    )
    monkeypatch.setitem(sys.modules, "pybulletproofs", stub)
    import cryptography_suite.zk.bulletproof as bp
    importlib.reload(bp)
    assert bp.BULLETPROOF_AVAILABLE
    proof, commit, nonce = bp.prove(10)
    assert bp.verify(proof, commit)
    with pytest.raises(ProtocolError):
        bp.prove(-1)


def test_bulletproof_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pybulletproofs", None)
    import cryptography_suite.zk.bulletproof as bp
    importlib.reload(bp)
    with pytest.raises(ImportError):
        bp.prove(1)
    with pytest.raises(ImportError):
        bp.verify(b"p", b"c")
