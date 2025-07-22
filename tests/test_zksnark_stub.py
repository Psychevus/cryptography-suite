import importlib
import sys
import types
import pytest

class DummyPrivVal:
    def __init__(self, val):
        self.val = val


def dummy_sha256(secret):
    class Bits:
        def __init__(self, val):
            self.val = val
    return Bits(secret.val)

class DummySnark:
    @staticmethod
    def prove():
        return "proof"

class DummyRun:
    @staticmethod
    def verify(hash_hex, proof_path):
        return True

def test_zksnark_full_flow(monkeypatch):
    runtime = types.SimpleNamespace(PrivVal=DummyPrivVal, snark=DummySnark, run=DummyRun)
    hash_mod = types.SimpleNamespace(sha256=dummy_sha256)
    monkeypatch.setitem(sys.modules, "pysnark.runtime", runtime)
    monkeypatch.setitem(sys.modules, "pysnark.hash", hash_mod)
    monkeypatch.setitem(sys.modules, "pysnark", types.SimpleNamespace(snarksetup=lambda x: None))
    import cryptography_suite.zk.zksnark as zk
    importlib.reload(zk)
    assert zk.ZKSNARK_AVAILABLE
    zk.setup()
    digest, proof = zk.prove(b"x")
    assert zk.verify(digest, proof)


def test_zksnark_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pysnark.runtime", None)
    monkeypatch.setitem(sys.modules, "pysnark.hash", None)
    monkeypatch.setitem(sys.modules, "pysnark", None)
    import cryptography_suite.zk.zksnark as zk
    importlib.reload(zk)
    with pytest.raises(ImportError):
        zk.setup()
    with pytest.raises(ImportError):
        zk.prove(b"x")
    with pytest.raises(ImportError):
        zk.verify("h", "p")
