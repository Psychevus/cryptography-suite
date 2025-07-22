import builtins
import importlib
import sys
import cryptography_suite


def test_init_without_optional_modules(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if (name in {"cryptography_suite.zk", "zk"} and ("bulletproof" in fromlist or "zksnark" in fromlist)):
            raise ImportError
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    for mod in ["cryptography_suite.zk", "cryptography_suite.zk.bulletproof", "cryptography_suite.zk.zksnark"]:
        sys.modules.pop(mod, None)
    mod = importlib.reload(cryptography_suite)
    assert not mod.BULLETPROOF_AVAILABLE
    assert not mod.ZKSNARK_AVAILABLE
    assert "bulletproof" not in mod.__all__
    assert "zksnark" not in mod.__all__
    importlib.reload(mod)
