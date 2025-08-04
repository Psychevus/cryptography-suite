import importlib
import sys
import pytest


def test_import_error_without_flag(monkeypatch):
    monkeypatch.delenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", raising=False)
    for mod in [
        "cryptography_suite.experimental",
        "cryptography_suite.experimental.signal_demo",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental.zk",
    ]:
        sys.modules.pop(mod, None)
    with pytest.raises(ImportError):
        importlib.import_module("cryptography_suite.experimental.signal_demo")
    with pytest.raises(ImportError):
        importlib.import_module("cryptography_suite.experimental.fhe")
    with pytest.raises(ImportError):
        importlib.import_module("cryptography_suite.experimental.zk")


def test_import_success_with_flag(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    importlib.import_module("cryptography_suite.experimental.signal_demo")
    importlib.import_module("cryptography_suite.experimental.fhe")
    importlib.import_module("cryptography_suite.experimental.zk")
