import importlib
import sys
import pytest
from cryptography.utils import CryptographyDeprecationWarning


def test_ascon_import_warns(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    for mod in ["cryptography_suite.experimental", "cryptography_suite.experimental.ascon"]:
        sys.modules.pop(mod, None)
    with pytest.warns(CryptographyDeprecationWarning):
        importlib.import_module("cryptography_suite.experimental.ascon")


def test_ascon_import_requires_flag(monkeypatch):
    monkeypatch.delenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", raising=False)
    for mod in ["cryptography_suite.experimental", "cryptography_suite.experimental.ascon"]:
        sys.modules.pop(mod, None)
    with pytest.raises(ImportError):
        importlib.import_module("cryptography_suite.experimental.ascon")
