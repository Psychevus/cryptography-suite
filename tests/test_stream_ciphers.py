import os
import sys
import pytest


def test_salsa20_import_raises():
    if os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
        with pytest.raises(RuntimeError):
            __import__("cryptography_suite.experimental.salsa20")
    else:
        for mod in ["cryptography_suite.experimental", "cryptography_suite.experimental.salsa20"]:
            sys.modules.pop(mod, None)
        with pytest.raises(ImportError):
            __import__("cryptography_suite.experimental.salsa20")
