import importlib
import os
import sys
import pytest


def test_init_without_optional_modules() -> None:
    import cryptography_suite

    core_all = set(cryptography_suite.__all__)
    assert "bulletproof" not in core_all
    assert "zksnark" not in core_all

    if os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
        experimental = importlib.import_module("cryptography_suite.experimental")
        assert hasattr(experimental, "BULLETPROOF_AVAILABLE")
        assert hasattr(experimental, "ZKSNARK_AVAILABLE")
    else:
        sys.modules.pop("cryptography_suite.experimental", None)
        with pytest.raises(ImportError):
            importlib.import_module("cryptography_suite.experimental")

