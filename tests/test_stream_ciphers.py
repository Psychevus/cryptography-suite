import pytest


def test_salsa20_import_raises():
    with pytest.raises(RuntimeError):
        __import__("cryptography_suite.experimental.salsa20")
