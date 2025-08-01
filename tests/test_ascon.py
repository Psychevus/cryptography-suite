import pytest


def test_ascon_import_raises():
    with pytest.raises(RuntimeError):
        __import__("cryptography_suite.experimental.ascon")
