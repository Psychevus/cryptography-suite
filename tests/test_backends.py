import importlib
import pytest

import cryptography_suite.crypto_backends as backends
import cryptography_suite.crypto_backends.pyca_backend as pyca_backend


def test_available_backends_contains_pyca():
    assert "pyca" in backends.available_backends()


def test_use_backend_runtime_switch():
    class Dummy:
        def __init__(self) -> None:
            self.value = 1

    backends.register_backend("dummy")(Dummy)
    backends.use_backend("dummy")
    b = backends.get_backend()
    assert isinstance(b, Dummy)
    assert b.value == 1
    backends.use_backend("pyca")


def test_select_backend_alias():
    class Dummy2:
        pass

    backends.register_backend("dummy2")(Dummy2)
    with pytest.deprecated_call():
        backends.select_backend("dummy2")
    assert isinstance(backends.get_backend(), Dummy2)
    backends.use_backend("pyca")
