import importlib

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
