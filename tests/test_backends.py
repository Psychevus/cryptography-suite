import importlib
import pytest

import cryptography_suite.crypto_backends as backends
import cryptography_suite.crypto_backends.pyca_backend as pyca_backend


def test_available_backends_contains_pyca():
    assert "pyca" in backends.available_backends()


def test_get_backend_warns_when_default_used():
    importlib.reload(backends)
    importlib.reload(pyca_backend)
    with pytest.warns(RuntimeWarning):
        b = backends.get_backend()
    assert isinstance(b, pyca_backend.PyCABackend)
    backends.use_backend("pyca")


def test_use_backend_context_manager():
    class Dummy:
        def __init__(self) -> None:
            self.value = 1

    backends.register_backend("dummy")(Dummy)
    backends.use_backend("pyca")
    with backends.use_backend("dummy"):
        b = backends.get_backend()
        assert isinstance(b, Dummy)
        assert b.value == 1
    assert isinstance(backends.get_backend(), pyca_backend.PyCABackend)


def test_select_backend_with_instance():
    class Dummy2:
        name = "dummy2"

    inst = Dummy2()
    backends.select_backend(inst)
    assert isinstance(backends.get_backend(), Dummy2)
    assert "dummy2" in backends.available_backends()
    backends.use_backend("pyca")


def test_pipeline_backend_override():
    class Dummy:
        pass

    backends.register_backend("dummy")(Dummy)
    backends.use_backend("pyca")
    from cryptography_suite.pipeline import AESGCMEncrypt

    AESGCMEncrypt(password="pw", backend="dummy").run("hi")
    # original backend restored
    assert isinstance(backends.get_backend(), pyca_backend.PyCABackend)
