import ctypes
import platform

import pytest

from crypto_suite.utils.zeroize import secure_zero

pytestmark = pytest.mark.skipif(
    platform.python_implementation() != "PyPy", reason="PyPy specific"
)


def test_secure_zero_wipes_pypy_frame() -> None:
    buf = bytearray(b"TOPSECRET")
    size = len(buf)
    view = (ctypes.c_char * size).from_buffer(buf)
    addr = ctypes.addressof(view)
    secure_zero(buf)
    dump = ctypes.string_at(addr, size)
    if hasattr(view, "release"):
        view.release()
    assert dump == b"\x00" * size
