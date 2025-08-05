import ctypes
import platform

import pytest

from crypto_suite.utils.zeroize import secure_zero


def _get_bytearray_offset() -> int:
    sample = bytearray(b"x")
    buf = (ctypes.c_char * len(sample)).from_buffer(sample)
    offset = ctypes.addressof(buf) - id(sample)
    if hasattr(buf, "release"):
        buf.release()
    return offset


PYOBJECT_OFFSET = _get_bytearray_offset()


def test_secure_zero_wipes_pypy_frame():
    if platform.python_implementation() != "PyPy":
        pytest.xfail("PyPy specific")
    buf = bytearray(b"secret")
    size = len(buf)
    addr = id(buf)
    secure_zero(buf)
    dump = ctypes.string_at(addr + PYOBJECT_OFFSET, size)
    assert dump == b"\x00" * size
