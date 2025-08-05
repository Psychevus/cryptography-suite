"""Utilities for securely zeroing memory buffers."""
from __future__ import annotations

import ctypes
import ctypes.util
import gc
import platform
import time

try:  # Optional dependency
    from cffi import FFI  # type: ignore
except Exception:  # pragma: no cover - cffi not installed
    FFI = None  # type: ignore


def secure_zero_pypy(obj: bytearray) -> None:
    """Best-effort zeroization for PyPy JIT frames.

    PyPy's JIT may move objects in memory; to ensure wiping we:
    1. Overwrite the buffer via ``ctypes.memset``.
    2. Delete the slice to drop references.
    3. Run ``gc.collect`` and yield to the OS.
    """

    buf = (ctypes.c_char * len(obj)).from_buffer(obj)  # pragma: no cover - PyPy only
    ctypes.memset(ctypes.addressof(buf), 0, len(obj))  # pragma: no cover - PyPy only
    if hasattr(buf, "release"):  # pragma: no cover - PyPy only
        buf.release()  # pragma: no cover - PyPy only

    del obj[:]  # pragma: no cover - PyPy only
    gc.collect()  # pragma: no cover - PyPy only
    time.sleep(0)  # pragma: no cover - PyPy only


def _cffi_memset_s(data: bytearray) -> bool:
    """Attempt zeroization via CFFI's ``memset_s``.

    Returns ``True`` on success, ``False`` otherwise.
    """

    if FFI is None:
        return False  # pragma: no cover - CFFI not installed
    try:
        ffi = FFI()  # pragma: no cover - requires CFFI
        ffi.cdef("int memset_s(void *s, size_t smax, int c, size_t n);")  # pragma: no cover - requires CFFI
        C = ffi.dlopen(ctypes.util.find_library("c") or None)  # pragma: no cover - requires CFFI
        C.memset_s(ffi.from_buffer(data), len(data), 0, len(data))  # pragma: no cover - requires CFFI
        return True  # pragma: no cover - requires CFFI
    except Exception:  # pragma: no cover - requires CFFI
        return False  # pragma: no cover - requires CFFI


def secure_zero(data: bytearray) -> None:
    """Overwrite ``data`` with zeros in-place.

    Dispatches between CPython and PyPy implementations and falls back
    to a CFFI-based ``memset_s`` if needed.
    """

    if not isinstance(data, bytearray):
        raise TypeError("secure_zero expects a bytearray")

    if platform.python_implementation() == "PyPy":
        secure_zero_pypy(data)  # pragma: no cover - PyPy only
        return  # pragma: no cover - PyPy only

    buf = (ctypes.c_char * len(data)).from_buffer(data)
    libc_name = ctypes.util.find_library("c")
    memset_s = None
    if libc_name:
        try:
            libc = ctypes.CDLL(libc_name)
            memset_s = getattr(libc, "memset_s", None)
        except Exception:  # pragma: no cover - libc load failure
            memset_s = None  # pragma: no cover - libc load failure

    if memset_s is not None:
        memset_s.argtypes = [  # pragma: no cover - requires memset_s
            ctypes.c_void_p,  # pragma: no cover - requires memset_s
            ctypes.c_size_t,  # pragma: no cover - requires memset_s
            ctypes.c_int,  # pragma: no cover - requires memset_s
            ctypes.c_size_t,  # pragma: no cover - requires memset_s
        ]
        memset_s.restype = ctypes.c_int  # pragma: no cover - requires memset_s
        memset_s(ctypes.addressof(buf), len(data), 0, len(data))  # pragma: no cover - requires memset_s
    elif not _cffi_memset_s(data):
        ctypes.memset(ctypes.addressof(buf), 0, len(data))

    if hasattr(buf, "release"):
        buf.release()  # pragma: no cover - buffer lacks release
