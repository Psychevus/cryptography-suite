"""Utilities for securely zeroing memory buffers."""

from __future__ import annotations

import ctypes
import ctypes.util
import gc
import platform
import os
import time

try:  # Optional dependency
    from cffi import FFI  # type: ignore
except Exception:  # pragma: no cover - cffi not installed
    FFI = None  # type: ignore

_libc_name = ctypes.util.find_library("c")
if _libc_name is None and os.name == "nt":  # pragma: no cover - Windows lookup
    _libc_name = ctypes.util.find_library("msvcrt") or "msvcrt"
try:
    _libc = ctypes.CDLL(_libc_name) if _libc_name else None
except Exception:  # pragma: no cover - libc load failure
    _libc = None
if _libc is not None:
    _libc_memset = _libc.memset
    _libc_memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
    _libc_memset.restype = ctypes.c_void_p
else:
    _libc_memset = None


def _memset(addr: ctypes.c_void_p, value: int, size: int) -> None:
    """Invoke libc's ``memset`` to overwrite memory."""

    if _libc_memset is not None:
        _libc_memset(addr, value, size)
    else:  # pragma: no cover - libc unavailable
        ctypes.memset(addr, value, size)


def _pypy_memset(addr: ctypes.c_void_p, value: int, size: int) -> None:
    """Call ``libc.memset`` directly for PyPy."""

    if _libc_memset is not None:
        _libc_memset(addr, value, size)  # pragma: no cover - PyPy only
    else:  # pragma: no cover - libc unavailable
        ctypes.memset(addr, value, size)  # pragma: no cover - libc unavailable


def _secure_zero_pypy(obj: bytearray) -> None:
    """Best-effort zeroization for PyPy JIT frames."""

    buf = (ctypes.c_char * len(obj)).from_buffer(obj)  # pragma: no cover - PyPy only
    _pypy_memset(ctypes.addressof(buf), 0, len(obj))  # pragma: no cover - PyPy only
    if hasattr(buf, "release"):  # pragma: no cover - PyPy only
        buf.release()  # pragma: no cover - PyPy only

    del obj[:]  # pragma: no cover - PyPy only
    gc.collect()  # pragma: no cover - PyPy only
    time.sleep(0)  # pragma: no cover - PyPy only


# Public alias for backward compatibility
secure_zero_pypy = _secure_zero_pypy


def _cffi_memset_s(data: bytearray) -> bool:
    """Attempt zeroization via CFFI's ``memset_s``.

    Returns ``True`` on success, ``False`` otherwise.
    """

    if FFI is None:
        return False  # pragma: no cover - CFFI not installed
    try:
        ffi = FFI()  # pragma: no cover - requires CFFI
        ffi.cdef(
            "int memset_s(void *s, size_t smax, int c, size_t n);"
        )  # pragma: no cover - requires CFFI
        C = ffi.dlopen(
            ctypes.util.find_library("c") or None
        )  # pragma: no cover - requires CFFI
        C.memset_s(
            ffi.from_buffer(data), len(data), 0, len(data)
        )  # pragma: no cover - requires CFFI
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

    buf = (ctypes.c_char * len(data)).from_buffer(data)

    if platform.python_implementation() == "PyPy":
        _pypy_memset(ctypes.addressof(buf), 0, len(data))  # pragma: no cover - PyPy only
        if hasattr(buf, "release"):  # pragma: no cover - PyPy only
            buf.release()  # pragma: no cover - PyPy only
        del data[:]  # pragma: no cover - PyPy only
        gc.collect()  # pragma: no cover - PyPy only
        time.sleep(0)  # pragma: no cover - PyPy only
        return  # pragma: no cover - PyPy only

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
        memset_s(
            ctypes.addressof(buf), len(data), 0, len(data)
        )  # pragma: no cover - requires memset_s
    elif not _cffi_memset_s(data):
        _memset(ctypes.addressof(buf), 0, len(data))

    if hasattr(buf, "release"):
        buf.release()  # pragma: no cover - buffer lacks release
