"""Backend abstraction layer for cryptography-suite.

Backend selection is context-local and can be temporarily overridden using
``use_backend`` as a context manager.
"""

from __future__ import annotations

from typing import Callable, Dict, Type, Optional, Any
import warnings
import contextlib
from contextvars import ContextVar


_backend_registry: Dict[str, Type[Any]] = {}
_current_backend: ContextVar[Optional[Any]] = ContextVar(
    "cryptography_suite_current_backend", default=None
)
_default_warning_emitted = ContextVar(
    "cryptography_suite_backend_warned", default=False
)


def register_backend(name: str) -> Callable[[Type[Any]], Type[Any]]:
    """Class decorator to register a backend implementation."""

    def decorator(cls: Type[Any]) -> Type[Any]:
        _backend_registry[name] = cls
        return cls

    return decorator


def available_backends() -> list[str]:
    return list(_backend_registry.keys())


class _BackendContext(contextlib.AbstractContextManager[Any]):
    def __init__(self, name: str) -> None:
        self.name = name
        self._prev: Optional[Any] = None
        self._entered = False

        # Set immediately for compatibility with previous behaviour
        self.__enter__()

    def __enter__(self) -> Any:  # pragma: no cover - simple state switch
        if not self._entered:
            self._prev = _current_backend.get()
            try:
                backend_cls = _backend_registry[self.name]
            except KeyError as exc:
                raise ValueError(f"Unknown backend: {self.name}") from exc
            backend = backend_cls()
            _current_backend.set(backend)
            self._entered = True
        return _current_backend.get()

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - simple
        if self._entered:
            _current_backend.set(self._prev)
            self._entered = False


def use_backend(name: str) -> _BackendContext:
    """Select the backend to use.

    Backend selection is stored in a :class:`contextvars.ContextVar`, making it
    safe for threads and asynchronous tasks. The function returns a context
    manager so it can be used in ``with`` blocks::

        with use_backend("pyca"):
            ...

    Calling it without ``with`` permanently switches the backend for the
    current thread or task.
    """

    return _BackendContext(name)


def select_backend(obj: Any) -> None:
    """Register and select a backend.

    Parameters
    ----------
    obj:
        Either the name of a registered backend or a backend instance. When an
        instance is provided it will be registered under ``obj.name`` if the
        attribute exists, otherwise the lower-cased class name.
    """

    if isinstance(obj, str):
        use_backend(obj)
    else:
        name = getattr(obj, "name", obj.__class__.__name__.lower())
        _backend_registry[name] = obj.__class__
        _current_backend.set(obj)


def get_backend() -> Any:
    """Return the currently selected backend instance.

    Emits a :class:`RuntimeWarning` if no backend was explicitly selected.
    """

    backend = _current_backend.get()
    if backend is None:
        if not _backend_registry:
            raise RuntimeError("No backends registered")
        name = next(iter(_backend_registry))
        backend_cls = _backend_registry[name]
        backend = backend_cls()
        _current_backend.set(backend)
        if not _default_warning_emitted.get():
            warnings.warn(
                "No backend explicitly selected; defaulting to '%s'. "
                "Call use_backend() to select one explicitly." % name,
                RuntimeWarning,
                stacklevel=2,
            )
            _default_warning_emitted.set(True)
    return backend


# register built-in backends
from . import pyca_backend  # noqa: F401,E402

__all__ = [
    "register_backend",
    "available_backends",
    "use_backend",
    "select_backend",
    "get_backend",
]
