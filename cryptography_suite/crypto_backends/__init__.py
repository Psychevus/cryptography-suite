"""Backend abstraction layer for cryptography-suite."""

from __future__ import annotations

from typing import Callable, Dict, Type, Optional, Any
import warnings


_backend_registry: Dict[str, Type[Any]] = {}
_current_backend: Optional[Any] = None


def register_backend(name: str) -> Callable[[Type[Any]], Type[Any]]:
    """Class decorator to register a backend implementation."""

    def decorator(cls: Type[Any]) -> Type[Any]:
        _backend_registry[name] = cls
        return cls

    return decorator


def available_backends() -> list[str]:
    return list(_backend_registry.keys())


def use_backend(name: str) -> None:
    """Select the backend to use at runtime.

    Example
    -------

    >>> from cryptography_suite.crypto_backends import use_backend
    >>> use_backend("pyca")
    >>> use_backend("sodium")  # doctest: +SKIP
    >>> use_backend("rust")    # doctest: +SKIP
    """
    global _current_backend
    try:
        backend_cls = _backend_registry[name]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unknown backend: {name}") from exc
    _current_backend = backend_cls()


def select_backend(name: str) -> None:
    """Deprecated alias for :func:`use_backend`."""
    warnings.warn(
        "select_backend is deprecated; use use_backend instead",
        DeprecationWarning,
        stacklevel=2,
    )
    use_backend(name)


def get_backend() -> Any:
    """Return the currently selected backend instance."""
    if _current_backend is None:
        # default to first registered backend
        if not _backend_registry:
            raise RuntimeError("No backends registered")
        name = next(iter(_backend_registry))
        use_backend(name)
    assert _current_backend is not None
    return _current_backend


# register built-in backends
from . import pyca_backend  # noqa: F401,E402

__all__ = [
    "register_backend",
    "available_backends",
    "use_backend",
    "select_backend",
    "get_backend",
]
