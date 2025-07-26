from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import pathlib
from importlib import metadata
from typing import Dict, Type

from .base import KeyStore

_REGISTRY: Dict[str, Type[KeyStore]] = {}


def register_keystore(name: str):
    """Class decorator to register keystore implementations."""

    def decorator(cls: Type[KeyStore]) -> Type[KeyStore]:
        _REGISTRY[name] = cls
        return cls

    return decorator


def list_keystores() -> list[str]:
    return list(_REGISTRY.keys())


def get_keystore(name: str) -> Type[KeyStore]:
    return _REGISTRY[name]


def load_plugins(directory: str | None = None) -> None:
    """Import available keystore plugins."""

    # built-in plugins in this package
    pkg = __name__
    for _, modname, _ in pkgutil.iter_modules(__path__):
        if modname.startswith('_') or modname in {"base"}:
            continue
        importlib.import_module(f"{pkg}.{modname}")

    # external plugins from path
    if directory is None:
        directory = str(pathlib.Path.cwd() / "keystores")
    dpath = pathlib.Path(directory)
    if dpath.is_dir():
        for file in dpath.glob("*.py"):
            spec = importlib.util.spec_from_file_location(
                f"ext_keystore_{file.stem}", file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

    # entry points
    try:
        for ep in metadata.entry_points(group="cryptosuite.keystores"):
            ep.load()
    except Exception:
        pass


__all__ = [
    "KeyStore",
    "register_keystore",
    "list_keystores",
    "get_keystore",
    "load_plugins",
]
