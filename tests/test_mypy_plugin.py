import importlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import tomllib

pytest.importorskip("mypy")


def configured_mypy_plugins() -> list[str]:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    mypy = cast(dict[str, Any], cast(dict[str, Any], data["tool"])["mypy"])
    plugins = mypy.get("plugins", [])
    if isinstance(plugins, str):
        return [plugins]
    return cast(list[str], plugins)


def run_mypy(path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mypy", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONPATH": str(Path.cwd())},
        text=True,
    )


def test_configured_mypy_plugin_is_importable() -> None:
    plugins = configured_mypy_plugins()

    assert "cryptography_suite._mypy_crypto_checker" in plugins
    assert all(not plugin.startswith("tools.") for plugin in plugins)
    for plugin in plugins:
        module = importlib.import_module(plugin)
        assert module.__file__


def test_vulnerable_example_triggers_error() -> None:
    proc = run_mypy("examples/vulnerable.py")
    assert proc.returncode != 0
    assert "Insecure hash function" in proc.stdout
