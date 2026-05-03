import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mypy")


def run_mypy(path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mypy", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONPATH": str(Path.cwd())},
        text=True,
    )


def test_vulnerable_example_triggers_error():
    proc = run_mypy("examples/vulnerable.py")
    assert proc.returncode != 0
    assert "Insecure hash function" in proc.stdout
