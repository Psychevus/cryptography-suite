from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from conftest import REPO_ROOT, BuiltArtifacts

EXPECTED_ROOT = [
    "AuthenticationError",
    "ContextMismatchError",
    "CryptographySuiteError",
    "EncryptionContext",
    "Envelope",
    "EnvelopeError",
    "EnvelopeMetadata",
    "ErrorCode",
    "KeyProvider",
    "KeyRef",
    "MigrationError",
    "Policy",
    "PolicyError",
    "Protector",
    "ProviderError",
]


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def test_isolated_installed_wheel_and_sdist_rebuild(
    built_artifacts: BuiltArtifacts,
    tmp_path: Path,
) -> None:
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = _venv_python(venv)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            str(built_artifacts.wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    code = """
import importlib.metadata
import json
import sys
import cryptography_suite

forbidden = [
    "cryptography_suite.aead",
    "cryptography_suite.cli",
    "cryptography_suite.experimental",
    "cryptography_suite.keystores",
    "cryptography_suite.labs",
    "cryptography_suite.providers.fake",
]
failures = []
for name in forbidden:
    try:
        __import__(name)
    except ModuleNotFoundError:
        continue
    failures.append(name)

print(json.dumps({
    "all": cryptography_suite.__all__,
    "failures": failures,
    "origin": cryptography_suite.__file__,
    "version": importlib.metadata.version("cryptography-suite"),
    "repo_on_path": any(
        str(entry).lower().startswith(REPO.lower()) for entry in sys.path
    ),
}))
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [str(python), "-I", "-c", f"REPO={str(REPO_ROOT)!r}\n{code}"],
        cwd=outside,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    snapshot = json.loads(result.stdout)

    assert snapshot["all"] == EXPECTED_ROOT
    assert snapshot["failures"] == []
    assert snapshot["version"] == "3.0.0"
    assert "site-packages" in snapshot["origin"].lower()
    assert snapshot["repo_on_path"] is False

    subprocess.run(
        [str(python), "-m", "pip", "check"],
        cwd=outside,
        check=True,
        capture_output=True,
        text=True,
    )

    rebuilt = tmp_path / "rebuilt"
    rebuilt.mkdir()
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(rebuilt),
            str(built_artifacts.sdist),
        ],
        cwd=outside,
        check=True,
        capture_output=True,
        text=True,
    )
    rebuilt_wheel = next(rebuilt.glob("*.whl"))
    with zipfile.ZipFile(built_artifacts.wheel) as first:
        first_names = sorted(first.namelist())
    with zipfile.ZipFile(rebuilt_wheel) as second:
        second_names = sorted(second.namelist())
    assert first_names == second_names

    with tarfile.open(built_artifacts.sdist) as archive:
        assert all(
            not member.name.endswith("/cryptography_suite/__init__.py")
            or "/src/" in member.name
            for member in archive.getmembers()
        )
