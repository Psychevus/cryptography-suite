from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import tomllib

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
REQUIREMENTS = REPO_ROOT / "requirements.txt"

DISALLOWED_DEFAULTS = {
    "py-ecc",
    "spake2",
    "pqcrypto",
    "pyfhel",
    "ipywidgets",
    "networkx",
    "jinja2",
    "requests",
    "boto3",
    "python-pkcs11",
    "pkcs11",
    "pyyaml",
    "rich",
    "pytest",
    "hypothesis",
    "mypy",
    "ruff",
    "black",
    "coverage",
}
EXPECTED_EXTRAS = {
    "async",
    "bls",
    "cli",
    "codegen",
    "dev",
    "docs",
    "fhe",
    "hashing-extra",
    "hsm",
    "kms",
    "network",
    "pake",
    "pqc",
    "viz",
    "aws",
    "legacy",
    "zk",
}
OPTIONAL_DISTRIBUTION_NAMES = {
    "aiofiles",
    "blake3",
    "boto3",
    "jinja2",
    "networkx",
    "pkcs11",
    "pqcrypto",
    "py-ecc",
    "pybulletproofs",
    "pyfhel",
    "pyyaml",
    "pysnark",
    "python-pkcs11",
    "requests",
    "rich",
    "spake2",
}
OPTIONAL_IMPORT_ROOTS = [
    "blake3",
    "spake2",
    "py_ecc",
    "pqcrypto",
    "Pyfhel",
    "ipywidgets",
    "networkx",
    "jinja2",
    "rich",
    "requests",
    "yaml",
]


def _pyproject() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _requirement_name(requirement: str) -> str:
    name = re.split(r"[\[<>=!~; ]", requirement, maxsplit=1)[0]
    return name.lower().replace("_", "-")


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_pyproject_default_dependencies_are_minimal() -> None:
    project = cast(dict[str, Any], _pyproject()["project"])
    dependencies = {_requirement_name(req) for req in project.get("dependencies", [])}

    assert dependencies == {"cryptography"}
    assert not dependencies & DISALLOWED_DEFAULTS


def test_requirements_txt_matches_minimal_runtime_dependencies() -> None:
    requirements = {_requirement_name(req) for req in _requirement_lines(REQUIREMENTS)}

    assert requirements == {"cryptography"}
    assert not requirements & DISALLOWED_DEFAULTS


def test_optional_dependency_names_are_not_base_dependencies() -> None:
    project = cast(dict[str, Any], _pyproject()["project"])
    base_dependencies = {
        _requirement_name(req) for req in project.get("dependencies", [])
    }
    optional_dependencies = cast(dict[str, list[str]], project["optional-dependencies"])
    extras_dependencies = {
        _requirement_name(req)
        for dependencies in optional_dependencies.values()
        for req in dependencies
    }

    assert not base_dependencies & OPTIONAL_DISTRIBUTION_NAMES
    assert extras_dependencies & OPTIONAL_DISTRIBUTION_NAMES


def test_expected_optional_extras_exist() -> None:
    project = cast(dict[str, Any], _pyproject()["project"])
    optional_dependencies = cast(dict[str, list[str]], project["optional-dependencies"])
    extras = set(optional_dependencies)

    assert EXPECTED_EXTRAS <= extras


def test_requests_is_not_part_of_local_cli_extra() -> None:
    project = cast(dict[str, Any], _pyproject()["project"])
    optional_dependencies = cast(dict[str, list[str]], project["optional-dependencies"])
    cli_dependencies = {
        _requirement_name(req) for req in optional_dependencies.get("cli", [])
    }
    network_dependencies = {
        _requirement_name(req) for req in optional_dependencies.get("network", [])
    }

    assert "requests" not in cli_dependencies
    assert "requests" in network_dependencies


def test_package_discovery_does_not_include_tools() -> None:
    data = _pyproject()
    tool = cast(dict[str, Any], data["tool"])
    setuptools = cast(dict[str, Any], tool["setuptools"])
    packages = cast(dict[str, Any], setuptools["packages"])
    package_find = cast(dict[str, list[str]], packages["find"])
    includes = package_find["include"]

    assert all(not include.startswith("tools") for include in includes)
    assert "cryptography_suite*" in includes


def test_importing_root_package_does_not_import_optional_dependencies() -> None:
    code = f"""
import json
import sys

import cryptography_suite  # noqa: F401

optional = {OPTIONAL_IMPORT_ROOTS!r}
print(json.dumps([name for name in optional if name in sys.modules]))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == []


def test_importing_cli_module_does_not_import_optional_dependencies() -> None:
    code = f"""
import json
import sys

import cryptography_suite.cli  # noqa: F401

optional = {OPTIONAL_IMPORT_ROOTS!r}
print(json.dumps([name for name in optional if name in sys.modules]))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == []
