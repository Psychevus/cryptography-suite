from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import REPO_ROOT

SOURCE = REPO_ROOT / "src" / "cryptography_suite"

FORBIDDEN_TOKENS = {
    "sys.path",
    "__path__",
    "spec_from_file_location",
    "exec_module",
    "entry_points",
    "Path.cwd",
    "os.getcwd",
    "getcwd(",
    "CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS",
}

FORBIDDEN_IMPORT_PARTS = {
    "boto3",
    "cryptography_suite.cli",
    "cryptography_suite.legacy",
    "cryptography_suite.labs",
    "jinja2",
    "pkcs11",
    "pqcrypto",
}


def _import_snapshot(cwd: Path, environment_value: str) -> dict[str, object]:
    code = """
import json
import socket
import sys

def blocked(*args, **kwargs):
    raise AssertionError("network access during import")

socket.socket.connect = blocked
import cryptography_suite
print(json.dumps({
    "all": cryptography_suite.__all__,
    "modules": sorted(
        name for name in sys.modules
        if name == "cryptography_suite" or name.startswith("cryptography_suite.")
    ),
    "origin": cryptography_suite.__file__,
}))
"""
    env = os.environ.copy()
    env["PHASE3_IMPORT_SENTINEL"] = environment_value
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_root_import_is_stable_across_cwd_and_environment(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    snapshot_one = _import_snapshot(first, "one")
    snapshot_two = _import_snapshot(second, "two")

    assert snapshot_one["all"] == snapshot_two["all"]
    assert snapshot_one["modules"] == snapshot_two["modules"]
    assert "cryptography_suite.legacy" not in snapshot_one["modules"]
    assert "cryptography_suite.lifecycle" not in snapshot_one["modules"]
    assert all(".cli" not in name for name in snapshot_one["modules"])
    assert all(".labs" not in name for name in snapshot_one["modules"])


def test_stable_source_has_no_forbidden_runtime_mechanism() -> None:
    violations: list[str] = []
    for path in sorted(SOURCE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_TOKENS:
            if token in text:
                violations.append(f"{path.relative_to(REPO_ROOT)}: {token}")
    assert violations == []


def test_stable_ast_imports_exclude_forbidden_packages() -> None:
    violations: list[str] = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if any(part in name for part in FORBIDDEN_IMPORT_PARTS):
                    violations.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert violations == []


def test_only_one_runtime_package_tree_remains_after_migration() -> None:
    candidates = [
        REPO_ROOT / "cryptography_suite",
        REPO_ROOT / "src" / "cryptography_suite",
        REPO_ROOT / "src" / "crypto_suite",
        REPO_ROOT / "src" / "suite",
    ]
    existing = [path for path in candidates if (path / "__init__.py").is_file()]
    assert existing == [REPO_ROOT / "src" / "cryptography_suite"]
