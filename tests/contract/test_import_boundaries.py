from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "src" / "cryptography_suite"

FORBIDDEN_TOKENS = {
    "sys.path",
    "__path__",
    "spec_from_file_location",
    "exec_module",
    "entry_points",
    "getenv",
    "os.environ",
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


class ImportSnapshot(TypedDict):
    all: list[str]
    modules: list[str]
    origin: str | None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"import snapshot field {field!r} must be a string list")
    return [item for item in value if isinstance(item, str)]


def _import_snapshot(cwd: Path, environment_value: str) -> ImportSnapshot:
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
    raw: object = json.loads(result.stdout)
    if not isinstance(raw, dict):
        raise TypeError("import snapshot must be an object")
    origin: object = raw.get("origin")
    if origin is not None and not isinstance(origin, str):
        raise TypeError("import snapshot field 'origin' must be a string or null")
    return ImportSnapshot(
        all=_string_list(raw.get("all"), "all"),
        modules=_string_list(raw.get("modules"), "modules"),
        origin=origin,
    )


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


def test_internal_import_graph_matches_phase_2_layers() -> None:
    allowed: dict[str, set[str]] = {
        "cryptography_suite": {
            "audit",
            "context",
            "envelope",
            "errors",
            "policy",
            "protector",
            "providers",
            "streaming",
        },
        "cryptography_suite.audit": {"errors"},
        "cryptography_suite.context": set(),
        "cryptography_suite.envelope": {"providers"},
        "cryptography_suite.errors": set(),
        "cryptography_suite.legacy": set(),
        "cryptography_suite.lifecycle": {"providers"},
        "cryptography_suite.policy": set(),
        "cryptography_suite.protector": {
            "audit",
            "context",
            "envelope",
            "policy",
            "providers",
            "streaming",
        },
        "cryptography_suite.providers": set(),
        "cryptography_suite.streaming": set(),
    }
    violations: list[str] = []
    for path in sorted(SOURCE.rglob("*.py")):
        relative = path.relative_to(SOURCE)
        parts = relative.with_suffix("").parts
        owner = "cryptography_suite"
        if len(parts) > 1:
            owner = f"cryptography_suite.{parts[0]}"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level == 0:
                continue
            target = (node.module or "").split(".", 1)[0]
            is_local_submodule = len(parts) > 1 and node.level == 1
            if not is_local_submodule and target and target not in allowed[owner]:
                violations.append(f"{path.relative_to(REPO_ROOT)}: {owner} -> {target}")
    assert violations == []


def test_audit_package_has_no_provider_import_edge() -> None:
    audit_source = SOURCE / "audit"
    violations: list[str] = []
    for path in sorted(audit_source.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(
                    alias.name == "cryptography_suite.providers"
                    or alias.name.startswith("cryptography_suite.providers.")
                    for alias in node.names
                ):
                    violations.append(str(path.relative_to(REPO_ROOT)))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                is_provider_edge = (
                    module == "cryptography_suite.providers"
                    or module.startswith("cryptography_suite.providers.")
                    or (
                        node.level >= 2
                        and (
                            module == "providers"
                            or module.startswith("providers.")
                            or (
                                not module
                                and any(
                                    alias.name == "providers" for alias in node.names
                                )
                            )
                        )
                    )
                )
                if is_provider_edge:
                    violations.append(str(path.relative_to(REPO_ROOT)))
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
