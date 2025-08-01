#!/usr/bin/env python3
"""Fail if deprecated functions are exported via __all__ or imported in public modules."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / "cryptography_suite"


def module_of(path: Path, root: Path) -> str:
    return path.relative_to(root).with_suffix("").as_posix().replace("/", ".")


def find_deprecated(root: Path) -> set[tuple[str, str]]:
    names: set[tuple[str, str]] = set()
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        mod = module_of(path, root)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for deco in node.decorator_list:
                    func = getattr(deco, "func", deco)
                    if isinstance(func, ast.Name) and func.id == "deprecated":
                        names.add((mod, node.name))
    return names


def resolve_import_module(current_mod: str, node: ast.ImportFrom) -> str:
    module = node.module or ""
    if node.level:
        parts = current_mod.split(".")
        module_parts = parts[:-node.level]
        if module:
            module_parts.append(module)
        module = ".".join(module_parts)
    return module


def check_exports(root: Path, deprecated: set[tuple[str, str]]) -> list[str]:
    dep_names = {name for _, name in deprecated}
    errors: list[str] = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        current_mod = module_of(path, root)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        try:
                            names = ast.literal_eval(node.value)
                            for name in names:
                                if name in dep_names:
                                    errors.append(f"{path}: deprecated {name} found in __all__")
                        except Exception:
                            pass
            elif isinstance(node, ast.ImportFrom):
                mod = resolve_import_module(current_mod, node)
                for alias in node.names:
                    if (mod, alias.name) in deprecated:
                        errors.append(
                            f"{path}: deprecated {alias.name} imported from {mod}"
                        )
    return errors


def main() -> int:
    deprecated = find_deprecated(ROOT)
    errors = check_exports(ROOT, deprecated)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("No deprecated exports found.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
