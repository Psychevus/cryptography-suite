#!/usr/bin/env python3
"""Fail if experimental primitives are imported outside the experimental package."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / "cryptography_suite"
EXPERIMENTAL = ROOT / "experimental"


def main() -> int:
    errors: list[str] = []
    for path in ROOT.rglob("*.py"):
        if path.is_relative_to(EXPERIMENTAL):
            continue
        tree = ast.parse(path.read_text())
        mod = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("cryptography_suite.experimental"):
                        errors.append(f"{mod}: import of experimental primitive {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("cryptography_suite.experimental"):
                    errors.append(f"{mod}: import from experimental module {node.module}")
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("No experimental imports found.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
