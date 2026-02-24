#!/usr/bin/env python3
"""Fail when README workflow references drift from actual workflow files."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

WORKFLOW_REF_RE = re.compile(r"actions/workflows/([A-Za-z0-9_.-]+\.ya?ml)")


def main() -> int:
    text = README.read_text(encoding="utf-8")
    referenced = sorted(set(WORKFLOW_REF_RE.findall(text)))
    existing = {p.name for p in WORKFLOWS_DIR.glob("*.yml")} | {
        p.name for p in WORKFLOWS_DIR.glob("*.yaml")
    }

    missing = [name for name in referenced if name not in existing]

    if missing:
        print("README references non-existent workflow file(s):")
        for name in missing:
            print(f"  - {name}")
        print("\nExisting workflow files:")
        for name in sorted(existing):
            print(f"  - {name}")
        return 1

    print("README workflow references are valid.")
    if referenced:
        for name in referenced:
            print(f"  - {name}")
    else:
        print("No workflow references found in README.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
