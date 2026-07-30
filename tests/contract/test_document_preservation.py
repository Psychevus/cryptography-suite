from __future__ import annotations

import subprocess

from conftest import REPO_ROOT

BASE_SHA = "def6fe31329ada2b112b09fff3f31ff1965a3ffb"
PRESERVED_PATHS = [
    "docs/v4/baseline",
    "docs/v4/rfcs",
    "docs/v4/architecture",
    "docs/v4/phase-2-summary.md",
]


def _current_blob(path: str) -> str:
    return subprocess.run(
        ["git", "hash-object", f"--path={path}", path],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_phase_1_and_phase_2_documents_are_byte_identical() -> None:
    tracked = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", BASE_SHA, "--", *PRESERVED_PATHS],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()

    assert tracked
    mismatches: list[str] = []
    for relative in tracked:
        base_blob = subprocess.run(
            ["git", "rev-parse", f"{BASE_SHA}:{relative}"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if _current_blob(relative) != base_blob:
            mismatches.append(relative)
    assert mismatches == []
