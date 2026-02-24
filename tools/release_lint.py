"""Validate presence of release security artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def _collect_expected(dist: Path) -> list[str]:
    artifacts = list(dist.glob("*.whl")) + list(dist.glob("*.tar.gz"))
    required_artifacts = artifacts + [
        dist / "sbom.json",
        dist / "provenance.intoto.jsonl",
    ]
    expected = [item.name for item in required_artifacts]
    for art in required_artifacts:
        expected.extend([art.name + ".sig", art.name + ".cert"])
    return sorted(expected)


def main() -> None:
    expected = _collect_expected(DIST)
    missing = [name for name in expected if not (DIST / name).exists()]
    if missing:
        print("Missing release artifacts:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
