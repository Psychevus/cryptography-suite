"""Validate presence of release security artifacts."""

from __future__ import annotations
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def main() -> None:
    expected = ["sbom.json", "provenance.intoto.jsonl"]
    artifacts = list(DIST.glob("*.whl")) + list(DIST.glob("*.tar.gz"))
    for art in artifacts:
        expected.extend([art.name + ".sig", art.name + ".cert"])
    missing = [name for name in expected if not (DIST / name).exists()]
    if missing:
        print("Missing release artifacts:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
