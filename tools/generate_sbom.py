"""Generate a CycloneDX SBOM for the project."""

from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def main() -> None:
    DIST.mkdir(exist_ok=True)
    output = DIST / "sbom.json"
    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "sbom",
                "--format",
                "cyclonedx-json",
                "--output",
                str(output),
            ],
            cwd=ROOT,
        )
    except subprocess.CalledProcessError:
        subprocess.check_call(
            [sys.executable, "-m", "cyclonedx_py", "-o", str(output)], cwd=ROOT
        )


if __name__ == "__main__":
    main()
