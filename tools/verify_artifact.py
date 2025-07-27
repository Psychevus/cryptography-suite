import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_and_hash(tag: str) -> dict[str, str]:
    subprocess.check_call([sys.executable, "tools/reproducible_build.py"], cwd=ROOT)
    hashes = {}
    for artifact in DIST.glob("*"):
        hashes[artifact.name] = sha256(artifact)
    return hashes


def verify(artifact: Path, expected_hash: str) -> bool:
    return sha256(artifact) == expected_hash


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: verify_artifact.py ARTIFACT EXPECTED_HASH")
        sys.exit(1)
    artifact = Path(sys.argv[1])
    if verify(artifact, sys.argv[2]):
        print("Artifact matches expected hash")
    else:
        print("Mismatch!", file=sys.stderr)
        sys.exit(2)
