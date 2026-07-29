from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class BuiltArtifacts:
    wheel: Path
    sdist: Path


@pytest.fixture(scope="session")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> BuiltArtifacts:
    output = tmp_path_factory.mktemp("phase3-artifacts")
    subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(output.glob("*.whl"))
    sdist = next(output.glob("*.tar.gz"))
    return BuiltArtifacts(wheel=wheel, sdist=sdist)
