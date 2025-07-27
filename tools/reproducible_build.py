import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def build(sdist: bool = True, wheel: bool = True) -> None:
    """Build package deterministically."""
    with TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env.setdefault("SOURCE_DATE_EPOCH", "1700000000")
        cmd = [sys.executable, "-m", "build"]
        if not sdist:
            cmd.append("--wheel")
        if not wheel:
            cmd.append("--sdist")
        subprocess.check_call(cmd + ["--outdir", tmp], env=env, cwd=ROOT)
        DIST.mkdir(exist_ok=True)
        for artifact in Path(tmp).iterdir():
            target = DIST / artifact.name
            artifact.replace(target)


if __name__ == "__main__":
    build()
