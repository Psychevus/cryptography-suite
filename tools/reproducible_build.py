import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory, NamedTemporaryFile
import gzip
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def build(sdist: bool = True, wheel: bool = True) -> None:
    """Build package deterministically."""
    with TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env.setdefault("SOURCE_DATE_EPOCH", "1700000000")
        env.setdefault("PYTHONHASHSEED", "0")
        cmd = [sys.executable, "-m", "build"]
        if not sdist:
            cmd.append("--wheel")
        if not wheel:
            cmd.append("--sdist")
        subprocess.check_call(cmd + ["--outdir", tmp], env=env, cwd=ROOT)
        DIST.mkdir(exist_ok=True)
        for artifact in Path(tmp).iterdir():
            target = DIST / artifact.name
            if artifact.name.endswith(".tar.gz"):
                base = artifact.name[:-7]
                with TemporaryDirectory() as tdir:
                    subprocess.check_call(["tar", "xf", artifact, "-C", tdir])
                    temp_tar = Path(tdir) / f"{base}.tar"
                    subprocess.check_call([
                        "tar",
                        "--sort=name",
                        "--owner=0",
                        "--group=0",
                        "--numeric-owner",
                        f"--mtime=@{env['SOURCE_DATE_EPOCH']}",
                        "-cf",
                        temp_tar,
                        "-C",
                        tdir,
                        base,
                    ])
                    subprocess.check_call(["gzip", "-n", temp_tar])
                    (temp_tar.with_suffix(".tar.gz")).replace(target)
            elif artifact.suffix == ".gz":
                with NamedTemporaryFile(delete=False) as temp:
                    with gzip.open(artifact, "rb") as f_in:
                        shutil.copyfileobj(f_in, temp)
                with open(temp.name, "rb") as f_in, open(target, "wb") as raw_out:
                    with gzip.GzipFile(fileobj=raw_out, mode="wb", mtime=0) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.unlink(temp.name)
            else:
                artifact.replace(target)


if __name__ == "__main__":
    build()
