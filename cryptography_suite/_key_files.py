from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_bytes(
    path: str | Path,
    data: bytes,
    *,
    mode: int = 0o600,
    overwrite: bool = False,
) -> None:
    """Atomically write bytes while preserving existing files on failure."""

    target = Path(path)
    if not target.parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {target.parent}")
    if target.is_symlink():
        raise FileExistsError(f"Refusing to write through symlink: {target}")
    if target.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {target}")

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_path, mode)
        except OSError:
            pass

        if target.is_symlink():
            raise FileExistsError(f"Refusing to write through symlink: {target}")
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {target}")
        os.replace(tmp_path, target)
        try:
            os.chmod(target, mode)
        except OSError:
            pass
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
