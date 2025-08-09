"""Runtime warnings for experimental modules."""

from __future__ import annotations

import sys
import warnings
from typing import Set


_SHOWN: Set[str] = set()


def experimental_warning(module_name: str) -> None:
    """Emit a loud warning banner for experimental modules.

    The banner and warning are printed only once per process for each module.
    """
    if module_name in _SHOWN:
        return
    _SHOWN.add(module_name)

    banner = (
        "\n" +
        "!" * 70 + "\n" +
        f"! WARNING: {module_name} is EXPERIMENTAL!\n" +
        "! Use at your own risk.\n" +
        "!" * 70 + "\n"
    )
    print(banner, file=sys.stderr)
    warnings.warn(
        f"{module_name} is experimental and unsupported", RuntimeWarning, stacklevel=2
    )
