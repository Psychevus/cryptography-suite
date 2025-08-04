"""Zero-knowledge proof helpers (experimental)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
    from ..zk import bulletproof, zksnark
    from ..zk.bulletproof import BULLETPROOF_AVAILABLE
    from ..zk.zksnark import ZKSNARK_AVAILABLE

    __all__ = [
        "BULLETPROOF_AVAILABLE",
        "bulletproof",
        "ZKSNARK_AVAILABLE",
        "zksnark",
    ]
else:  # pragma: no cover - executed when experimental disabled
    raise ImportError(
        "Zero-knowledge helpers are experimental. Set CRYPTOSUITE_ALLOW_EXPERIMENTAL=1 to enable."
    )
