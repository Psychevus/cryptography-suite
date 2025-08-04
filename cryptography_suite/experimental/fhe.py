"""Homomorphic encryption helpers (experimental)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
    from ..homomorphic import (
        PYFHEL_AVAILABLE as FHE_AVAILABLE,
        add as fhe_add,
        decrypt as fhe_decrypt,
        encrypt as fhe_encrypt,
        keygen as fhe_keygen,
        load_context as fhe_load_context,
        multiply as fhe_multiply,
        serialize_context as fhe_serialize_context,
    )

    __all__ = [
        "FHE_AVAILABLE",
        "fhe_keygen",
        "fhe_encrypt",
        "fhe_decrypt",
        "fhe_add",
        "fhe_multiply",
        "fhe_serialize_context",
        "fhe_load_context",
    ]
else:  # pragma: no cover - executed when experimental disabled
    raise ImportError(
        "FHE features are experimental. Set CRYPTOSUITE_ALLOW_EXPERIMENTAL=1 to enable."
    )
