"""Compatibility gate for experimental homomorphic encryption helpers.

The FHE implementation lives in :mod:`cryptography_suite.experimental.fhe` and
is not part of the stable production API.
"""

# ruff: noqa: E402, I001

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if not (TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL")):
    raise ImportError(
        "Homomorphic encryption helpers are experimental. Set "
        "CRYPTOSUITE_ALLOW_EXPERIMENTAL=1 and import "
        "cryptography_suite.experimental.fhe."
    )

from .experimental.fhe import (  # noqa: E402
    FHE_AVAILABLE as PYFHEL_AVAILABLE,
    HEBackend,
    HEParams,
    PyfhelBackend,
    add,
    decrypt,
    encrypt,
    keygen,
    load_context,
    multiply,
    serialize_context,
)

__all__ = [
    "PYFHEL_AVAILABLE",
    "HEParams",
    "HEBackend",
    "PyfhelBackend",
    "keygen",
    "encrypt",
    "decrypt",
    "add",
    "multiply",
    "serialize_context",
    "load_context",
]
