"""Bulletproof range proof utilities using pybulletproofs.

This module provides simple wrappers around the `pybulletproofs` library to
create and verify Bulletproof range proofs for values in the range
``[0, 2**32)`` using Pedersen commitments on secp256k1.
"""
from __future__ import annotations

from typing import Tuple
from ..errors import MissingDependencyError, ProtocolError

try:  # pragma: no cover - handle missing optional dependency
    import pybulletproofs
    BULLETPROOF_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency not present
    pybulletproofs = None  # type: ignore[assignment]
    BULLETPROOF_AVAILABLE = False

BITS = 32


def setup() -> None:
    """No-op setup placeholder for API compatibility."""
    return None


def prove(value: int) -> Tuple[bytes, bytes, bytes]:
    """Generate a Bulletproof range proof for ``value``.

    Parameters
    ----------
    value:
        Integer in the range ``[0, 2**32)``.

    Returns
    -------
    Tuple[bytes, bytes, bytes]
        ``(proof, commitment, nonce)`` produced by ``pybulletproofs``.
    """
    if not BULLETPROOF_AVAILABLE:
        raise MissingDependencyError(
            "pybulletproofs is required for bulletproof range proofs"
        )

    if not 0 <= value < 2 ** BITS:
        raise ProtocolError("value out of range")

    proof, commitment, nonce = pybulletproofs.zkrp_prove(value, BITS)
    return bytes(proof), bytes(commitment), bytes(nonce)


def verify(proof: bytes, commitment: bytes) -> bool:
    """Verify a Bulletproof range proof."""
    if not BULLETPROOF_AVAILABLE:
        raise MissingDependencyError(
            "pybulletproofs is required for bulletproof range proofs"
        )
    return bool(pybulletproofs.zkrp_verify(proof, commitment))
