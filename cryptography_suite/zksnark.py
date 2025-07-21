"""Minimal PySNARK example: SHA256 pre-image proof."""
from __future__ import annotations

from hashlib import sha256
from typing import Tuple

try:  # pragma: no cover - optional dependency
    from pysnark.runtime import PrivVal, snark, run
    from pysnark.hash import sha256 as snark_sha256
    from pysnark import snarksetup
except Exception as exc:  # pragma: no cover - library missing
    raise ImportError(
        "PySNARK is required for zk-SNARK proofs"
    ) from exc


def setup() -> None:
    """Run trusted setup for PySNARK."""
    snarksetup("groth16")


def prove(preimage: bytes) -> Tuple[str, str]:
    """Create a zk-SNARK proving knowledge of ``preimage`` whose SHA256 hash is
    public.

    Returns the tuple ``(hash_hex, proof_path)``.
    """
    secret = PrivVal(int.from_bytes(preimage, "big"))
    digest_bits = snark_sha256(secret)
    digest = int(digest_bits.val).to_bytes(32, "big")
    hash_hex = digest.hex()
    proof_path = snark.prove()
    return hash_hex, proof_path


def verify(hash_hex: str, proof_path: str) -> bool:
    """Verify a generated proof."""
    return run.verify(hash_hex, proof_path)

