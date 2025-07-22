"""Command line utilities for zero-knowledge proofs."""
from __future__ import annotations

import argparse

from .zk.bulletproof import prove as bp_prove, verify as bp_verify, setup as bp_setup

try:
    from . import zksnark

    ZKSNARK_AVAILABLE = getattr(zksnark, "ZKSNARK_AVAILABLE", False)
except Exception:
    zksnark = None  # type: ignore[assignment]
    ZKSNARK_AVAILABLE = False


def bulletproof_cli(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bulletproof range proof")
    parser.add_argument("value", type=int, help="Integer in [0, 2^32)")
    args = parser.parse_args(argv)
    bp_setup()
    proof, commitment, nonce = bp_prove(args.value)
    ok = bp_verify(proof, commitment)
    print(f"Proof valid: {ok}")


def zksnark_cli(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="SHA256 pre-image proof")
    parser.add_argument("preimage", help="Preimage string")
    if not ZKSNARK_AVAILABLE and argv and not any(a in ("-h", "--help") for a in argv):
        raise RuntimeError("PySNARK not installed")
    args = parser.parse_args(argv)
    if not ZKSNARK_AVAILABLE:
        raise RuntimeError("PySNARK not installed")
    zksnark.setup()
    hash_hex, proof_path = zksnark.prove(args.preimage.encode())
    valid = zksnark.verify(hash_hex, proof_path)
    print(f"Hash: {hash_hex}\nProof valid: {valid}")
