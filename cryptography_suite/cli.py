"""Command line utilities for zero-knowledge proofs."""
from __future__ import annotations

import argparse
import os
from hashlib import sha256

from .bulletproof import prove as bp_prove, verify as bp_verify, setup as bp_setup

try:
    from . import zksnark
    ZKSNARK_AVAILABLE = True
except Exception:
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
    if not ZKSNARK_AVAILABLE:
        raise RuntimeError("PySNARK not installed")
    parser = argparse.ArgumentParser(description="SHA256 pre-image proof")
    parser.add_argument("preimage", help="Preimage string")
    args = parser.parse_args(argv)
    zksnark.setup()
    hash_hex, proof_path = zksnark.prove(args.preimage.encode())
    valid = zksnark.verify(hash_hex, proof_path)
    print(f"Hash: {hash_hex}\nProof valid: {valid}")

