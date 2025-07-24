"""Command line utilities for zero-knowledge proofs."""
from __future__ import annotations

import argparse
from .errors import MissingDependencyError, DecryptionError

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
        raise MissingDependencyError("PySNARK not installed")
    args = parser.parse_args(argv)
    if not ZKSNARK_AVAILABLE:
        raise MissingDependencyError("PySNARK not installed")
    zksnark.setup()
    hash_hex, proof_path = zksnark.prove(args.preimage.encode())
    valid = zksnark.verify(hash_hex, proof_path)
    print(f"Hash: {hash_hex}\nProof valid: {valid}")


def file_cli(argv: list[str] | None = None) -> None:
    """Encrypt or decrypt files using AES-GCM."""

    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument(
        "--in",
        dest="input_file",
        required=True,
        help="Path to the input file",
    )
    enc_parser.add_argument(
        "--out",
        dest="output_file",
        required=True,
        help="Path for the encrypted file",
    )
    enc_parser.add_argument(
        "--password",
        required=True,
        help="Password to derive encryption key",
    )

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument(
        "--in",
        dest="input_file",
        required=True,
        help="Path to the encrypted file",
    )
    dec_parser.add_argument(
        "--out",
        dest="output_file",
        required=True,
        help="Destination for the decrypted file",
    )
    dec_parser.add_argument(
        "--password",
        required=True,
        help="Password used during encryption",
    )

    args = parser.parse_args(argv)

    from .symmetric import encrypt_file, decrypt_file

    try:
        if args.command == "encrypt":
            encrypt_file(args.input_file, args.output_file, args.password)
            print(f"Encrypted file written to {args.output_file}")
        else:
            decrypt_file(args.input_file, args.output_file, args.password)
            print(f"Decrypted file written to {args.output_file}")
    except Exception as exc:  # pragma: no cover - high-level error reporting
        _handle_cli_error(exc)


def _handle_cli_error(exc: Exception) -> None:
    """Display user-friendly CLI error messages."""

    if isinstance(exc, MissingDependencyError):
        print(f"Missing dependency: {exc}. Please install the required module.")
    elif isinstance(exc, DecryptionError):
        print("Password is incorrect or file corrupted.")
    else:
        print(f"Error: {exc}")
