"""Command line utilities for zero-knowledge proofs."""

from __future__ import annotations

import argparse
from .errors import MissingDependencyError, DecryptionError
from .protocols import generate_totp
from .hashing import (
    sha3_256_hash,
    sha3_512_hash,
    blake2b_hash,
    blake3_hash,
)
from .pqc import (
    generate_kyber_keypair,
    generate_dilithium_keypair,
    generate_sphincs_keypair,
    PQCRYPTO_AVAILABLE,
)
from .protocols.key_management import KeyManager

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

    parser = argparse.ArgumentParser(description="Encrypt or decrypt files")
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


def keygen_cli(argv: list[str] | None = None) -> None:
    """Generate RSA or post-quantum key pairs."""

    parser = argparse.ArgumentParser(description=keygen_cli.__doc__)
    sub = parser.add_subparsers(dest="scheme", required=True)

    rsa_p = sub.add_parser("rsa", help="Generate an RSA key pair")
    rsa_p.add_argument("--private", required=True, help="Private key path")
    rsa_p.add_argument("--public", required=True, help="Public key path")
    rsa_p.add_argument("--password", required=True, help="Password for private key")

    if PQCRYPTO_AVAILABLE:
        sub.add_parser("dilithium", help="Generate a Dilithium key pair")
        sub.add_parser("kyber", help="Generate a Kyber key pair")
        if generate_sphincs_keypair:
            sub.add_parser("sphincs", help="Generate a SPHINCS+ key pair")

    args = parser.parse_args(argv)

    if args.scheme == "rsa":
        km = KeyManager()
        km.generate_rsa_keypair_and_save(args.private, args.public, args.password)
        print(f"RSA keys saved to {args.private} and {args.public}")
    else:
        if args.scheme == "dilithium":
            pk, sk = generate_dilithium_keypair()
        elif args.scheme == "kyber":
            pk, sk = generate_kyber_keypair()
        else:
            pk, sk = generate_sphincs_keypair()
        print(pk.hex())
        print(sk.hex())


def hash_cli(argv: list[str] | None = None) -> None:
    """Digest a file using various hashing algorithms."""

    parser = argparse.ArgumentParser(description=hash_cli.__doc__)
    parser.add_argument("file", help="File to hash")
    parser.add_argument(
        "--algorithm",
        choices=["sha3-256", "sha3-512", "blake2b", "blake3"],
        default="sha3-256",
    )
    args = parser.parse_args(argv)

    with open(args.file, "rb") as f:
        data = f.read().decode("utf-8", errors="ignore")

    if args.algorithm == "sha3-256":
        digest = sha3_256_hash(data)
    elif args.algorithm == "sha3-512":
        digest = sha3_512_hash(data)
    elif args.algorithm == "blake2b":
        digest = blake2b_hash(data)
    else:
        digest = blake3_hash(data)

    print(digest)


def otp_cli(argv: list[str] | None = None) -> None:
    """Generate a time-based OTP code for a secret."""

    parser = argparse.ArgumentParser(description=otp_cli.__doc__)
    parser.add_argument("--secret", required=True, help="Base32 encoded secret")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--digits", type=int, default=6)
    parser.add_argument(
        "--algorithm",
        choices=["sha1", "sha256", "sha512"],
        default="sha1",
    )
    args = parser.parse_args(argv)

    code = generate_totp(
        args.secret,
        interval=args.interval,
        digits=args.digits,
        algorithm=args.algorithm,
    )
    print(code)


def main(argv: list[str] | None = None) -> None:
    """Unified command line interface for the cryptography suite."""

    parser = argparse.ArgumentParser(description=main.__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen_parser = sub.add_parser(
        "keygen", help="Generate key pairs", description=keygen_cli.__doc__
    )
    keygen_parser.add_argument(
        "scheme", choices=["rsa", "dilithium", "kyber", "sphincs"], help="Key scheme"
    )
    keygen_parser.add_argument("--private", help="Private key path")
    keygen_parser.add_argument("--public", help="Public key path")
    keygen_parser.add_argument("--password", help="Private key password")

    hash_parser = sub.add_parser(
        "hash", help="Hash a file", description=hash_cli.__doc__
    )
    hash_parser.add_argument("file")
    hash_parser.add_argument(
        "--algorithm",
        choices=["sha3-256", "sha3-512", "blake2b", "blake3"],
        default="sha3-256",
    )

    otp_parser = sub.add_parser(
        "otp", help="Generate a TOTP", description=otp_cli.__doc__
    )
    otp_parser.add_argument("--secret", required=True)
    otp_parser.add_argument("--interval", type=int, default=30)
    otp_parser.add_argument("--digits", type=int, default=6)
    otp_parser.add_argument(
        "--algorithm",
        choices=["sha1", "sha256", "sha512"],
        default="sha1",
    )

    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        argv2: list[str] = [args.scheme]
        if args.private:
            argv2.extend(["--private", args.private])
        if args.public:
            argv2.extend(["--public", args.public])
        if args.password:
            argv2.extend(["--password", args.password])
        keygen_cli(argv2)
    elif args.cmd == "hash":
        hash_cli([args.file, f"--algorithm={args.algorithm}"])
    else:
        otp_cli(
            [
                f"--secret={args.secret}",
                f"--interval={args.interval}",
                f"--digits={args.digits}",
                f"--algorithm={args.algorithm}",
            ]
        )
