"""Command line utilities for zero-knowledge proofs."""

from __future__ import annotations

from . import __version__

import argparse
import subprocess
import sys
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
    SPHINCS_AVAILABLE,
)
from .protocols.key_management import KeyManager
from .utils import KeyVault

from .zk.bulletproof import (
    prove as bp_prove,
    verify as bp_verify,
    setup as bp_setup,
    BULLETPROOF_AVAILABLE,
)
from .crypto_backends import available_backends

try:
    from .experimental import zksnark

    ZKSNARK_AVAILABLE = getattr(zksnark, "ZKSNARK_AVAILABLE", False)
except Exception:
    zksnark = None  # type: ignore[assignment]
    ZKSNARK_AVAILABLE = False


def bulletproof_cli(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bulletproof range proof")
    parser.add_argument("value", type=int, help="Integer in [0, 2^32)")
    args = parser.parse_args(argv)
    try:
        if not BULLETPROOF_AVAILABLE:
            raise MissingDependencyError(
                "Bulletproof ZKP requires 'petlib'. Install it with: pip install cryptography-suite[zkp]"
            )
        bp_setup()
        proof, commitment, nonce = bp_prove(args.value)
        ok = bp_verify(proof, commitment)
        print(f"Proof valid: {ok}")
    except Exception as exc:  # pragma: no cover - graceful CLI errors
        _handle_cli_error(exc)


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
        print(exc)
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
        if SPHINCS_AVAILABLE:
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
        sk_bytes = bytes(sk) if isinstance(sk, KeyVault) else sk
        print(sk_bytes.hex())


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


def backends_cli(argv: list[str] | None = None) -> None:
    """Manage registered crypto backends."""

    parser = argparse.ArgumentParser(description="Backend management")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="List available backends")
    args = parser.parse_args(argv)

    if args.action == "list":
        for name in available_backends():
            print(name)


def keystore_cli(argv: list[str] | None = None) -> None:
    """Manage registered keystores."""

    from pathlib import Path
    from .keystores import load_plugins, list_keystores, get_keystore

    parser = argparse.ArgumentParser(description="Keystore management")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="List available keystores")
    sub.add_parser("test", help="Test keystore connectivity")
    imp = sub.add_parser("import", help="Import a PEM key into the local keystore")
    imp.add_argument("--file", required=True)
    imp.add_argument("--name", required=True)
    imp.add_argument("--password")
    mig = sub.add_parser("migrate", help="Migrate keys between keystores")
    mig.add_argument("--from", dest="src", required=True)
    mig.add_argument("--to", dest="dst", required=True)
    mig.add_argument("--key", dest="key")
    mig.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    load_plugins()

    if args.action == "list":
        for name in list_keystores():
            cls = get_keystore(name)
            status = getattr(cls, "status", "unknown")
            extra = ""
            try:
                ks = cls()
                label = getattr(ks, "token_label", None)
                serial = getattr(ks, "token_serial", None)
                if label and serial:
                    extra = f" - {label} ({serial})"
            except Exception:
                pass
            print(f"{name} ({status}){extra}")
    elif args.action == "test":
        for name in list_keystores():
            cls = get_keystore(name)
            extra = ""
            try:
                ks = cls()
                ok = ks.test_connection()
                if ok:
                    label = getattr(ks, "token_label", None)
                    serial = getattr(ks, "token_serial", None)
                    if label and serial:
                        extra = f" - {label} ({serial})"
            except Exception:
                ok = False
            print(f"{name}: {'ok' if ok else 'fail'}{extra}")
    elif args.action == "import":
        ks_cls = get_keystore("local")
        ks = ks_cls()
        pem = Path(args.file).read_bytes()
        new_id = ks.import_key(pem, args.name, args.password)
        print(new_id)
    elif args.action == "migrate":
        import hashlib

        try:
            Src = get_keystore(args.src)
            Dst = get_keystore(args.dst)
        except KeyError as exc:
            print(f"Unknown keystore: {exc}")
            sys.exit(1)

        src = Src()
        dst = Dst()
        ids = [args.key] if args.key else src.list_keys()
        stats = []
        for key_id in ids:
            try:
                raw, meta = src.export_key(key_id)
                new_id = key_id
                if not args.dry_run:
                    new_id = dst.import_key(raw, meta)
                fp = hashlib.sha256(raw).hexdigest()[:16]
                stats.append((key_id, new_id, meta.get("type"), fp))
                print(f"{key_id} -> {new_id}")
            except Exception as exc:  # pragma: no cover - user feedback
                print(f"Error migrating {key_id}: {exc}")
                sys.exit(1)
        if stats:
            header = ("Old ID", "New ID", "Algorithm", "Fingerprint")
            row = "{:<20} {:<20} {:<10} {:<32}"
            print(row.format(*header))
            for old_id, new_id, algo, fp in stats:
                print(row.format(old_id, new_id, algo, fp))


def export_cli(argv: list[str] | None = None) -> None:
    """Export a pipeline definition to a formal verification model."""

    parser = argparse.ArgumentParser(description=export_cli.__doc__)
    parser.add_argument("pipeline", help="Path to pipeline YAML file")
    parser.add_argument("--format", choices=["proverif", "tamarin"], default="proverif")
    parser.add_argument(
        "--track", action="append", default=[], help="Secret names to monitor"
    )
    args = parser.parse_args(argv)

    import yaml  # type: ignore
    from typing import Any
    from .pipeline import Pipeline, CryptoModule

    class Stub:
        def __init__(self, name: str) -> None:
            self._name = name

        def run(self, data: bytes) -> bytes:  # pragma: no cover - stub
            return data

        def to_proverif(self) -> str:
            return f"(* {self._name} *)"

        def to_tamarin(self) -> str:
            return f"# {self._name}"

    with open(args.pipeline, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or []

    modules: list[CryptoModule[Any, Any]] = [
        Stub(item["module"] if isinstance(item, dict) else str(item)) for item in config
    ]
    pipe: Pipeline[Any, Any] = Pipeline(modules)
    for name in args.track:
        pipe.track_secret(name)
    if args.format == "proverif":
        print(pipe.to_proverif())
    else:
        print(pipe.to_tamarin())


def gen_cli(argv: list[str] | None = None) -> None:
    """Generate application skeletons from a pipeline."""

    parser = argparse.ArgumentParser(description=gen_cli.__doc__)
    parser.add_argument("--target", choices=["fastapi", "flask", "node"], required=True)
    parser.add_argument("--pipeline", required=True, help="Pipeline YAML file")
    parser.add_argument("--output", help="Output directory")
    args = parser.parse_args(argv)

    from .codegen import generate

    generate(args.target, args.pipeline, args.output)


def fuzz_cli(argv: list[str] | None = None) -> None:
    """Run Atheris fuzzing harnesses."""

    parser = argparse.ArgumentParser(description=fuzz_cli.__doc__)
    parser.add_argument("--pipeline", help="Pipeline config YAML")
    parser.add_argument("--runs", type=int, default=1000)
    args = parser.parse_args(argv)

    script = "fuzz/fuzz_aes.py" if not args.pipeline else "fuzz/fuzz_pipeline.py"
    cmd = [sys.executable, script, f"-runs={args.runs}"]
    if args.pipeline:
        cmd.append(args.pipeline)
    subprocess.run(cmd, check=False)


def main(argv: list[str] | None = None) -> None:
    """Unified command line interface for the cryptography suite."""

    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
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

    export_parser = sub.add_parser(
        "export", help="Export pipeline", description=export_cli.__doc__
    )
    export_parser.add_argument("pipeline")
    export_parser.add_argument(
        "--format", choices=["proverif", "tamarin"], default="proverif"
    )
    export_parser.add_argument(
        "--track", action="append", default=[], help="Secret names to monitor"
    )

    gen_parser = sub.add_parser(
        "gen", help="Generate application skeleton", description=gen_cli.__doc__
    )
    gen_parser.add_argument(
        "--target", choices=["fastapi", "flask", "node"], required=True
    )
    gen_parser.add_argument("--pipeline", required=True)
    gen_parser.add_argument("--output")

    back_parser = sub.add_parser(
        "backends", help="Manage crypto backends", description=backends_cli.__doc__
    )
    back_parser.add_argument("action", choices=["list"], nargs="?")

    fuzz_parser = sub.add_parser(
        "fuzz", help="Run fuzzing", description=fuzz_cli.__doc__
    )
    fuzz_parser.add_argument("--pipeline")
    fuzz_parser.add_argument("--runs", type=int, default=1000)

    ks_parser = sub.add_parser(
        "keystore", help="Manage keystores", description=keystore_cli.__doc__
    )
    ks_parser.add_argument("action", choices=["list", "test", "migrate"])
    ks_parser.add_argument("--from", dest="src")
    ks_parser.add_argument("--to", dest="dst")
    ks_parser.add_argument("--key", dest="key")
    ks_parser.add_argument("--dry-run", action="store_true")

    # File operations subcommand
    file_parser = sub.add_parser(
        "file",
        help="Encrypt or decrypt files",
        description=file_cli.__doc__,
    )
    file_sub = file_parser.add_subparsers(dest="file_cmd", required=True)
    f_enc = file_sub.add_parser("encrypt", help="Encrypt a file")
    f_enc.add_argument("--in", dest="input_file", required=True)
    f_enc.add_argument("--out", dest="output_file", required=True)
    f_enc.add_argument("--password", required=True)
    f_dec = file_sub.add_parser("decrypt", help="Decrypt a file")
    f_dec.add_argument("--in", dest="input_file", required=True)
    f_dec.add_argument("--out", dest="output_file", required=True)
    f_dec.add_argument("--password", required=True)

    # Backward compatibility aliases
    enc_alias = sub.add_parser(
        "encrypt",
        help=argparse.SUPPRESS,
        description="Alias for 'file encrypt'",
    )
    enc_alias.add_argument("--in", dest="input_file", required=True)
    enc_alias.add_argument("--out", dest="output_file", required=True)
    enc_alias.add_argument("--password", required=True)
    dec_alias = sub.add_parser(
        "decrypt",
        help=argparse.SUPPRESS,
        description="Alias for 'file decrypt'",
    )
    dec_alias.add_argument("--in", dest="input_file", required=True)
    dec_alias.add_argument("--out", dest="output_file", required=True)
    dec_alias.add_argument("--password", required=True)

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
    elif args.cmd == "export":
        argv2 = [args.pipeline, f"--format={args.format}"]
        for sec in args.track:
            argv2.extend(["--track", sec])
        export_cli(argv2)
    elif args.cmd == "gen":
        argv2 = [f"--target={args.target}", f"--pipeline={args.pipeline}"]
        if args.output:
            argv2.extend(["--output", args.output])
        gen_cli(argv2)
    elif args.cmd == "keystore":
        argv2 = [args.action]
        if args.src:
            argv2.extend(["--from", args.src])
        if args.dst:
            argv2.extend(["--to", args.dst])
        if args.key:
            argv2.extend(["--key", args.key])
        if getattr(args, "dry_run", False):
            argv2.append("--dry-run")
        keystore_cli(argv2)
    elif args.cmd in ("file", "encrypt", "decrypt"):
        if args.cmd == "file":
            mode = args.file_cmd
        else:
            mode = args.cmd
        argv2 = [
            mode,
            "--in",
            args.input_file,
            "--out",
            args.output_file,
            "--password",
            args.password,
        ]
        file_cli(argv2)
    elif args.cmd == "backends":
        action_args: list[str] = []
        if args.action:
            action_args.append(args.action)
        backends_cli(action_args)
    elif args.cmd == "fuzz":
        argv2 = []  # reuse argument list without redeclaring type
        if args.pipeline:
            argv2.extend(["--pipeline", args.pipeline])
        argv2.extend(["--runs", str(args.runs)])
        fuzz_cli(argv2)
    else:
        otp_cli(
            [
                f"--secret={args.secret}",
                f"--interval={args.interval}",
                f"--digits={args.digits}",
                f"--algorithm={args.algorithm}",
            ]
        )
