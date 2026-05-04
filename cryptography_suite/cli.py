"""Command line utilities for zero-knowledge proofs."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Protocol, cast

from blake3 import blake3

from . import __version__
from .core.logging import configure_structured_logging, get_structured_logger, log_event
from .core.operations import (
    METRICS,
    install_signal_handlers,
    run_command,
)
from .crypto_backends import available_backends
from .debug import redact_message
from .errors import DecryptionError, MissingDependencyError
from .pqc import (
    PQCRYPTO_AVAILABLE,
    SPHINCS_AVAILABLE,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
)
from .protocols import generate_totp
from .protocols.key_management import KeyManager
from .symmetric.kdf import DEFAULT_KDF
from .utils import _detect_private_pem_encryption
from .zk.bulletproof import (
    BULLETPROOF_AVAILABLE,
)
from .zk.bulletproof import (
    prove as bp_prove,
)
from .zk.bulletproof import (
    setup as bp_setup,
)
from .zk.bulletproof import (
    verify as bp_verify,
)

_OUTPUT_FORMAT = "text"


class _HasherLike(Protocol):
    def update(self, data: bytes) -> object: ...

    def hexdigest(self) -> str: ...


def _set_output_format(fmt: str) -> None:
    """Configure global CLI output format."""

    global _OUTPUT_FORMAT
    _OUTPUT_FORMAT = fmt


def _emit(text: str, payload: dict[str, object] | None = None) -> None:
    """Emit command output in text (default) or JSON format."""

    if _OUTPUT_FORMAT == "json" and payload is not None:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(text)


def _add_password_source_args(parser: argparse.ArgumentParser) -> None:
    """Add safe password input sources to a parser."""

    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from the first line of standard input",
    )
    parser.add_argument(
        "--password-env",
        help=(
            "Read the password from an environment variable; less safe than "
            "prompt/stdin/fd"
        ),
    )
    parser.add_argument(
        "--password-file",
        help="Read the password from a local file; protect file permissions carefully",
    )
    parser.add_argument(
        "--password-fd",
        type=int,
        help="Read the password from an already-open file descriptor",
    )


def _append_password_source_args(argv: list[str], args: argparse.Namespace) -> None:
    if getattr(args, "password_stdin", False):
        argv.append("--password-stdin")
    if getattr(args, "password_env", None):
        argv.extend(["--password-env", args.password_env])
    if getattr(args, "password_file", None):
        argv.extend(["--password-file", args.password_file])
    if getattr(args, "password_fd", None) is not None:
        argv.extend(["--password-fd", str(args.password_fd)])


def _resolve_password(
    args: argparse.Namespace,
    prompt: str,
    *,
    required: bool = True,
) -> str | None:
    sources = [
        bool(getattr(args, "password_stdin", False)),
        getattr(args, "password_env", None) is not None,
        getattr(args, "password_file", None) is not None,
        getattr(args, "password_fd", None) is not None,
    ]
    if sum(sources) > 1:
        raise ValueError("Choose only one password input source.")
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline().rstrip("\r\n")
    elif getattr(args, "password_env", None) is not None:
        env_name = args.password_env
        password = os.environ.get(env_name)
        if password is None:
            raise ValueError(f"Environment variable is not set: {env_name}")
    elif getattr(args, "password_file", None) is not None:
        password = Path(args.password_file).read_text(encoding="utf-8").rstrip("\r\n")
    elif getattr(args, "password_fd", None) is not None:
        fd = os.dup(args.password_fd)
        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as handle:
            password = handle.readline().rstrip("\r\n")
    elif required:
        password = getpass.getpass(f"{prompt}: ")
    else:
        return None

    if not password:
        raise ValueError(f"{prompt} cannot be empty.")
    return password


try:
    from .experimental import zksnark

    ZKSNARK_AVAILABLE = getattr(zksnark, "ZKSNARK_AVAILABLE", False)
except Exception:
    zksnark = None
    ZKSNARK_AVAILABLE = False


def bulletproof_cli(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bulletproof range proof")
    parser.add_argument("value", type=int, help="Integer in [0, 2^32)")
    args = parser.parse_args(argv)
    try:
        if not BULLETPROOF_AVAILABLE:
            raise MissingDependencyError(
                "Bulletproof ZKP requires 'petlib'. Install it with: "
                "pip install cryptography-suite[zk]"
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
    _add_password_source_args(enc_parser)
    enc_parser.add_argument(
        "--kdf",
        choices=["argon2", "scrypt", "pbkdf2"],
        default=DEFAULT_KDF,
        help="KDF for key derivation (stored in new-format file headers)",
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
    _add_password_source_args(dec_parser)
    dec_parser.add_argument(
        "--kdf",
        choices=["argon2", "scrypt", "pbkdf2"],
        default=DEFAULT_KDF,
        help="Legacy fallback KDF (ignored for new-format files)",
    )
    dec_parser.add_argument(
        "--allow-legacy-format",
        action="store_true",
        help="Explicitly allow pre-v2 unauthenticated-header file formats",
    )

    args = parser.parse_args(argv)

    from .symmetric import decrypt_file, encrypt_file

    try:
        # Keep CLI path checks lightweight for compatibility with test doubles.
        # The underlying crypto/file helpers enforce concrete filesystem semantics.
        _validate_output_parent(args.output_file)
        password = cast(str, _resolve_password(args, "File password"))
        if args.command == "encrypt":
            encrypt_file(args.input_file, args.output_file, password, kdf=args.kdf)
            _emit(
                f"Encrypted file written to {args.output_file}",
                {
                    "command": "file encrypt",
                    "output_file": args.output_file,
                    "status": "ok",
                },
            )
        else:
            decrypt_file(
                args.input_file,
                args.output_file,
                password,
                kdf=args.kdf,
                allow_legacy_format=args.allow_legacy_format,
            )
            _emit(
                f"Decrypted file written to {args.output_file}",
                {
                    "command": "file decrypt",
                    "output_file": args.output_file,
                    "status": "ok",
                },
            )
    except Exception as exc:  # pragma: no cover - high-level error reporting
        _handle_cli_error(exc)


def _handle_cli_error(exc: Exception) -> None:
    """Display user-friendly CLI error messages."""

    safe_error = redact_message(str(exc))
    if isinstance(exc, MissingDependencyError):
        _emit(safe_error, {"error": safe_error, "error_type": "missing_dependency"})
    elif isinstance(exc, DecryptionError):
        _emit(
            "Password is incorrect or file corrupted.",
            {
                "error": "Password is incorrect or file corrupted.",
                "error_type": "decryption_error",
            },
        )
    else:
        _emit(
            f"Error: {safe_error}",
            {"error": safe_error, "error_type": exc.__class__.__name__},
        )


def _validate_regular_file(path_str: str, label: str) -> None:
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        raise ValueError(f"{label} does not exist or is not a regular file: {path}")


def _validate_output_parent(path_str: str) -> None:
    parent = Path(path_str).resolve().parent
    if not parent.exists() or not parent.is_dir():
        raise ValueError(f"Output directory does not exist: {parent}")


def _raw_private_key_is_unencrypted(raw: bytes, meta: dict[str, object]) -> bool:
    encrypted_meta = meta.get("encrypted")
    if encrypted_meta is False:
        return True
    detected = _detect_private_pem_encryption(raw)
    return detected is False


def _keystore_import_key(
    store: Any,
    raw: bytes,
    meta: dict[str, object],
    *,
    allow_unencrypted: bool,
) -> str:
    import_key = store.import_key
    try:
        return cast(
            str,
            import_key(
                raw,
                meta,
                allow_unencrypted=allow_unencrypted,
            ),
        )
    except TypeError as exc:
        if "allow_unencrypted" not in str(exc):
            raise
        return cast(str, import_key(raw, meta))


def keygen_cli(argv: list[str] | None = None) -> None:
    """Generate RSA or post-quantum key pairs."""

    parser = argparse.ArgumentParser(description=keygen_cli.__doc__)
    sub = parser.add_subparsers(dest="scheme", required=True)

    rsa_p = sub.add_parser("rsa", help="Generate an RSA key pair")
    rsa_p.add_argument("--private", required=True, help="Private key path")
    rsa_p.add_argument("--public", required=True, help="Public key path")
    _add_password_source_args(rsa_p)

    if PQCRYPTO_AVAILABLE:
        sub.add_parser("dilithium", help="Generate a Dilithium key pair")
        sub.add_parser("kyber", help="Generate a Kyber key pair")
        if SPHINCS_AVAILABLE:
            sub.add_parser("sphincs", help="Generate a SPHINCS+ key pair")

    args = parser.parse_args(argv)

    if args.scheme == "rsa":
        km = KeyManager()
        password = cast(str, _resolve_password(args, "Private key password"))
        km.generate_rsa_keypair_and_save(args.private, args.public, password)
        print(f"RSA keys saved to {args.private} and {args.public}")
    else:
        if args.scheme == "dilithium":
            generate_dilithium_keypair()
        elif args.scheme == "kyber":
            generate_kyber_keypair()
        else:
            generate_sphincs_keypair()
        _emit(
            f"{args.scheme} private key material was generated but not printed.",
            {
                "private_key_output": "suppressed",
                "public_key_output": "suppressed",
                "scheme": args.scheme,
                "status": "generated",
            },
        )


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

    _validate_regular_file(args.file, "file")

    hasher: _HasherLike
    if args.algorithm == "sha3-256":
        hasher = hashlib.sha3_256()
    elif args.algorithm == "sha3-512":
        hasher = hashlib.sha3_512()
    elif args.algorithm == "blake2b":
        hasher = hashlib.blake2b()
    else:
        hasher = blake3()

    with open(args.file, "rb") as file_handle:
        while chunk := file_handle.read(8192):
            hasher.update(chunk)

    digest = hasher.hexdigest()

    _emit(
        digest,
        {
            "algorithm": args.algorithm,
            "digest": digest,
            "file": str(Path(args.file)),
        },
    )


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
    _emit(
        code,
        {
            "algorithm": args.algorithm,
            "code": code,
            "digits": args.digits,
            "interval": args.interval,
        },
    )


def backends_cli(argv: list[str] | None = None) -> None:
    """Manage registered crypto backends."""

    parser = argparse.ArgumentParser(description="Backend management")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="List available backends")
    args = parser.parse_args(argv)

    if args.action == "list":
        names = sorted(available_backends())
        if _OUTPUT_FORMAT == "json":
            _emit("", {"action": "list", "backends": names})
        else:
            for name in names:
                print(name)


def keystore_cli(argv: list[str] | None = None) -> None:
    """Manage registered keystores."""

    from .keystores import (
        KeyStoreCapability,
        failed_plugins,
        get_keystore,
        list_keystores,
        load_plugins,
        supports_capability,
    )

    parser = argparse.ArgumentParser(description="Keystore management")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="List available keystores")
    sub.add_parser("test", help="Test keystore connectivity")
    imp = sub.add_parser("import", help="Import a PEM key into the local keystore")
    imp.add_argument("--file", required=True)
    imp.add_argument("--name", required=True)
    _add_password_source_args(imp)
    imp.add_argument(
        "--unsafe-allow-unencrypted-private-key",
        action="store_true",
        help="Allow plaintext private key import for controlled testing/migration",
    )
    mig = sub.add_parser("migrate", help="Migrate keys between keystores")
    mig.add_argument("--from", dest="src", required=True)
    mig.add_argument("--to", dest="dst", required=True)
    mig.add_argument("--key", dest="key")
    mig.add_argument("--dry-run", action="store_true")
    mig.add_argument("--apply", action="store_true")
    mig.add_argument(
        "--unsafe-allow-unencrypted-private-key",
        action="store_true",
        help="Allow plaintext private key migration for controlled testing only",
    )
    args = parser.parse_args(argv)

    load_plugins()
    failed = failed_plugins()

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
        for name in failed:
            print(f"{name} (broken)")
        if failed:
            sys.exit(1)
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
        for name in failed:
            print(f"{name}: broken")
        if failed:
            sys.exit(1)
    elif args.action == "import":
        from .keystores.local import LocalKeyStore

        ks_cls = cast(type[LocalKeyStore], get_keystore("local"))
        ks = ks_cls()
        pem = Path(args.file).read_bytes()
        password = _resolve_password(args, "Key import password", required=False)
        new_id = ks.import_key(
            pem,
            args.name,
            password,
            allow_unencrypted=args.unsafe_allow_unencrypted_private_key,
        )
        print(new_id)
    elif args.action == "migrate":
        if not args.dry_run and not getattr(args, "apply", False):
            raise ValueError(
                "Refusing live key migration without --apply. "
                "Use --dry-run to preview changes."
            )

        try:
            Src = get_keystore(args.src)
            Dst = get_keystore(args.dst)
        except KeyError as exc:
            print(f"Unknown keystore: {exc}")
            sys.exit(1)

        src = Src()
        dst = Dst()

        if not supports_capability(src, KeyStoreCapability.EXPORT_PRIVATE_KEY):
            raise ValueError(
                f"Source keystore '{args.src}' does not support raw key export. "
                "Choose a source backend that supports export, or use a "
                "provider-native migration path."
            )
        if not supports_capability(dst, KeyStoreCapability.IMPORT_PRIVATE_KEY):
            raise ValueError(
                f"Destination keystore '{args.dst}' does not support raw key import. "
                "Choose a destination backend that supports import, or create keys "
                "natively on the destination backend."
            )

        ids = [args.key] if args.key else src.list_keys()
        stats = []
        for key_id in ids:
            try:
                raw, meta = src.export_key(key_id)
                if (
                    _raw_private_key_is_unencrypted(raw, meta)
                    and not args.unsafe_allow_unencrypted_private_key
                ):
                    raise ValueError(
                        "Refusing to migrate unencrypted private key without "
                        "--unsafe-allow-unencrypted-private-key."
                    )
                new_id = key_id
                if not args.dry_run:
                    new_id = _keystore_import_key(
                        dst,
                        raw,
                        meta,
                        allow_unencrypted=args.unsafe_allow_unencrypted_private_key,
                    )
                stats.append((key_id, new_id, meta.get("type"), "redacted"))
                print(f"{key_id} -> {new_id}")
            except Exception as exc:  # pragma: no cover - user feedback
                raw_detail = str(exc)
                if raw_detail.startswith("Refusing to migrate unencrypted"):
                    detail = raw_detail
                else:
                    detail = redact_message(raw_detail)
                if detail:
                    print(
                        f"Error migrating {key_id}: "
                        f"{exc.__class__.__name__}: {detail}"
                    )
                else:
                    print(f"Error migrating {key_id}: {exc.__class__.__name__}")
                sys.exit(1)
        if stats:
            header = ("Old ID", "New ID", "Algorithm", "Private Material")
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
    _validate_regular_file(args.pipeline, "pipeline")

    yaml = __import__("yaml")

    from .pipeline import CryptoModule, Pipeline

    class Stub:
        def __init__(self, name: str) -> None:
            self._name = name

        def run(self, data: bytes) -> bytes:  # pragma: no cover - stub
            return data

        def to_proverif(self) -> str:
            return f"(* {self._name} *)"

        def to_tamarin(self) -> str:
            return f"# {self._name}"

    with open(args.pipeline, encoding="utf-8") as f:
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
    _validate_regular_file(args.pipeline, "pipeline")
    if args.output:
        _validate_output_parent(args.output)

    from .codegen import generate

    generate(args.target, args.pipeline, args.output)


def fuzz_cli(argv: list[str] | None = None) -> None:
    """Run Atheris fuzzing harnesses."""

    parser = argparse.ArgumentParser(description=fuzz_cli.__doc__)
    parser.add_argument("--pipeline", help="Pipeline config YAML")
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="Subprocess timeout seconds"
    )
    args = parser.parse_args(argv)

    if args.runs < 1 or args.runs > 1_000_000:
        raise ValueError("--runs must be between 1 and 1000000")
    if args.pipeline:
        _validate_regular_file(args.pipeline, "pipeline")

    script = "fuzz/fuzz_aes.py" if not args.pipeline else "fuzz/fuzz_pipeline.py"
    cmd = [sys.executable, script, f"-runs={args.runs}"]
    if args.pipeline:
        cmd.append(args.pipeline)
    run_command(cmd, timeout_s=args.timeout, operation_name="fuzz_runner")


def main(argv: list[str] | None = None) -> None:
    """Unified command line interface for the cryptography suite."""

    install_signal_handlers()
    configure_structured_logging()
    logger = get_structured_logger("cryptography_suite.cli")
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--experimental",
        action="append",
        choices=["gcm-sst"],
        default=[],
        help="Enable preview features",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "--show-metrics",
        action="store_true",
        help="Print operation metrics after command execution",
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="Output format for command responses",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Deprecated alias for --output-format json",
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
    _add_password_source_args(keygen_parser)

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
    fuzz_parser.add_argument("--timeout", type=float, default=60.0)

    ks_parser = sub.add_parser(
        "keystore", help="Manage keystores", description=keystore_cli.__doc__
    )
    ks_parser.add_argument("action", choices=["list", "test", "import", "migrate"])
    ks_parser.add_argument("--file")
    ks_parser.add_argument("--name")
    _add_password_source_args(ks_parser)
    ks_parser.add_argument(
        "--unsafe-allow-unencrypted-private-key",
        action="store_true",
        help="Allow plaintext private key import/migration for controlled testing only",
    )
    ks_parser.add_argument("--from", dest="src")
    ks_parser.add_argument("--to", dest="dst")
    ks_parser.add_argument("--key", dest="key")
    ks_parser.add_argument("--dry-run", action="store_true")
    ks_parser.add_argument("--apply", action="store_true")

    migrate_parser = sub.add_parser(
        "migrate-keys",
        help="Migrate keys between backends",
        description="Interactive key migration wizard",
    )
    migrate_parser.add_argument(
        "--from", dest="src", required=True, choices=["file", "vault", "hsm"]
    )
    migrate_parser.add_argument(
        "--to", dest="dst", required=True, choices=["file", "vault", "hsm"]
    )
    migrate_parser.add_argument(
        "--batch", action="store_true", help="Run non-interactive batch mode"
    )
    migrate_parser.add_argument(
        "--ignore-errors",
        action="store_true",
        help="Continue migrating after errors in batch mode",
    )
    migrate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log actions without persisting keys",
    )

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
    _add_password_source_args(f_enc)
    f_enc.add_argument(
        "--kdf", choices=["argon2", "scrypt", "pbkdf2"], default=DEFAULT_KDF
    )
    f_dec = file_sub.add_parser("decrypt", help="Decrypt a file")
    f_dec.add_argument("--in", dest="input_file", required=True)
    f_dec.add_argument("--out", dest="output_file", required=True)
    _add_password_source_args(f_dec)
    f_dec.add_argument(
        "--kdf", choices=["argon2", "scrypt", "pbkdf2"], default=DEFAULT_KDF
    )
    f_dec.add_argument("--allow-legacy-format", action="store_true")

    # Backward compatibility aliases
    enc_alias = sub.add_parser(
        "encrypt",
        help=argparse.SUPPRESS,
        description="Alias for 'file encrypt'",
    )
    enc_alias.add_argument("--in", dest="input_file", required=True)
    enc_alias.add_argument("--out", dest="output_file", required=True)
    _add_password_source_args(enc_alias)
    enc_alias.add_argument(
        "--kdf", choices=["argon2", "scrypt", "pbkdf2"], default=DEFAULT_KDF
    )
    dec_alias = sub.add_parser(
        "decrypt",
        help=argparse.SUPPRESS,
        description="Alias for 'file decrypt'",
    )
    dec_alias.add_argument("--in", dest="input_file", required=True)
    dec_alias.add_argument("--out", dest="output_file", required=True)
    _add_password_source_args(dec_alias)
    dec_alias.add_argument(
        "--kdf", choices=["argon2", "scrypt", "pbkdf2"], default=DEFAULT_KDF
    )
    dec_alias.add_argument("--allow-legacy-format", action="store_true")

    args = parser.parse_args(argv)
    if args.json:
        _emit(
            "Warning: --json is deprecated, use --output-format json.",
            {
                "warning": "--json is deprecated, use --output-format json",
                "warning_type": "deprecation",
            },
        )
    _set_output_format("json" if args.json else args.output_format)
    configure_structured_logging(getattr(logging, args.log_level))
    log_event(logger, "cli_invocation", command=args.cmd)

    if "gcm-sst" in args.experimental:
        # Lazy import to avoid importing experimental modules unless requested
        import cryptography_suite.aead as _aead

        _aead.DEFAULT = "GCM-SST"

    if args.cmd == "keygen":
        argv2: list[str] = [args.scheme]
        if args.private:
            argv2.extend(["--private", args.private])
        if args.public:
            argv2.extend(["--public", args.public])
        _append_password_source_args(argv2, args)
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
        if args.file:
            argv2.extend(["--file", args.file])
        if args.name:
            argv2.extend(["--name", args.name])
        if args.password:
            argv2.extend(["--password", args.password])
        if args.password_file:
            argv2.extend(["--password-file", args.password_file])
        if args.password_env:
            argv2.extend(["--password-env", args.password_env])
        if args.password_stdin:
            argv2.append("--password-stdin")
        if getattr(args, "dry_run", False):
            argv2.append("--dry-run")
        if getattr(args, "apply", False):
            argv2.append("--apply")
        if getattr(args, "unsafe_allow_unencrypted_private_key", False):
            argv2.append("--unsafe-allow-unencrypted-private-key")
        keystore_cli(argv2)
    elif args.cmd == "migrate-keys":
        from importlib import util
        from pathlib import Path

        mod_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "cryptography_suite"
            / "cli"
            / "migrate_keys.py"
        )
        spec = util.spec_from_file_location(
            "cryptography_suite.cli.migrate_keys", mod_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("Unable to load migrate_keys module")
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)
        argv2 = ["--from", args.src, "--to", args.dst]
        if getattr(args, "batch", False):
            argv2.append("--batch")
        if getattr(args, "ignore_errors", False):
            argv2.append("--ignore-errors")
        if getattr(args, "dry_run", False):
            argv2.append("--dry-run")
        module.wizard_cli(argv2)
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
            "--kdf",
            args.kdf,
        ]
        if mode == "decrypt" and getattr(args, "allow_legacy_format", False):
            argv2.append("--allow-legacy-format")
        _append_password_source_args(argv2, args)
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
        argv2.extend(["--timeout", str(args.timeout)])
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
    if args.show_metrics:
        print(METRICS.snapshot())
