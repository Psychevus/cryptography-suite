"""Key migration utilities.

This module provides an interactive wizard and a non-interactive batch mode
for migrating keys between in-memory backends. All operations keep keys in
memory only and append actions to a tamper-evident ``audit.log`` file.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Dict, Iterable, Optional

import requests

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class PQPublicKey:
    """Minimal representation of a post-quantum public key."""

    def __init__(self, algorithm: str, security_level: int, mode: str = "pq") -> None:
        self.algorithm = algorithm
        self.security_level = security_level
        self.mode = mode

    def public_bytes(self, *_, **__) -> bytes:
        """Return deterministic bytes for fingerprinting."""
        data = f"{self.algorithm}:{self.security_level}:{self.mode}"
        return data.encode()


class PQPrivateKey:
    """Minimal in-memory PQ private key."""

    def __init__(self, algorithm: str, security_level: int, mode: str = "pq") -> None:
        self.algorithm = algorithm
        self.security_level = security_level
        self.mode = mode

    def public_key(self) -> PQPublicKey:
        return PQPublicKey(self.algorithm, self.security_level, self.mode)


@dataclass
class KeyInfo:
    """Representation of a key within a backend."""

    identifier: str
    key_obj: object

    @property
    def key_type(self) -> str:
        if isinstance(self.key_obj, rsa.RSAPrivateKey):
            return "RSA"
        if isinstance(self.key_obj, ec.EllipticCurvePrivateKey):
            return "ECC"
        if isinstance(self.key_obj, ed25519.Ed25519PrivateKey):
            return "Ed25519"
        if isinstance(self.key_obj, PQPrivateKey):
            return self.key_obj.algorithm
        return "Unknown"

    @property
    def security_level(self) -> str:
        if isinstance(self.key_obj, rsa.RSAPrivateKey):
            return str(self.key_obj.key_size)
        if isinstance(self.key_obj, ec.EllipticCurvePrivateKey):
            return self.key_obj.curve.name
        if isinstance(self.key_obj, ed25519.Ed25519PrivateKey):
            return "128"
        if isinstance(self.key_obj, PQPrivateKey):
            return str(self.key_obj.security_level)
        return "unknown"

    @property
    def fingerprint(self) -> str:
        pub = self.key_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(pub).hexdigest()

    @property
    def insecure(self) -> bool:
        return (
            isinstance(self.key_obj, rsa.RSAPrivateKey)
            and self.key_obj.key_size < 2048
        )

    @property
    def pq_mode(self) -> Optional[str]:
        if isinstance(self.key_obj, PQPrivateKey):
            return self.key_obj.mode
        return None


class InMemoryBackend:
    """Simple in-memory backend for demonstration."""

    def __init__(self, name: str, keys: Optional[Dict[str, object]] = None) -> None:
        self.name = name
        self._keys: Dict[str, object] = keys or {}

    @classmethod
    def with_sample_keys(cls, name: str) -> "InMemoryBackend":
        keys: Dict[str, object] = {
            "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ecc": ec.generate_private_key(ec.SECP256R1()),
            "ed": ed25519.Ed25519PrivateKey.generate(),
            "kyber": PQPrivateKey("Kyber", 3, mode="hybrid"),
            "dilithium": PQPrivateKey("Dilithium", 5),
        }
        return cls(name, keys)

    def list_keys(self) -> Iterable[KeyInfo]:
        for ident, key in self._keys.items():
            yield KeyInfo(identifier=ident, key_obj=key)

    def store_key(self, info: KeyInfo) -> None:
        self._keys[info.identifier] = info.key_obj


BACKENDS: Dict[str, InMemoryBackend] = {
    "file": InMemoryBackend.with_sample_keys("file"),
    "vault": InMemoryBackend.with_sample_keys("vault"),
    "hsm": InMemoryBackend.with_sample_keys("hsm"),
}


class AuditLogger:
    """Append-only logger with hash chaining and Ed25519 signatures."""

    def __init__(
        self,
        path: Path,
        *,
        syslog: bool = False,
        webhook: Optional[str] = None,
    ) -> None:
        self.path = path
        self.webhook = webhook
        self._last_hash = self._load_last_hash()
        self._signer = ed25519.Ed25519PrivateKey.generate()
        self.public_key_bytes = self._signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._syslog_logger: Optional[logging.Logger] = None
        if syslog:
            logger = logging.getLogger("migrate_keys.siem")
            handler = SysLogHandler(address=("localhost", 514))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            self._syslog_logger = logger

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf8") as fh:
            for line in fh:
                if line.strip():
                    parts = line.strip().split("|")
                    last = parts[-2] if len(parts) >= 5 else parts[-1]
        return last

    def log(self, action: str, details: str) -> None:
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        entry = f"{ts}|{action}|{details}"
        digest = hashlib.sha256((self._last_hash + entry).encode()).hexdigest()
        signature = self._signer.sign(digest.encode())
        sig_b64 = base64.b64encode(signature).decode()
        with self.path.open("a", encoding="utf8") as fh:
            fh.write(f"{entry}|{digest}|{sig_b64}\n")
        self._last_hash = digest
        if self._syslog_logger:
            try:
                self._syslog_logger.info(f"{entry}|{digest}")
            except Exception:  # pragma: no cover - syslog best effort
                pass
        if self.webhook:
            try:
                requests.post(
                    self.webhook,
                    json={"entry": entry, "digest": digest, "signature": sig_b64},
                    timeout=5,
                )
            except Exception:  # pragma: no cover - network best effort
                pass

    def export_report(self, dest: Path) -> None:
        """Export log entries and a signed digest to ``dest``."""

        entries = []
        if self.path.exists():
            with self.path.open("r", encoding="utf8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    parts = line.strip().split("|")
                    if len(parts) >= 5:
                        ts, action, details, digest, sig = parts
                    else:  # backward compatibility with unsigned logs
                        ts, action, details, digest = parts
                        sig = ""
                    entries.append(
                        {
                            "timestamp": ts,
                            "action": action,
                            "details": details,
                            "digest": digest,
                            "signature": sig,
                        }
                    )
        final_digest = self._last_hash
        report_sig = base64.b64encode(self._signer.sign(final_digest.encode())).decode()
        data = {
            "entries": entries,
            "final_digest": final_digest,
            "public_key": base64.b64encode(self.public_key_bytes).decode(),
            "signature": report_sig,
        }
        dest.write_text(json.dumps(data, indent=2), encoding="utf8")


def migrate_wizard(
    source: InMemoryBackend,
    target: InMemoryBackend,
    logger: AuditLogger,
    dry_run: bool = False,
) -> None:
    """Run interactive migration wizard."""

    console = Console()
    keys = list(source.list_keys())
    if not keys:
        console.print("[yellow]No keys available in source backend[/yellow]")
        return
    migrate_all = False
    for info in keys:
        table = Table(show_header=False)
        table.add_row("Identifier", info.identifier)
        table.add_row("Algorithm", info.key_type)
        table.add_row("Security", info.security_level)
        table.add_row("Fingerprint", info.fingerprint)
        console.print(table)
        if info.insecure:
            console.print("[red]Warning: RSA key <2048 bits[/red]")
        if info.pq_mode in {"hybrid", "legacy"}:
            console.print(
                f"[yellow]Warning: PQ key in {info.pq_mode} mode[/yellow]"
            )
        choice = "y" if migrate_all else Prompt.ask(
            "Migrate this key?", choices=["y", "n", "all", "skip"], default="n"
        )
        if choice in {"y", "all"}:
            action = "dry-run" if dry_run else "migrate"
            if not dry_run:
                target.store_key(info)
            logger.log(
                action,
                f"{info.identifier}:{info.key_type}/{info.security_level}:"
                f"{source.name}->{target.name}",
            )
            verb = "Would migrate" if dry_run else "Migrated"
            console.print(f"[green]{verb} {info.identifier}[/green]")
            if choice == "all":
                migrate_all = True
        elif choice == "skip":
            logger.log("skip-all", f"from {info.identifier}")
            console.print("[yellow]Skipping remaining keys[/yellow]")
            break
        else:
            logger.log(
                "skip",
                f"{info.identifier}:{info.key_type}/{info.security_level}",
            )
            console.print(f"[yellow]Skipped {info.identifier}[/yellow]")


def migrate_batch(
    source: InMemoryBackend,
    target: InMemoryBackend,
    logger: AuditLogger,
    ignore_errors: bool = False,
    dry_run: bool = False,
) -> None:
    """Run non-interactive batch migration."""

    console = Console()
    keys = list(source.list_keys())
    if not keys:
        console.print("[yellow]No keys available in source backend[/yellow]")
        return

    results: list[tuple[str, str]] = []
    for idx, info in enumerate(keys):
        try:
            if dry_run:
                logger.log(
                    "dry-run",
                    f"{info.identifier}:{info.key_type}/{info.security_level}:"
                    f"{source.name}->{target.name}",
                )
                results.append((info.identifier, "skipped"))
                continue
            target.store_key(info)
            logger.log(
                "migrate",
                f"{info.identifier}:{info.key_type}/{info.security_level}:"
                f"{source.name}->{target.name}",
            )
            results.append((info.identifier, "success"))
        except Exception as exc:  # pragma: no cover - defensive
            logger.log("error", f"{info.identifier}:{type(exc).__name__}")
            results.append((info.identifier, "failed"))
            if not ignore_errors:
                for remaining in keys[idx + 1 :]:
                    results.append((remaining.identifier, "skipped"))
                    logger.log(
                        "skip",
                        f"{remaining.identifier}:{remaining.key_type}/"
                        f"{remaining.security_level}",
                    )
                break

    table = Table(title="Migration Summary")
    table.add_column("Key")
    table.add_column("Result")
    icons = {"success": "✅", "skipped": "⚠️", "failed": "❌"}
    for ident, status in results:
        table.add_row(ident, f"{icons[status]} {status}")
    console.print(table)


def wizard_cli(argv: Optional[list[str]] = None) -> None:
    """CLI wrapper for key migration modes."""

    parser = argparse.ArgumentParser(description="Migrate keys between backends")
    parser.add_argument("--from", dest="src", required=True, choices=BACKENDS.keys())
    parser.add_argument("--to", dest="dst", required=True, choices=BACKENDS.keys())
    parser.add_argument(
        "--batch", action="store_true", help="Run non-interactive batch mode"
    )
    parser.add_argument(
        "--ignore-errors",
        action="store_true",
        help="Continue migrating after errors in batch mode",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log actions without persisting keys",
    )
    parser.add_argument(
        "--forensics-report",
        help="Export migration evidence to the specified JSON file",
    )
    parser.add_argument(
        "--syslog", action="store_true", help="Mirror audit log to syslog"
    )
    parser.add_argument(
        "--webhook", help="POST audit entries to a webhook URL"
    )
    args = parser.parse_args(argv)

    source = BACKENDS[args.src]
    target = BACKENDS[args.dst]
    logger = AuditLogger(
        Path("audit.log"), syslog=args.syslog, webhook=args.webhook
    )

    if args.batch:
        migrate_batch(
            source,
            target,
            logger,
            ignore_errors=args.ignore_errors,
            dry_run=args.dry_run,
        )
    else:
        migrate_wizard(source, target, logger, dry_run=args.dry_run)
    if args.forensics_report:
        logger.export_report(Path(args.forensics_report))
