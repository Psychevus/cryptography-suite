"""Key migration utilities.

This module provides an interactive wizard and a non-interactive batch mode
for migrating keys between in-memory backends. All operations keep keys in
memory only and append actions to a tamper-evident ``audit.log`` file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


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
        return "Unknown"

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
    """Append-only tamper-evident logger."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf8") as fh:
            for line in fh:
                if line.strip():
                    last = line.rsplit("|", 1)[-1].strip()
        return last

    def log(self, action: str, details: str) -> None:
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        entry = f"{ts}|{action}|{details}"
        digest = hashlib.sha256((self._last_hash + entry).encode()).hexdigest()
        with self.path.open("a", encoding="utf8") as fh:
            fh.write(f"{entry}|{digest}\n")
        self._last_hash = digest


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
        table.add_row("Type", info.key_type)
        table.add_row("Fingerprint", info.fingerprint)
        console.print(table)
        if info.insecure:
            console.print("[red]Warning: RSA key <2048 bits[/red]")
        choice = "y" if migrate_all else Prompt.ask(
            "Migrate this key?", choices=["y", "n", "all", "skip"], default="n"
        )
        if choice in {"y", "all"}:
            action = "dry-run" if dry_run else "migrate"
            if not dry_run:
                target.store_key(info)
            logger.log(action, f"{info.identifier}:{source.name}->{target.name}")
            verb = "Would migrate" if dry_run else "Migrated"
            console.print(f"[green]{verb} {info.identifier}[/green]")
            if choice == "all":
                migrate_all = True
        elif choice == "skip":
            logger.log("skip-all", f"from {info.identifier}")
            console.print("[yellow]Skipping remaining keys[/yellow]")
            break
        else:
            logger.log("skip", info.identifier)
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
                    "dry-run", f"{info.identifier}:{source.name}->{target.name}"
                )
                results.append((info.identifier, "skipped"))
                continue
            target.store_key(info)
            logger.log("migrate", f"{info.identifier}:{source.name}->{target.name}")
            results.append((info.identifier, "success"))
        except Exception as exc:  # pragma: no cover - defensive
            logger.log("error", f"{info.identifier}:{exc}")
            results.append((info.identifier, "failed"))
            if not ignore_errors:
                for remaining in keys[idx + 1 :]:
                    results.append((remaining.identifier, "skipped"))
                    logger.log("skip", remaining.identifier)
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
    args = parser.parse_args(argv)

    source = BACKENDS[args.src]
    target = BACKENDS[args.dst]
    logger = AuditLogger(Path("audit.log"))

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
