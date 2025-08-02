#!/usr/bin/env python3
"""Generate support matrix for cryptography-suite features."""
from __future__ import annotations

import importlib
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_cli_text() -> str:
    return Path("cryptography_suite/cli.py").read_text(encoding="utf-8").lower()


def _load_keystore_text() -> str:
    folder = Path("cryptography_suite/keystores")
    parts = [p.read_text(encoding="utf-8").lower() for p in folder.glob("*.py")]
    return "\n".join(parts)


def _get_module(obj: object | None) -> str:
    return getattr(obj, "__module__", "")


def collect_features() -> dict[str, dict[str, str]]:
    features: dict[str, dict[str, str]] = {}

    pipeline = importlib.import_module("cryptography_suite.pipeline")
    for name, cls in pipeline.MODULE_REGISTRY.items():
        features[name] = {
            "module": _get_module(cls),
            "pipeline": "Yes",
            "status": "stable",
        }

    experimental = importlib.import_module("cryptography_suite.experimental")
    for name in getattr(experimental, "__all__", []):
        obj = getattr(experimental, name, None)
        data = features.setdefault(
            name,
            {
                "module": _get_module(obj),
                "pipeline": "Yes" if name in features else "No",
            },
        )
        data["module"] = _get_module(obj)
        data["status"] = "experimental"
        data.setdefault("pipeline", "No")

    legacy = importlib.import_module("cryptography_suite.legacy")
    for name in getattr(legacy, "__all__", []):
        obj = getattr(legacy, name, None)
        data = features.setdefault(
            name,
            {
                "module": _get_module(obj),
                "pipeline": "Yes" if name in features else "No",
            },
        )
        data["module"] = _get_module(obj)
        data["status"] = "deprecated"
        data.setdefault("pipeline", "No")

    return features


def enrich_features(features: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    cli_text = _load_cli_text()
    keystore_text = _load_keystore_text()
    for name, data in features.items():
        lname = name.lower()
        data["cli"] = "Yes" if re.search(rf"\b{re.escape(lname)}\b", cli_text) else "No"
        data["keystore"] = (
            "Yes" if re.search(rf"\b{re.escape(lname)}\b", keystore_text) else "No"
        )
        data.setdefault("extra", "")
    return features


def generate_table(features: dict[str, dict[str, str]]) -> str:
    header = (
        "| Feature | Module | Pipeline? | CLI? | Keystore? | Status | Extra |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
    )
    rows: list[str] = []
    for name in sorted(features):
        data = features[name]
        rows.append(
            f"| {name} | {data.get('module', '')} | {data.get('pipeline', 'No')} | "
            f"{data.get('cli', 'No')} | {data.get('keystore', 'No')} | {data.get('status', '')} | "
            f"{data.get('extra', '')} |"
        )
    return header + "\n".join(rows) + "\n"


def update_readme(table: str) -> None:
    readme = Path(__file__).resolve().parent.parent / "README.md"
    text = readme.read_text(encoding="utf-8")
    start = "<!-- SUPPORT-MATRIX-START -->"
    end = "<!-- SUPPORT-MATRIX-END -->"
    pattern = re.compile(start + r".*?" + end, re.DOTALL)
    new_text = pattern.sub(f"{start}\n{table}{end}", text)
    readme.write_text(new_text, encoding="utf-8")


def main() -> None:
    features = collect_features()
    features = enrich_features(features)
    table = generate_table(features)
    update_readme(table)
    print(table)


if __name__ == "__main__":
    main()
