"""Generate a table of the public API for documentation.

This script introspects the :mod:`cryptography_suite` package and writes an
RST table listing each exported symbol along with a short docstring summary and
its status (core, experimental, or legacy).
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path


SECTIONS = [
    ("Core", "cryptography_suite"),
    ("Experimental", "cryptography_suite.experimental"),
    ("Legacy", "cryptography_suite.legacy"),
]


def _summary(obj: object) -> str:
    doc = inspect.getdoc(obj) or ""
    return doc.splitlines()[0] if doc else ""


def generate_table() -> str:
    rows = [
        ".. list-table:: Public API Inventory",
        "   :header-rows: 1",
        "",
        "   * - API",
        "     - Summary",
        "     - Status",
    ]

    for status, modname in SECTIONS:
        mod = importlib.import_module(modname)
        for name in getattr(mod, "__all__", []):
            obj = getattr(mod, name, None)
            rows.append(f"   * - ``{name}``")
            rows.append(f"     - {_summary(obj)}")
            rows.append(f"     - {status}")

    return "\n".join(rows) + "\n"


def main() -> None:
    content = "Public API Inventory\n====================\n\n" + generate_table()
    out_path = Path(__file__).resolve().parent.parent / "docs" / "api" / "public_api_table.rst"
    out_path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
