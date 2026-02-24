"""Enforce per-module line and branch coverage thresholds."""

from __future__ import annotations

import json
import sys
from pathlib import Path

THRESHOLDS = {
    "cryptography_suite/core/settings.py": {"line": 0.95, "branch": 0.95},
    "cryptography_suite/core/errors.py": {"line": 0.95, "branch": 0.95},
    "cryptography_suite/audit.py": {"line": 0.95, "branch": 0.95},
}


def _rate(summary: dict[str, int], covered_key: str, total_key: str) -> float:
    total = summary.get(total_key, 0)
    if total == 0:
        return 1.0
    return summary.get(covered_key, 0) / total


def main() -> int:
    report_path = Path("coverage.json")
    if not report_path.exists():
        print("coverage.json not found. Run `coverage json` first.")
        return 2

    data = json.loads(report_path.read_text(encoding="utf-8"))
    files = data.get("files", {})

    failures: list[str] = []
    for module, limits in THRESHOLDS.items():
        summary = files.get(module, {}).get("summary")
        if summary is None:
            failures.append(f"Missing module in coverage report: {module}")
            continue

        line_rate = _rate(summary, "covered_lines", "num_statements")
        branch_rate = _rate(summary, "covered_branches", "num_branches")

        if line_rate < limits["line"]:
            failures.append(
                f"{module}: line coverage {line_rate:.3%} < {limits['line']:.0%}"
            )
        if branch_rate < limits["branch"]:
            failures.append(
                f"{module}: branch coverage {branch_rate:.3%} < {limits['branch']:.0%}"
            )

    if failures:
        print("Coverage threshold check failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Coverage thresholds passed for all guarded modules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
