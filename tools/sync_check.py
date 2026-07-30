#!/usr/bin/env python3
"""Synchronisation checker for README vs codebase."""

from __future__ import annotations

from pathlib import Path

import cryptography_suite


def get_exports() -> list[str]:
    return list(getattr(cryptography_suite, "__all__", []))


def get_cli_subcommands() -> list[str]:
    # Phase 3 intentionally publishes no CLI implementation.
    return []


def get_documented_features() -> list[str]:
    lines = Path("README.md").read_text().splitlines()
    features: list[str] = []
    start = None
    for i, line in enumerate(lines):
        if line.lower().startswith("## ") and "key features" in line.lower():
            start = i + 1
            break
    if start is None:
        return features
    for line in lines[start:]:
        if line.startswith("## "):
            break
        if line.strip().startswith("- "):
            features.append(line.strip()[2:])
    return features


def check_mismatches(
    exports: list[str], subcommands: list[str], features: list[str]
) -> list[str]:
    lower_exports = [e.lower() for e in exports]
    lower_cmds = [c.lower() for c in subcommands]
    mismatches: list[str] = []
    for feat in features:
        feat_l = feat.lower()
        if not any(name in feat_l for name in lower_exports + lower_cmds):
            mismatches.append(feat)
    return mismatches


def main() -> None:
    exports = get_exports()
    subcommands = get_cli_subcommands()
    features = get_documented_features()
    mismatches = check_mismatches(exports, subcommands, features)

    print("Exports (__all__):")
    for e in exports:
        print(f" - {e}")
    print("\nCLI subcommands:")
    for c in subcommands:
        print(f" - {c}")
    print("\nDocumented features:")
    for f in features:
        print(f" - {f}")
    if mismatches:
        print("\nFeatures without matching export or subcommand:")
        for m in mismatches:
            print(f" - {m}")
    else:
        print("\nAll documented features map to exports or subcommands.")


if __name__ == "__main__":
    main()
