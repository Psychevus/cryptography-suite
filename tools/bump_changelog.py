#!/usr/bin/env python3
"""Bump CHANGELOG from Unreleased to current version."""

import datetime
import re
import subprocess
from pathlib import Path

VERSION = "2.0.1"
CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def main():
    lines = CHANGELOG.read_text().splitlines()
    unreleased_idx = next(i for i, line in enumerate(lines) if line.startswith("## [Unreleased]"))
    # find next header after Unreleased
    next_idx = next(
        (i for i, line in enumerate(lines[unreleased_idx + 1 :], start=unreleased_idx + 1) if line.startswith("## [")),
        len(lines),
    )
    entries = [line for line in lines[unreleased_idx + 1 : next_idx] if line.strip()]
    entries = [line for line in entries if line.strip() != "- Nothing yet."]
    del lines[unreleased_idx + 1 : next_idx]

    today = datetime.date.today().strftime("%Y-%m-%d")
    header_pattern = re.compile(rf"## \[{re.escape(VERSION)}\]")
    for i, line in enumerate(lines):
        if header_pattern.match(line):
            lines[i] = f"## [{VERSION}] - {today}"
            insert_idx = i
            break
    else:
        insert_idx = unreleased_idx + 1
        lines.insert(insert_idx, "")
        lines.insert(insert_idx + 1, f"## [{VERSION}] - {today}")
        lines.insert(insert_idx + 2, "")
        insert_idx = insert_idx + 1

    if entries:
        lines[insert_idx + 1 : insert_idx + 1] = entries + [""]

    CHANGELOG.write_text("\n".join(lines) + "\n")

    subprocess.run(["git", "add", str(CHANGELOG)], check=True)
    subprocess.run(["git", "commit", "-m", f"Update changelog for {VERSION}"], check=True)


if __name__ == "__main__":
    main()
