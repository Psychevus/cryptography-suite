#!/usr/bin/env python3
"""Bump CHANGELOG from Unreleased to current version."""
import datetime
import subprocess
import re
from pathlib import Path

VERSION = "2.0.0"
CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"

def main():
    lines = CHANGELOG.read_text().splitlines()
    unreleased_idx = next(i for i,l in enumerate(lines) if l.startswith("## [Unreleased]"))
    # find next header after Unreleased
    next_idx = next((i for i,l in enumerate(lines[unreleased_idx+1:], start=unreleased_idx+1) if l.startswith("## [")), len(lines))
    entries = [l for l in lines[unreleased_idx+1:next_idx] if l.strip()]
    entries = [l for l in entries if l.strip() != "- Nothing yet."]
    del lines[unreleased_idx+1:next_idx]

    today = datetime.date.today().strftime("%Y-%m-%d")
    header_pattern = re.compile(rf"## \[{re.escape(VERSION)}\]")
    for i,l in enumerate(lines):
        if header_pattern.match(l):
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
        lines[insert_idx+1:insert_idx+1] = entries + [""]

    CHANGELOG.write_text("\n".join(lines) + "\n")

    subprocess.run(["git", "add", str(CHANGELOG)], check=True)
    subprocess.run(["git", "commit", "-m", f"Update changelog for {VERSION}"], check=True)

if __name__ == "__main__":
    main()
