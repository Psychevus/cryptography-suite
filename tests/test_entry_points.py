"""Entry point loading tests for packaging metadata."""

from __future__ import annotations

from importlib import metadata


def test_entry_points_load() -> None:
    dist = metadata.distribution("cryptography-suite")
    entry_points = dist.entry_points

    targets = []
    for ep in entry_points:
        if ep.group == "cryptosuite.aead":
            targets.append(ep)
            continue
        if ep.group == "console_scripts" and ep.name in {
            "cryptography-suite",
            "cryptosuite-fuzz",
        }:
            targets.append(ep)

    assert targets, "Expected cryptosuite.aead and console script entry points"

    for entry_point in targets:
        loaded = entry_point.load()
        assert loaded is not None
