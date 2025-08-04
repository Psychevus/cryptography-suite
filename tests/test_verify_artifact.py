"""Tests for the tools.verify_artifact module."""

from pathlib import Path

from tools.verify_artifact import sha256, verify


def test_verify_artifact_returns_bool(tmp_path: Path) -> None:
    """verify should return bool and preserve behaviour."""

    artifact = tmp_path / "data.txt"
    artifact.write_text("hello world")

    good_hash = sha256(artifact)

    assert verify(artifact, good_hash) is True

    bad_result = verify(artifact, "deadbeef")

    assert bad_result is False
    assert isinstance(bad_result, bool)

