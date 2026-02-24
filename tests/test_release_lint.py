from __future__ import annotations

from pathlib import Path

import pytest

from tools import release_lint


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")


def test_collect_expected_includes_build_outputs_and_signatures(tmp_path: Path) -> None:
    _touch(tmp_path / "cryptography_suite-1.2.3-py3-none-any.whl")
    _touch(tmp_path / "cryptography_suite-1.2.3.tar.gz")

    expected = release_lint._collect_expected(tmp_path)

    assert "sbom.json" in expected
    assert "provenance.intoto.jsonl" in expected
    assert "cryptography_suite-1.2.3-py3-none-any.whl.sig" in expected
    assert "cryptography_suite-1.2.3-py3-none-any.whl.cert" in expected
    assert "sbom.json.sig" in expected
    assert "provenance.intoto.jsonl.cert" in expected


def test_main_passes_when_expected_artifacts_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = "cryptography_suite-1.2.3-py3-none-any.whl"
    sdist = "cryptography_suite-1.2.3.tar.gz"
    for name in [wheel, sdist, "sbom.json", "provenance.intoto.jsonl"]:
        _touch(tmp_path / name)
        _touch(tmp_path / f"{name}.sig")
        _touch(tmp_path / f"{name}.cert")

    monkeypatch.setattr(release_lint, "DIST", tmp_path)

    release_lint.main()


def test_main_fails_when_signature_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = "cryptography_suite-1.2.3-py3-none-any.whl"
    _touch(tmp_path / wheel)
    _touch(tmp_path / f"{wheel}.cert")
    _touch(tmp_path / "sbom.json")
    _touch(tmp_path / "provenance.intoto.jsonl")
    for name in ["sbom.json", "provenance.intoto.jsonl"]:
        _touch(tmp_path / f"{name}.sig")
        _touch(tmp_path / f"{name}.cert")

    monkeypatch.setattr(release_lint, "DIST", tmp_path)

    with pytest.raises(SystemExit):
        release_lint.main()
