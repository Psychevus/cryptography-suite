from __future__ import annotations

from pathlib import Path

from conftest import REPO_ROOT

BANNED_PHRASES = {
    "enterprise-grade",
    "formally verified",
    "full coverage",
    "guaranteed constant-time",
    "independently audited",
    "military-grade",
    "production grade",
    "production ready",
    "production stable",
    "production-grade",
    "production-ready",
    "production-stable",
    "slsa compliant",
    "slsa-compliant",
}

ALLOWED_NEGATIONS = {
    "independently audited": {
        "not independently audited",
        "not an independent security audit",
    },
    "production ready": {"not production ready"},
    "production-ready": {"not production-ready"},
}


def _claim_files() -> list[Path]:
    roots = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "SECURITY.md",
        REPO_ROOT / "CONTRIBUTING.md",
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "RELEASE_NOTES.md",
    ]
    roots.extend(REPO_ROOT.glob("docs/**/*.md"))
    roots.extend(REPO_ROOT.glob("docs/**/*.rst"))
    return sorted({path for path in roots if path.is_file()})


def test_documents_do_not_make_unsupported_trust_claims() -> None:
    violations: list[str] = []
    for path in _claim_files():
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            normalized = line.lower()
            for phrase in BANNED_PHRASES:
                if phrase not in normalized:
                    continue
                if any(
                    allowed in normalized
                    for allowed in ALLOWED_NEGATIONS.get(phrase, set())
                ):
                    continue
                violations.append(f"{path.relative_to(REPO_ROOT)}:{number}: {phrase}")
    assert violations == []
