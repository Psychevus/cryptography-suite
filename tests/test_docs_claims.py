from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

CLAIM_PATHS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "pyproject.toml",
    REPO_ROOT / "SECURITY.md",
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "RELEASE_NOTES.md",
    REPO_ROOT / "CONTRIBUTING.md",
]
CLAIM_GLOBS = [
    "docs/**/*.md",
    "docs/**/*.rst",
    "examples/**/*.md",
    "examples/**/*.rst",
    "examples/**/*.py",
]

BANNED_PHRASES = [
    "production-ready",
    "production ready",
    "production-grade",
    "production grade",
    "production stable",
    "production-stable",
    "stable production",
    "military-grade",
    "enterprise-grade",
    "slsa-compliant",
    "slsa compliant",
    "99% coverage",
    "100% coverage",
    "full coverage",
    "replace pyca",
    "replacement for cryptography",
    "independently audited",
    "formally verified",
    "constant-time guarantee",
    "guaranteed constant-time",
]

ALLOWED_NEGATED_CLAIMS = {
    "production-ready": ("not production-ready",),
    "production ready": ("not production ready",),
    "independently audited": (
        "not independently audited",
        "not an independent security audit",
        "not an audit",
    ),
    "constant-time guarantee": (
        "no constant-time guarantee",
        "there is no constant-time guarantee",
    ),
}


def _claim_files() -> list[Path]:
    paths = list(CLAIM_PATHS)
    for pattern in CLAIM_GLOBS:
        paths.extend(REPO_ROOT.glob(pattern))
    return sorted({path for path in paths if path.is_file()})


def _is_allowed_negation(phrase: str, line: str) -> bool:
    allowed = ALLOWED_NEGATED_CLAIMS.get(phrase, ())
    return any(exception in line for exception in allowed)


def test_docs_do_not_advertise_unsupported_trust_claims() -> None:
    violations: list[str] = []

    for path in _claim_files():
        relative = path.relative_to(REPO_ROOT)
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            normalized = line.lower()
            for phrase in BANNED_PHRASES:
                if phrase in normalized and not _is_allowed_negation(
                    phrase, normalized
                ):
                    violations.append(f"{relative}:{line_number}: {phrase}")

    assert not violations, "Unsupported trust claims found:\n" + "\n".join(violations)
