# Release Process

This project enforces a SemVer-based release workflow with reproducible builds.

## Versioning policy

- We follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- Tags **must** use the form `vMAJOR.MINOR.PATCH`.
- `CHANGELOG.md` is maintained using Keep a Changelog format.

## Automated release pipeline

`Release` workflow (`.github/workflows/release.yml`) is triggered only by SemVer tags.

1. Validate tag format (`vX.Y.Z`).
2. Verify `CHANGELOG.md` includes a matching version header.
3. Re-run quality gate checks: formatter and lint checks on Python files changed since the previous tag, plus repository-wide typing, security, dependency audit, and tests with branch coverage.
4. Install pinned release dependencies from `requirements-release.txt`.
5. Build reproducible wheel/sdist artifacts.
6. Generate SBOM.
7. Validate release artifacts (`tools/release_lint.py`).
8. Publish to PyPI.
9. Create GitHub Release and attach artifacts.

Release notes are generated directly from the matching changelog section.

## Reproducibility requirements

- CI tooling for checks is pinned in `requirements-dev.txt`.
- Release build tooling is pinned in `requirements-release.txt`.
- Build job runs from a clean environment and generates deterministic artifacts.
