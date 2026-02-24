# Release Process

This project uses a SemVer release workflow with reproducible builds.

## Versioning policy

- We follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- Tags must use `vMAJOR.MINOR.PATCH`.
- `CHANGELOG.md` follows Keep a Changelog conventions.

## Automated release pipeline

`Release` workflow (`.github/workflows/release.yml`) is triggered by SemVer tags only.

1. Validate tag format (`vX.Y.Z`).
2. Verify `CHANGELOG.md` has a matching version header.
3. Install pinned dev dependencies from `requirements-dev.txt`.
4. Run quality checks equivalent to CI gates:
   - `ruff format --check` (changed Python files)
   - `black --check` (changed Python files)
   - `ruff check` (changed Python files)
   - `mypy` (changed Python files)
   - `bandit` repository scan
   - `pip-audit -r requirements.txt --strict`
   - `pytest --cov=cryptography_suite --cov-branch --cov-fail-under=95`
5. Install pinned release dependencies from `requirements-release.txt`.
6. Build deterministic wheel/sdist artifacts (`tools/reproducible_build.py`).
7. Generate SBOM (`tools/generate_sbom.py`).
8. Validate artifacts (`tools/release_lint.py`).
9. Publish to PyPI and create a GitHub Release.

## Reproducibility requirements

- CI tooling is pinned in `requirements-dev.txt`.
- Release build tooling is pinned in `requirements-release.txt`.
- Reproducibility is verified in `.github/workflows/reproducibility.yml`.
