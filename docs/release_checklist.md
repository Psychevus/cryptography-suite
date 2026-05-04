# Release Checklist

## Before tagging

- [ ] Ensure `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section for the release.
- [ ] Confirm version follows SemVer and planned scope (`MAJOR`, `MINOR`, `PATCH`).
- [ ] Run local quality checks:
  - `pre-commit run` (formatting/lint/type/security on changed files)
  - `ruff check <changed-python-files>`
  - `mypy --follow-imports=skip --ignore-missing-imports --disable-error-code=no-any-return --disable-error-code=no-untyped-def --disable-error-code=misc --disable-error-code=type-arg <changed-python-files>`
  - `bandit -q -r cryptography_suite -x tests,docs,examples -s B101,B110,B301,B311,B403,B404,B413,B603,B701`
  - `pip-audit -r requirements.txt --strict`
  - `pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch`

## Tag and release

- [ ] Create a signed SemVer tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`.
- [ ] Push the tag: `git push origin vX.Y.Z`.
- [ ] Confirm GitHub Actions `Release` workflow passed:
  - SemVer tag validation
  - Changelog entry validation
  - Full quality gate rerun
  - Reproducibility check + SBOM generation
  - Signature and provenance metadata generation, when release assets are present
  - Artifact linting + PyPI publish + GitHub Release upload

## Post-release

- [ ] Verify release artifacts exist on GitHub Releases and PyPI.
- [ ] Verify release notes were populated from `CHANGELOG.md`.
- [ ] Announce release and link migration notes when relevant.
