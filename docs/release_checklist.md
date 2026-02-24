# Release Checklist

## Before tagging

- [ ] Ensure `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section for the release.
- [ ] Confirm version follows SemVer and planned scope (`MAJOR`, `MINOR`, `PATCH`).
- [ ] Run local quality checks:
  - `pre-commit run` (formatting/lint/type/security on changed files)
  - `ruff check <changed-python-files>`
  - `mypy cryptography_suite tools`
  - `bandit -q -r cryptography_suite -x tests,docs,examples`
  - `pip-audit -r requirements.txt --strict`
  - `pytest --cov=cryptography_suite --cov-branch --cov-fail-under=95`

## Tag and release

- [ ] Create a signed SemVer tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`.
- [ ] Push the tag: `git push origin vX.Y.Z`.
- [ ] Confirm GitHub Actions `Release` workflow passed:
  - SemVer tag validation
  - Changelog entry validation
  - Full quality gate rerun
  - Reproducible build + SBOM generation
  - Artifact linting + PyPI publish + GitHub Release upload

## Post-release

- [ ] Verify release artifacts exist on GitHub Releases and PyPI.
- [ ] Verify release notes were populated from `CHANGELOG.md`.
- [ ] Announce release and link migration notes when relevant.
