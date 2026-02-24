# Contributing

Thanks for helping improve `cryptography-suite`.

## Branching and pull requests

- Branch from `main` and keep each PR focused.
- Open PRs against `main`.
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip==24.2
pip install -r requirements-dev.txt
pip install -e .
pre-commit install
```

## Quality gate (must match CI)

CI enforces formatting, lint, and type checks on changed Python files and enforces security/tests gates repository-wide.

Run all checks locally before pushing:

```bash
pre-commit run
ruff check <changed-python-files>
mypy --follow-imports=skip --ignore-missing-imports --disable-error-code=no-any-return --disable-error-code=no-untyped-def --disable-error-code=misc --disable-error-code=type-arg <changed-python-files>
bandit -q -r cryptography_suite -x tests,docs,examples -s B101,B110,B301,B311,B403,B404,B413,B603,B701
pip-audit -r requirements.txt --strict
pytest --cov=cryptography_suite --cov-branch --cov-report=term-missing --cov-fail-under=95
```

If you need to format your branch before commit:

```bash
pre-commit run --all-files
```

CI runs on every push and pull request. Any failure blocks merges.

## Release policy and process

- Versioning follows **Semantic Versioning (SemVer)**.
- Release tags must match `vMAJOR.MINOR.PATCH` (example: `v3.1.0`).
- Update `CHANGELOG.md` under the matching version header before tagging.
- Release workflow validates the tag format, verifies changelog entry, reruns quality checks, then builds and publishes artifacts.
- Build tooling is pinned in `requirements-release.txt` for reproducible release builds.

See:

- `docs/release_checklist.md`
- `docs/release_process.md`

## Security-sensitive changes

PRs that touch cryptographic logic or key handling must include a **Threat Considerations** section describing misuse risks and mitigations.
