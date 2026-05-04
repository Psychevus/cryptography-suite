# Release Process

This project uses a SemVer release workflow with reproducibility checks and
artifact verification aids. These release artifacts are useful for inspection;
they are not an audit or compliance certification.

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
   - `pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch`
5. Install pinned release dependencies from `requirements-release.txt`.
6. Build deterministic wheel/sdist artifacts (`tools/reproducible_build.py`).
7. Generate SBOM (`tools/generate_sbom.py`).
8. Install `cosign` and sign all distributable artifacts with keyless Sigstore.
9. Generate in-toto provenance metadata (`dist/provenance.intoto.jsonl`) and sign it.
10. Validate artifacts (`tools/release_lint.py`).
11. Publish to PyPI and create a GitHub Release.

Release artifacts include:

- `dist/*.whl`
- `dist/*.tar.gz`
- `dist/sbom.json` (CycloneDX)
- `dist/provenance.intoto.jsonl` (in-toto provenance metadata)
- `*.sig` and `*.cert` for each artifact above.

## Local verification with cosign

Use the certificate identity for the exact release tag you downloaded.

```bash
export CERT_IDENTITY="https://github.com/Psychevus/cryptography-suite/.github/workflows/release.yml@refs/tags/vX.Y.Z"
export CERT_ISSUER="https://token.actions.githubusercontent.com"

cosign verify-blob --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" --signature dist/<artifact>.sig --certificate dist/<artifact>.cert dist/<artifact>
```

To inspect provenance subjects:

```bash
jq -r '.payload' dist/provenance.intoto.jsonl | base64 -d | jq '.statement.subject'
```

## Reproducibility requirements

- CI tooling is pinned in `requirements-dev.txt`.
- Release build tooling is pinned in `requirements-release.txt`.
- Reproducibility is verified in `.github/workflows/reproducibility.yml`.
