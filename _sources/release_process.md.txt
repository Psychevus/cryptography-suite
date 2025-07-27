# Release Process

This project aims for fully reproducible builds and signed artifacts. Releases are created via GitHub Actions.

## Steps

1. CI runs `tools/reproducible_build.py` to build the wheel and sdist with `SOURCE_DATE_EPOCH` set.
2. `reproducibility.yml` verifies that two independent builds produce identical hashes.
3. After tests pass, `release.yml` signs the artifacts using GitHub OIDC and `cosign`.
4. A CycloneDX SBOM is generated and attached to the GitHub Release.
5. Release notes are extracted from `CHANGELOG.md` and published to PyPI.

Users can verify a downloaded artifact with:

```bash
python tools/verify_artifact.py dist/cryptography_suite-<version>-py3-none-any.whl <sha256>
```

The expected hashes are published alongside each release.
