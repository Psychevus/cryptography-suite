# Release Process

This project aims for fully reproducible builds and signed artifacts. Releases are created via GitHub Actions.

## Steps

1. A fresh virtual environment installs pinned build tools via
   `pip install -r requirements-release.txt`.
2. `tools/reproducible_build.py` builds the wheel and sdist with
   `SOURCE_DATE_EPOCH` set to ensure determinism.
3. `tools/generate_sbom.py` creates a CycloneDX SBOM in `dist/sbom.json`.
4. `slsa-framework/slsa-github-generator` produces a
   `provenance.intoto.jsonl` attestation.
5. `cosign sign-blob` signs every artifact (wheel, sdist, SBOM, provenance).
6. `reprotest` verifies the build in varying environments for reproducibility.
7. `tools/release_lint.py` checks that SBOM, provenance and signatures are
   present before publishing.
8. Release notes are extracted from `CHANGELOG.md` and the artifacts,
   signatures and attestations are uploaded to PyPI and GitHub Releases.

Users can verify a downloaded wheel and related artifacts:

1. Verify the wheel's signature:

   ```bash
   cosign verify --certificate-identity "https://github.com/Psychevus/cryptography-suite/.github/workflows/release.yml@refs/tags/v3.0.0" <wheel>.sig <wheel>
   ```

2. Validate the checksums:

   ```bash
   sha256sum -c checksums.txt
   ```

3. Inspect the SLSA provenance:

   ```bash
   jq '.subject | .name' provenance.intoto.jsonl
   ```

The SBOM (`sbom.json`) can be inspected with tools such as
`cyclonedx-bom`:

```bash
cyclonedx-bom --input-file sbom.json --summary
```

Expected SHA256 hashes are published alongside each release for
additional manual verification.
