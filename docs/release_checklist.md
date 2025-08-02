# Release Checklist

- [ ] Run tests and linting.
- [ ] Install pinned build tools: `pip install -r requirements-release.txt`.
- [ ] Build wheel and sdist: `python tools/reproducible_build.py`.
- [ ] Generate SBOM: `python tools/generate_sbom.py`.
- [ ] Generate provenance attestation: `slsa-framework/slsa-github-generator`.
- [ ] Sign artifacts with `cosign sign-blob`.
- [ ] Verify reproducibility using `reprotest`.
- [ ] Lint release artifacts: `python tools/release_lint.py`.
- [ ] Publish to PyPI and create GitHub Release with SBOM, provenance and signatures.
