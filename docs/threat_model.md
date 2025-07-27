# Supply Chain Threat Model

This document outlines security measures for the build and release process.

## Mitigations

- Deterministic builds using a fixed `SOURCE_DATE_EPOCH` ensure identical artifacts across environments.
- GitHub Actions OIDC is used to obtain ephemeral signing credentials.
- Artifacts are signed with `cosign` and include provenance metadata.
- A CycloneDX SBOM lists all dependencies with exact versions.
- Reproducibility tests detect any build-time tampering.

## Attack Vectors

- **Compromised CI runner**: mitigated by minimal permissions and ephemeral credentials.
- **Dependency substitution**: pinned hashes in requirements and SBOM verification.
- **Malicious release artifact**: users can verify signatures and hashes before installation.
