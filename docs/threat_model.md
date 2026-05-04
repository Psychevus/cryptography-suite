# Supply Chain Threat Model

This document outlines planned and implemented build/release mitigations. It is
not a supply-chain compliance claim.

## Mitigations

- Deterministic build tooling uses a fixed `SOURCE_DATE_EPOCH` to reduce
  build-time variation across environments.
- GitHub Actions OIDC is used to obtain ephemeral signing credentials.
- Artifacts are signed with `cosign` and include provenance metadata.
- A CycloneDX SBOM lists all dependencies with exact versions.
- Reproducibility tests help detect unexpected build-time variation.

## Attack Vectors

- **Compromised CI runner**: mitigated by minimal permissions and ephemeral credentials.
- **Dependency substitution**: version-pinned requirements and SBOM inspection.
- **Malicious release artifact**: users can verify signatures and hashes before installation.
