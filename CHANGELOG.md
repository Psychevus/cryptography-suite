# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deprecated
- `derive_pbkdf2` alias in `symmetric.kdf` (use `kdf_pbkdf2`; will be removed in v4.0.0).
- Legacy helpers `generate_rsa_keypair_and_save` and `generate_ec_keypair_and_save`
  (use `KeyManager` methods; will be removed in v4.0.0).
- Insecure ciphers `salsa20_encrypt`/`salsa20_decrypt` and experimental `ascon.encrypt`/`ascon.decrypt`
  (use `chacha20_encrypt`/`xchacha_encrypt` or authenticated ciphers like `aes_encrypt`).

These functions remain temporarily for backward compatibility but emit
`DeprecationWarning` on use.

## [3.0.0] - 2025-08-30
### Major Changes
- Backend-Agnostic Core (Crypto Abstraction Layer)
- Pipeline DSL for Crypto Workflows
- Misuse-Resistant API (mypy plugin)
- Zeroization & Constant-Time Guarantees
- Formal Verification Export (ProVerif/Tamarin)
- Auto-Stub Generator for App Skeletons
- Rich Logging & Jupyter Widgets for Visualization
- HSM, YubiKey, PKCS#11, Cloud KMS Plugin Architecture
- Fuzzing Harness & Property-Based Testing
- Supply-Chain Attestation, SLSA, and Reproducible Builds

### Breaking Changes
- Old helper modules removed in favor of the Pipeline API.
- Explicit backend selection required.

### Added
- New plugin system for hardware and cloud key managers.
- Stubs generator for application scaffolding.

### Changed
- Documentation reorganized; see [Migration Guide](docs/migration_3.0.md).

### Deprecated
- Direct calls to legacy encrypt/decrypt helpers.

### Removed
- Deprecated functions from the 2.x series.

### Security
- Strengthened zeroization and constant-time operations.

### Fixed
- Miscellaneous bugs resolved during refactor.

[Full changelog](https://github.com/Psychevus/cryptography-suite/releases/tag/v3.0.0).

## [2.0.2] - 2025-07-26
### Fixed
- Verified `signed_prekey` during X3DH session initiation for receiver-side validation.
- Improved one-time prekey usage in DH chain (X3DH).
- Added test cases for signed prekey verification and optional one-time prekey handling.

## [2.0.1] - 2025-07-25
### Fixed
- Auto-padding for base32 secrets in OTP to prevent Incorrect padding error
- Improved handling of lowercase and unpadded OTP secrets
### Added
- Tests for real-world OTP misuse and malformed inputs

## [2.0.0] - 2025-07-24
### Added
- SPAKE2 password-authenticated key exchange implementation.
- Signal Protocol messaging utilities.
- BLAKE3 and SHA3 hashing options.
- Command line interface tools.
- Post-quantum cryptography support via Kyber KEM and Dilithium signatures.
- Hybrid RSA/ECIES + AES-GCM encryption helpers.
- XChaCha20-Poly1305 stream cipher when available.
- Audit logging utilities for tracing cryptographic operations.
- `KeyVault` context manager for secure in-memory key handling.
### Changed
- Major refactor into a modular package structure.
- Argon2id is now the default key derivation function.
### Fixed
- Test suite expanded to 100% coverage.

### Deprecated
- ``derive_pbkdf2`` alias in ``symmetric.kdf``. Use ``kdf_pbkdf2`` instead.
- Legacy ``generate_rsa_keypair_and_save`` helper. Use ``KeyManager.generate_rsa_keypair_and_save``.
- Experimental ciphers ``Salsa20`` and ``Ascon`` are not exported via ``__all__``.

### Migration Guide (1.x -> 2.0.0)
- **Argon2id Default**: Password-based encryption now derives keys with
  Argon2id. Set ``kdf="pbkdf2"`` to retain the previous behavior.
- **Package Layout**: Modules reorganized into subpackages like
  ``cryptography_suite.pqc`` and ``cryptography_suite.protocols``.
- **Breaking Changes**: Some helper functions return ``bytes`` when
  ``raw_output=True`` and new exceptions ``MissingDependencyError`` and
  ``ProtocolError`` are raised in edge cases.

## [1.0.0] - 2024-12-04
### Added
- Comprehensive documentation and usage examples.
- Packaging metadata improvements and CI workflow updates.
- Extensive tests providing full coverage.
### Changed
- Modules refined for better maintainability.
- Security best practices documented.

## [0.1.0] - 2024-11-09
### Added
- Initial release with AES encryption, RSA key management, and SHA-384 hashing.
- PBKDF2 key derivation and secure key storage utilities.
- Basic example usage script and helper utilities.
