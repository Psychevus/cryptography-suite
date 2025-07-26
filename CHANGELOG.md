# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
