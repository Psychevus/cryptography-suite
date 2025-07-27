# Release Notes - Cryptography Suite 3.0.0

Cryptography Suite 3.0.0 introduces a backend-agnostic core and a new pipeline
framework.

## Highlights

- Backend-agnostic Crypto Abstraction Layer
- Pipeline DSL for building workflows
- Misuse-resistant API with a mypy plugin
- Zeroization and constant-time safety guarantees
- Formal verification export tools
- Automatic stub generator for new applications
- Rich logging and interactive widgets
- Plugin architecture for HSM and cloud KMS
- Integrated fuzzing harness
- Supply-chain attestation and reproducible builds

---

# Release Notes - Cryptography Suite 2.0.2

Cryptography Suite 2.0.2 introduces improvements to the X3DH key agreement.

## Highlights

- **Signed Prekey Verification** ensures that session setup fails when the
  signature on the sender's prekey is invalid.
- **Optional One-Time Prekeys** are now mixed into the shared secret when
  provided, with each DH step logged when ``VERBOSE_MODE`` is enabled.

---

# Release Notes - Cryptography Suite 2.0.1

Cryptography Suite 2.0.1 is a maintenance release focused on reliability improvements and documentation updates.

## Highlights

- **OTP Auto-Padding Fix**: Base32 secrets for TOTP/HOTP are now auto-padded internally to prevent decoding errors.
- **Expanded Test Coverage** for OTP edge cases.
- **Internal cleanup and doc updates.**

Enjoy the improvements and minor fixes introduced in version 2.0.1.

---

# Release Notes - Cryptography Suite 2.0.0

Cryptography Suite 2.0.0 delivers a major update with post-quantum readiness and enhanced tooling.

## Highlights

- **Post-Quantum Cryptography**: Kyber key encapsulation and Dilithium signatures provide quantum-safe building blocks.
- **Hybrid Encryption**: Convenient helpers combine asymmetric keys with AES-GCM for secure and efficient messaging.
- **XChaCha20-Poly1305**: Optional modern stream cipher support when available from the ``cryptography`` library.
- **KeyVault**: Context manager for safely handling secrets in memory.
- **Audit Logging**: Decorators and helpers to trace operations, with optional encrypted logs.
- **Argon2id by Default**: Password-based encryption now derives keys using Argon2id for stronger security.
- **Modular Package**: Reorganized modules into clear subpackages for PQC, protocols, and utilities.

Enjoy the new features and improved security in version 2.0.0.
