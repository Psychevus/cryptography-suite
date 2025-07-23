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
