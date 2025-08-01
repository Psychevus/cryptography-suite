# Backend Consistency

Cryptography Suite standardizes on well audited backends for each primitive to
avoid accidental mixing of incompatible libraries.

## Philosophy

- **pyca/cryptography** is the authoritative backend for all symmetric and
  asymmetric primitives such as AES, ChaCha20-Poly1305, RSA, ECDSA, and EdDSA.
- Third-party libraries are only used when a primitive is unavailable in
  `cryptography`. Such usage is isolated in optional modules and marked as
  deprecated.
- Contributions should not introduce new dependencies for primitives already
  supported by `cryptography`.

## Backend Matrix

| Primitive | Backend | Notes |
| --- | --- | --- |
| AES-GCM | pyca/cryptography | Authoritative |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | pyca/cryptography | Authoritative |
| Salsa20 | PyCryptodome (optional) | Deprecated; reference only |
| Ascon-128a | Pure Python | Experimental |
| RSA, ECDSA, Ed25519, Ed448 | pyca/cryptography | Authoritative |
| BLS12-381 | py_ecc | Optional |
| SHA-2, SHA-3, BLAKE2b | pyca/cryptography | Authoritative |
| BLAKE3 | blake3 | Authoritative |
| Argon2id, Scrypt, PBKDF2, HKDF | pyca/cryptography | Authoritative |
| Kyber, Dilithium (PQC) | pqcrypto (optional) | Optional |

### Future Migration

When `pyca/cryptography` adds support for primitives currently provided by
optional modules (e.g. Salsa20), those modules and their dependencies will be
removed.

### Consistency Check

A lightweight test ensures that PyCryptodome is only imported from the optional
Salsa20 module. Running `pytest` will fail if any other package imports
`Crypto.*`.
