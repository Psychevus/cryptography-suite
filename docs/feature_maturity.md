# Feature Maturity

This project is in pre-v4 hardening. The categories below describe how the
current features should be treated by readers, contributors, and downstream
experimenters. None of these categories is an independent security audit.

## Core Examples / Learning APIs

These APIs are useful for learning, tests, demos, and local experiments. They
wrap common primitives and formats, but callers still need their own threat
model and review before handling real secrets.

| Feature | Examples | Notes |
| --- | --- | --- |
| Symmetric encryption helpers | `cryptography_suite.symmetric`, pipeline AES-GCM modules | Prefer authenticated modes; follow nonce and key-lifecycle guidance. |
| Asymmetric examples | RSA, ECIES/X25519, Ed25519, ECDSA | Backed by upstream libraries where possible; still not independently audited as a suite. |
| Hashing and KDF helpers | SHA-2, SHA-3, BLAKE2b, BLAKE3, PBKDF2, Scrypt, Argon2id, HKDF | Educational wrappers around common algorithms and dependency APIs. |
| CLI examples | file encryption, hashing, OTP, pipeline export | Useful for local workflows; review secret input/output behavior before automation. |
| Pipeline DSL | `cryptography_suite.pipeline` | Good for composing examples and regression tests; exported models are stubs. |

## Hardened But Still Not Audited

These areas have received targeted hardening and regression tests. They remain
unaudited and should not be treated as a blanket approval for production
secrets.

| Area | Current hardening | Remaining caution |
| --- | --- | --- |
| File decryption | Writes plaintext to a temporary file and replaces the destination only after AES-GCM authentication succeeds. | Confirm filesystem, backup, and incident-response behavior in your environment. |
| CLI and verbose output | Redacts secret-bearing fields and avoids printing passwords, derived keys, nonces, private keys, shared secrets, plaintext, or ciphertext internals. | Treat shell history, environment variables, logs, and CI artifacts as separate risk surfaces. |
| Private-key serialization | Normal helper paths prefer encrypted private-key PEMs; plaintext export is explicitly named unsafe. | Use strong passwords or external key management for real deployments. |
| LocalKeyStore | Refuses plaintext private-key writes by default and preserves encrypted PEMs during migration. | Development/testing backend unless wrapped with filesystem, backup, monitoring, and lifecycle controls. |
| FHE context loading | Experimental FHE helpers reject pickle context deserialization. | FHE remains experimental and opt-in. |
| ML-KEM envelope helpers | Current ML-KEM APIs return sealed envelopes and keep KEM shared secrets internal. | PQC support remains experimental and depends on optional third-party libraries. |

## Experimental / Opt-In / Demo-Only

These features are intentionally conservative opt-in demos or research helpers.
They require independent review before high-assurance use.

| Feature | Module or entry point | Status |
| --- | --- | --- |
| PQC and ML-KEM/Kyber compatibility | `cryptography_suite.pqc`, pipeline ML-KEM/Kyber modules | Experimental post-quantum learning demos. |
| Dilithium and SPHINCS+ | `cryptography_suite.pqc` | Experimental optional-dependency demos. |
| Homomorphic encryption | `cryptography_suite.experimental.fhe` | Experimental, requires `CRYPTOSUITE_ALLOW_EXPERIMENTAL=1`. |
| Zero-knowledge helpers | `cryptography_suite.experimental.zk`, `cryptography_suite.zk` | Experimental optional-dependency demos. |
| Signal protocol demo | `cryptography_suite.experimental.signal_demo` | Demonstration only; not a full Signal implementation. |
| BLS helpers | `cryptography_suite.asymmetric.bls` | Demo/legacy helper surface; treat as experimental unless independently reviewed. |
| Visualization widgets | `cryptography_suite.viz` | Developer visualization aids, not security controls. |
| Code generation templates | `cryptography_suite.codegen` | Scaffolding examples that require application review. |
| Fuzzing harnesses | `cryptosuite-fuzz`, `fuzz/` | Testing tools, not proof of security. |
| Formal model export | pipeline `to_proverif`/`to_tamarin`, CLI `export` | Lightweight stubs; no automatic proof claims. |

## Deprecated / Legacy Compatibility

These remain only for compatibility, tests, or migration. New examples should
avoid them.

| Feature | Status | Replacement direction |
| --- | --- | --- |
| `salsa20_encrypt` / `salsa20_decrypt` | Deprecated legacy compatibility | Use authenticated ciphers such as AES-GCM or ChaCha20-Poly1305 helpers. |
| Experimental Ascon helper | Deprecated or experimental depending on entry point | Prefer authenticated primitives backed by maintained dependencies. |
| `derive_pbkdf2` alias | Deprecated | Use `kdf_pbkdf2`. |
| `generate_rsa_keypair_and_save` / `generate_ec_keypair_and_save` standalone helpers | Deprecated | Use `KeyManager` methods and encrypted private-key paths. |
| Ambiguous `from_pem` private-key loading | Deprecated for private-key use | Use `load_public_pem` or `load_encrypted_private_pem`. |
| Kyber-named wrappers | Compatibility wrappers for ML-KEM envelope APIs | Prefer ML-KEM names for new examples. |
